#include "SshLfsAuthenticator.h"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPointer>
#include <QStandardPaths>
#include <QTimer>

#include "GitUtilities.h"
#include "Ssh2Client.h"
#include "Ssh2Process.h"
#include "asyncfuture.h"

#include <array>

namespace {

struct ParsedSshRemote
{
    QString host;
    int port = 22;
    QString user = QStringLiteral("git");
    QString repositoryPath;
};

QString trimJsonPayload(const QString& text)
{
    const int firstBrace = text.indexOf('{');
    const int lastBrace = text.lastIndexOf('}');
    if (firstBrace < 0 || lastBrace < firstBrace) {
        return text;
    }
    return text.mid(firstBrace, lastBrace - firstBrace + 1);
}

QString operationToString(QQuickGit::SshLfsAuthenticator::Operation operation)
{
    return operation == QQuickGit::SshLfsAuthenticator::Operation::Upload
        ? QStringLiteral("upload")
        : QStringLiteral("download");
}

Monad::Result<ParsedSshRemote> parseSshRemote(const QString& remoteUrl)
{
    const QUrl url = QQuickGit::GitUtilities::fixGitUrl(remoteUrl);
    if (!url.isValid() || url.scheme().toLower() != QStringLiteral("ssh")) {
        return Monad::Result<ParsedSshRemote>(QStringLiteral("Remote is not an SSH URL"));
    }

    ParsedSshRemote remote;
    remote.host = url.host().trimmed();
    remote.port = url.port(22);
    if (!url.userName().trimmed().isEmpty()) {
        remote.user = url.userName().trimmed();
    }

    QString repositoryPath = url.path();
    while (repositoryPath.startsWith('/')) {
        repositoryPath.remove(0, 1);
    }
    remote.repositoryPath = repositoryPath.trimmed();

    if (remote.host.isEmpty() || remote.repositoryPath.isEmpty()) {
        return Monad::Result<ParsedSshRemote>(QStringLiteral("SSH remote is missing host or repository path"));
    }

    return Monad::Result<ParsedSshRemote>(remote);
}

std::array<QString, 5> privateKeyCandidates()
{
    const QString homeDir = QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
    const QString appConfigDir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    return {
        homeDir + QStringLiteral("/.ssh/id_ed25519"),
        homeDir + QStringLiteral("/.ssh/id_rsa"),
        homeDir + QStringLiteral("/.ssh/id_ecdsa"),
        appConfigDir + QStringLiteral("/.ssh/id_ed25519"),
        appConfigDir + QStringLiteral("/.ssh/id_rsa")
    };
}

Monad::Result<QQuickGit::SshLfsAuthenticator::AuthResult> parseAuthReply(const QString& output)
{
    const QString payload = trimJsonPayload(output);
    QJsonParseError parseError{};
    const QJsonDocument document = QJsonDocument::fromJson(payload.toUtf8(), &parseError);
    if (document.isNull() || !document.isObject()) {
        return Monad::Result<QQuickGit::SshLfsAuthenticator::AuthResult>(
            QStringLiteral("Invalid git-lfs-authenticate response JSON"));
    }

    const QJsonObject root = document.object();
    const QUrl href(root.value(QStringLiteral("href")).toString());
    if (!href.isValid() || href.scheme().isEmpty()) {
        return Monad::Result<QQuickGit::SshLfsAuthenticator::AuthResult>(
            QStringLiteral("git-lfs-authenticate response missing href"));
    }

    QQuickGit::SshLfsAuthenticator::AuthResult result;
    result.href = href;

    const QJsonObject headerObject = root.value(QStringLiteral("header")).toObject();
    for (auto it = headerObject.begin(); it != headerObject.end(); ++it) {
        result.headers.insert(it.key().toUtf8(), it.value().toString().toUtf8());
    }

    return Monad::Result<QQuickGit::SshLfsAuthenticator::AuthResult>(result);
}

class SshLfsAuthJob : public QObject
{
    Q_OBJECT
public:
    SshLfsAuthJob(ParsedSshRemote remote,
                  QQuickGit::SshLfsAuthenticator::Operation operation,
                  AsyncFuture::Deferred<Monad::Result<QQuickGit::SshLfsAuthenticator::AuthResult>> deferred,
                  QObject* parent = nullptr) :
        QObject(parent),
        m_remote(std::move(remote)),
        m_operation(operation),
        m_deferred(std::move(deferred))
    {
        m_timeoutTimer.setSingleShot(true);
        connect(&m_timeoutTimer, &QTimer::timeout, this, [this]() {
            failAttempt(QStringLiteral("SSH command timeout"));
        });
    }

    void start()
    {
        startNextAttempt();
    }

private:
    void startNextAttempt()
    {
        cleanupAttemptObjects();

        while (m_keyIndex < m_keyCandidates.size() && m_keyCandidates[m_keyIndex].isEmpty()) {
            ++m_keyIndex;
        }

        if (m_keyIndex >= m_keyCandidates.size()) {
            m_completed = true;
            m_deferred.complete(Monad::Result<QQuickGit::SshLfsAuthenticator::AuthResult>(
                m_lastError.isEmpty() ? QStringLiteral("SSH authentication failed") : m_lastError));
            deleteLater();
            return;
        }

        qlibssh2::Ssh2Settings settings;
        settings.user = m_remote.user;
        settings.port = static_cast<quint16>(m_remote.port);
        settings.key = m_keyCandidates[m_keyIndex];
        settings.passphrase = QString();
        settings.keyphrase = QString();
        settings.timeout = 10000;

        m_stdoutText.clear();
        m_stderrText.clear();
        m_started = false;
        m_attemptFinished = false;

        m_client = new qlibssh2::Ssh2Client(settings, this);

        connect(m_client,
                &qlibssh2::Ssh2Client::ssh2Error,
                this,
                [this](std::error_code error) {
                    if (m_attemptFinished || m_completed) {
                        return;
                    }
                    if (error == qlibssh2::Ssh2Error::HostKeyUnknownError) {
                        m_lastError = QStringLiteral("SSH host key for %1 is not trusted. "
                                                     "Add it to known_hosts (for example: ssh-keyscan %1 >> ~/.ssh/known_hosts).")
                                          .arg(m_remote.host);
                    } else {
                        m_lastError = QString::fromLocal8Bit(error.message().c_str());
                    }
                });

        connect(m_client,
                &qlibssh2::Ssh2Client::sessionStateChanged,
                this,
                &SshLfsAuthJob::onSessionStateChanged);

        m_timeoutTimer.start(30000);
        m_client->connectToHost(m_remote.host, static_cast<qint16>(m_remote.port));
    }

    void onSessionStateChanged(qlibssh2::Ssh2Client::SessionStates state)
    {
        if (sender() != m_client || m_attemptFinished || m_completed) {
            return;
        }
        if (state == qlibssh2::Ssh2Client::Established) {
            if (!m_process) {
                const QString command = QStringLiteral("git-lfs-authenticate %1 %2")
                                            .arg(m_remote.repositoryPath, operationToString(m_operation));
                m_process = m_client->createProcess(command);
                if (!m_process) {
                    failAttempt(QStringLiteral("Failed to create SSH process"));
                    return;
                }

                connect(m_process,
                        &qlibssh2::Ssh2Channel::newChannelData,
                        this,
                        [this](const QByteArray& data, qlibssh2::Ssh2Channel::ChannelStream stream) {
                    const QString text = QString::fromUtf8(data);
                    if (stream == qlibssh2::Ssh2Channel::Err) {
                        m_stderrText += text;
                    } else {
                        m_stdoutText += text;
                    }
                });

                connect(m_process,
                        &qlibssh2::Ssh2Process::processStateChanged,
                        this,
                        &SshLfsAuthJob::onProcessStateChanged);

                m_process->open(QIODevice::ReadWrite);
            }
            return;
        }

        if (state == qlibssh2::Ssh2Client::FailedToEstablish
            || state == qlibssh2::Ssh2Client::Aborted) {
            failAttempt(QStringLiteral("SSH session failed"));
        }
    }

    void onProcessStateChanged(qlibssh2::Ssh2Process::ProcessStates processState)
    {
        if (sender() != m_process || m_attemptFinished || m_completed) {
            return;
        }
        if (processState == qlibssh2::Ssh2Process::Started) {
            m_started = true;
            return;
        }

        if (processState == qlibssh2::Ssh2Process::FailedToStart) {
            failAttempt(QStringLiteral("Failed to start git-lfs-authenticate"));
            return;
        }

        if (processState != qlibssh2::Ssh2Process::Finished) {
            return;
        }

        const int exitStatus = m_process ? m_process->exitStatus() : -1;
        if (!m_started) {
            failAttempt(QStringLiteral("git-lfs-authenticate was not started over SSH"));
            return;
        }

        if (exitStatus != 0) {
            failAttempt(QStringLiteral("git-lfs-authenticate failed (exit=%1): %2")
                            .arg(exitStatus)
                            .arg(m_stderrText.simplified()));
            return;
        }

        const auto parseResult = parseAuthReply(m_stdoutText);
        if (parseResult.hasError()) {
            failAttempt(parseResult.errorMessage());
            return;
        }

        m_timeoutTimer.stop();
        m_attemptFinished = true;
        m_completed = true;
        m_deferred.complete(parseResult);
        deleteLater();
    }

    void failAttempt(const QString& message)
    {
        if (m_attemptFinished || m_completed) {
            return;
        }
        m_attemptFinished = true;
        m_timeoutTimer.stop();
        if (!message.trimmed().isEmpty()) {
            m_lastError = message.trimmed();
        }
        if (m_process) {
            disconnect(m_process, nullptr, this, nullptr);
        }
        if (m_client) {
            disconnect(m_client, nullptr, this, nullptr);
        }
        ++m_keyIndex;
        QTimer::singleShot(0, this, &SshLfsAuthJob::startNextAttempt);
    }

    void cleanupAttemptObjects()
    {
        if (m_process) {
            m_process->deleteLater();
            m_process = nullptr;
        }
        if (m_client) {
            m_client->deleteLater();
            m_client = nullptr;
        }
    }

    ParsedSshRemote m_remote;
    QQuickGit::SshLfsAuthenticator::Operation m_operation;
    AsyncFuture::Deferred<Monad::Result<QQuickGit::SshLfsAuthenticator::AuthResult>> m_deferred;
    std::array<QString, 5> m_keyCandidates = privateKeyCandidates();
    int m_keyIndex = 0;
    QString m_lastError;
    QString m_stdoutText;
    QString m_stderrText;
    bool m_started = false;
    bool m_attemptFinished = false;
    bool m_completed = false;
    QPointer<qlibssh2::Ssh2Client> m_client;
    QPointer<qlibssh2::Ssh2Process> m_process;
    QTimer m_timeoutTimer;
};

}

namespace QQuickGit {

QFuture<Monad::Result<SshLfsAuthenticator::AuthResult>> SshLfsAuthenticator::authenticate(const QString& remoteUrl,
                                                                                           Operation operation)
{
    if (!QCoreApplication::instance()) {
        return AsyncFuture::completed(Monad::Result<AuthResult>(
            QStringLiteral("QCoreApplication instance is required for SSH authentication")));
    }

    const auto remoteResult = parseSshRemote(remoteUrl);
    if (remoteResult.hasError()) {
        return AsyncFuture::completed(Monad::Result<AuthResult>(remoteResult.errorMessage()));
    }

    auto deferred = AsyncFuture::deferred<Monad::Result<AuthResult>>();
    deferred.reportStarted();

    auto* job = new SshLfsAuthJob(remoteResult.value(), operation, deferred, QCoreApplication::instance());
    job->start();

    return deferred.future();
}

} // namespace QQuickGit

#include "SshLfsAuthenticator.moc"
