// Catch includes
#include <catch2/catch_test_macros.hpp>

// libgit2
#include "git2.h"
#include "git2/filter.h"

// Our includes
#include "GitRepository.h"
#include "Account.h"
#include "LfsAuthProvider.h"
#include "LfsBatchClient.h"
#include "LfsStore.h"
#include "asyncfuture.h"

// Qt includes
#include <QDir>
#include <QDirIterator>
#include <QDateTime>
#include <QCryptographicHash>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QImage>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <memory>
#include <csignal>
#if defined(Q_OS_UNIX)
#include <sys/resource.h>
#endif

using namespace QQuickGit;

namespace {

bool writeTextFile(const QString& path, const QByteArray& contents)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return false;
    }
    return file.write(contents) == contents.size();
}

QByteArray readFileBytes(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return QByteArray();
    }
    return file.readAll();
}

int countFilesRecursively(const QString& rootPath)
{
    int count = 0;
    QDirIterator it(rootPath, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        count++;
    }
    return count;
}

LfsPolicy makeCustomPolicy(const QString& tag)
{
    LfsPolicy policy;
    policy.setAttributesSectionTag(tag);
    policy.setRule(QStringLiteral("png"), [](const QString&, const QByteArray*) { return true; });
    policy.setRule(QStringLiteral("jpg"), [](const QString&, const QByteArray*) { return true; });
    policy.setRule(QStringLiteral("jpeg"), [](const QString&, const QByteArray*) { return true; });
    policy.setRule(QStringLiteral("pdf"), [](const QString&, const QByteArray*) { return true; });
    policy.setRule(QStringLiteral("svg"), [](const QString& path, const QByteArray* data) {
        if (data) {
            if (data->size() > 250 * 1024) {
                return true;
            }
            return data->toLower().contains(QByteArray("data:image/"));
        }
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            return false;
        }
        if (QFileInfo(path).size() > 250 * 1024) {
            return true;
        }
        return file.readAll().toLower().contains(QByteArray("data:image/"));
    });
    policy.setDefaultRule([](const QString&, const QByteArray*) { return false; });
    return policy;
}

QByteArray readBlobFromHead(git_repository* repo, const char* path)
{
    git_reference* head = nullptr;
    if (git_repository_head(&head, repo) != GIT_OK) {
        return QByteArray();
    }

    const git_oid* headId = git_reference_target(head);
    if (!headId) {
        git_reference_free(head);
        return QByteArray();
    }

    git_commit* commit = nullptr;
    if (git_commit_lookup(&commit, repo, headId) != GIT_OK) {
        git_reference_free(head);
        return QByteArray();
    }

    git_tree* tree = nullptr;
    if (git_commit_tree(&tree, commit) != GIT_OK) {
        git_commit_free(commit);
        git_reference_free(head);
        return QByteArray();
    }

    git_tree_entry* entry = nullptr;
    if (git_tree_entry_bypath(&entry, tree, path) != GIT_OK) {
        git_tree_free(tree);
        git_commit_free(commit);
        git_reference_free(head);
        return QByteArray();
    }

    git_blob* blob = nullptr;
    if (git_blob_lookup(&blob, repo, git_tree_entry_id(entry)) != GIT_OK) {
        git_tree_entry_free(entry);
        git_tree_free(tree);
        git_commit_free(commit);
        git_reference_free(head);
        return QByteArray();
    }

    const auto* content = static_cast<const char*>(git_blob_rawcontent(blob));
    const size_t size = git_blob_rawsize(blob);
    QByteArray result(content, static_cast<int>(size));

    git_blob_free(blob);
    git_tree_entry_free(entry);
    git_tree_free(tree);
    git_commit_free(commit);
    git_reference_free(head);

    return result;
}

QString headOidString(git_repository* repo)
{
    git_reference* head = nullptr;
    if (git_repository_head(&head, repo) != GIT_OK) {
        return QString();
    }

    const git_oid* headId = git_reference_target(head);
    if (!headId) {
        git_reference_free(head);
        return QString();
    }

    const char* oidStr = git_oid_tostr_s(headId);
    const QString result = oidStr ? QString::fromLatin1(oidStr) : QString();
    git_reference_free(head);
    return result;
}

QByteArray createPngFile(const QString& path, const QColor& color)
{
    QImage image(10, 10, QImage::Format_ARGB32);
    image.fill(color);
    if (!image.save(path, "PNG")) {
        return QByteArray();
    }
    return readFileBytes(path);
}

bool hasOwnerExecutePermission(const QString& path)
{
    return QFileInfo(path).permissions().testFlag(QFileDevice::ExeOwner);
}

QString permissionDebug(QFile::Permissions perms)
{
    return QStringLiteral("qtPerms=0x%1 ownerExec=%2")
        .arg(QString::number(static_cast<uint>(perms), 16))
        .arg(perms.testFlag(QFileDevice::ExeOwner));
}

QString permissionDebugString(const QString& path)
{
    QFileInfo info(path);
    const QFile::Permissions perms = info.permissions();

    return permissionDebug(perms);
}

bool configureRemoteUrl(const QString& workTreePath,
                        const QString& remoteName,
                        const QString& remoteUrl)
{
    git_repository* repo = nullptr;
    if (git_repository_open(&repo, workTreePath.toLocal8Bit().constData()) != GIT_OK || !repo) {
        return false;
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    const QByteArray remoteNameUtf8 = remoteName.toUtf8();
    const QByteArray remoteUrlUtf8 = remoteUrl.toUtf8();

    git_remote* existingRemote = nullptr;
    if (git_remote_lookup(&existingRemote, repo, remoteNameUtf8.constData()) == GIT_OK && existingRemote) {
        git_remote_free(existingRemote);
        return git_remote_set_url(repo, remoteNameUtf8.constData(), remoteUrlUtf8.constData()) == GIT_OK;
    }

    git_remote* createdRemote = nullptr;
    const int createResult = git_remote_create(&createdRemote,
                                               repo,
                                               remoteNameUtf8.constData(),
                                               remoteUrlUtf8.constData());
    if (createdRemote) {
        git_remote_free(createdRemote);
    }
    return createResult == GIT_OK;
}

class LocalLfsBatchServer
{
public:
    bool start()
    {
        QObject::connect(&mServer, &QTcpServer::newConnection, &mServer, [this]() { handleNewConnections(); });
        return mServer.listen(QHostAddress::LocalHost, 0);
    }

    quint16 port() const
    {
        return mServer.serverPort();
    }

    void setBatchResponse(const QByteArray& body)
    {
        mBatchResponse = body;
    }

    int batchRequestCount() const
    {
        return mBatchRequestCount;
    }

private:
    void handleNewConnections()
    {
        while (mServer.hasPendingConnections()) {
            QTcpSocket* socket = mServer.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
                const QByteArray request = socket->readAll();
                if (request.isEmpty()) {
                    return;
                }
                const QByteArray firstLine = request.split('\n').value(0).trimmed();
                if (firstLine.contains("/objects/batch")) {
                    mBatchRequestCount++;
                }

                const QByteArray body = firstLine.contains("/objects/batch")
                    ? mBatchResponse
                    : QByteArray("{\"message\":\"not found\"}");
                const QByteArray response =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/vnd.git-lfs+json\r\n"
                    "Connection: close\r\n"
                    "Content-Length: " + QByteArray::number(body.size()) + "\r\n"
                    "\r\n" + body;
                socket->write(response);
                socket->flush();
                socket->disconnectFromHost();
            });
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
        }
    }

    QTcpServer mServer;
    QByteArray mBatchResponse = QByteArray(
        "{\"transfer\":\"basic\",\"objects\":[{\"oid\":\"\",\"size\":0,"
        "\"error\":{\"code\":404,\"message\":\"missing\"}}]}");
    int mBatchRequestCount = 0;
};

class LocalLfsDownloadServer
{
public:
    bool start()
    {
        QObject::connect(&mServer, &QTcpServer::newConnection, &mServer, [this]() { handleNewConnections(); });
        return mServer.listen(QHostAddress::LocalHost, 0);
    }

    QString endpoint() const
    {
        return QStringLiteral("http://127.0.0.1:%1/info/lfs").arg(mServer.serverPort());
    }

    void setObject(const QString& oid, const QByteArray& bytes)
    {
        mOid = oid;
        mObjectBytes = bytes;
    }

    int batchRequestCount() const
    {
        return mBatchRequestCount;
    }

    int objectRequestCount() const
    {
        return mObjectRequestCount;
    }

private:
    void respond(QTcpSocket* socket, int status, const QByteArray& contentType, const QByteArray& body)
    {
        const QByteArray statusText = status == 200 ? QByteArray("OK") : QByteArray("Not Found");
        const QByteArray response =
            "HTTP/1.1 " + QByteArray::number(status) + " " + statusText + "\r\n"
            "Content-Type: " + contentType + "\r\n"
            "Connection: close\r\n"
            "Content-Length: " + QByteArray::number(body.size()) + "\r\n"
            "\r\n" + body;
        socket->write(response);
        socket->flush();
        socket->disconnectFromHost();
    }

    void handleNewConnections()
    {
        while (mServer.hasPendingConnections()) {
            QTcpSocket* socket = mServer.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
                const QByteArray request = socket->readAll();
                if (request.isEmpty()) {
                    return;
                }

                const QByteArray firstLine = request.split('\n').value(0).trimmed();
                const QByteArray path = firstLine.split(' ').value(1).trimmed();

                if (path.contains("/objects/batch")) {
                    mBatchRequestCount++;
                    if (mOid.isEmpty() || mObjectBytes.isEmpty()) {
                        respond(socket,
                                200,
                                QByteArray("application/vnd.git-lfs+json"),
                                QByteArray("{\"transfer\":\"basic\",\"objects\":[]}"));
                        return;
                    }

                    const QString href = QStringLiteral("http://127.0.0.1:%1/objects/%2")
                        .arg(mServer.serverPort())
                        .arg(mOid);
                    const QByteArray body = QStringLiteral(
                        "{\"transfer\":\"basic\",\"objects\":[{\"oid\":\"%1\",\"size\":%2,"
                        "\"actions\":{\"download\":{\"href\":\"%3\"}}}]}")
                        .arg(mOid)
                        .arg(mObjectBytes.size())
                        .arg(href)
                        .toUtf8();
                    respond(socket, 200, QByteArray("application/vnd.git-lfs+json"), body);
                    return;
                }

                const QByteArray objectPathPrefix("/objects/");
                const int objectPrefixIndex = path.indexOf(objectPathPrefix);
                if (objectPrefixIndex >= 0) {
                    mObjectRequestCount++;
                    const QByteArray oidBytes = path.mid(objectPrefixIndex + objectPathPrefix.size());
                    const QString requestedOid = QString::fromUtf8(oidBytes);
                    if (!requestedOid.isEmpty() && requestedOid == mOid) {
                        respond(socket, 200, QByteArray("application/octet-stream"), mObjectBytes);
                    } else {
                        respond(socket, 404, QByteArray("application/octet-stream"), QByteArray("missing"));
                    }
                    return;
                }

                respond(socket, 404, QByteArray("application/json"), QByteArray("{\"message\":\"not found\"}"));
            });
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
        }
    }

    QTcpServer mServer;
    QString mOid;
    QByteArray mObjectBytes;
    int mBatchRequestCount = 0;
    int mObjectRequestCount = 0;
};

class LocalLfsUploadServer
{
public:
    bool start()
    {
        QObject::connect(&mServer, &QTcpServer::newConnection, &mServer, [this]() { handleNewConnections(); });
        return mServer.listen(QHostAddress::LocalHost, 0);
    }

    QString endpoint() const
    {
        return QStringLiteral("http://127.0.0.1:%1/info/lfs").arg(mServer.serverPort());
    }

    void setExpectedObject(const QString& oid, qint64 size)
    {
        mOid = oid;
        mSize = size;
    }

    int uploadBatchRequestCount() const
    {
        return mUploadBatchRequestCount;
    }

    int uploadRequestCount() const
    {
        return mUploadRequestCount;
    }

private:
    void respond(QTcpSocket* socket, int status, const QByteArray& contentType, const QByteArray& body)
    {
        const QByteArray statusText = status == 200 ? QByteArray("OK") : QByteArray("Not Found");
        const QByteArray response =
            "HTTP/1.1 " + QByteArray::number(status) + " " + statusText + "\r\n"
            "Content-Type: " + contentType + "\r\n"
            "Connection: close\r\n"
            "Content-Length: " + QByteArray::number(body.size()) + "\r\n"
            "\r\n" + body;
        socket->write(response);
        socket->flush();
        socket->disconnectFromHost();
    }

    void handleNewConnections()
    {
        while (mServer.hasPendingConnections()) {
            QTcpSocket* socket = mServer.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
                const QByteArray request = socket->readAll();
                if (request.isEmpty()) {
                    return;
                }

                const QByteArray firstLine = request.split('\n').value(0).trimmed();
                const QByteArray method = firstLine.split(' ').value(0).trimmed();
                const QByteArray path = firstLine.split(' ').value(1).trimmed();
                const QByteArray body = request.mid(request.indexOf("\r\n\r\n") + 4);

                if (path.contains("/objects/batch")) {
                    if (body.contains("\"operation\":\"upload\"")) {
                        mUploadBatchRequestCount++;
                    }

                    if (mOid.isEmpty() || mSize <= 0) {
                        respond(socket,
                                200,
                                QByteArray("application/vnd.git-lfs+json"),
                                QByteArray("{\"transfer\":\"basic\",\"objects\":[]}"));
                        return;
                    }

                    const QString baseUrl = QStringLiteral("http://127.0.0.1:%1").arg(mServer.serverPort());
                    const QByteArray responseBody = QStringLiteral(
                        "{\"transfer\":\"basic\",\"objects\":[{\"oid\":\"%1\",\"size\":%2,"
                        "\"actions\":{\"upload\":{\"href\":\"%3/upload/%1\"}}}]}")
                        .arg(mOid)
                        .arg(mSize)
                        .arg(baseUrl)
                        .toUtf8();
                    respond(socket, 200, QByteArray("application/vnd.git-lfs+json"), responseBody);
                    return;
                }

                if (method == "PUT" && path.contains("/upload/")) {
                    mUploadRequestCount++;
                    respond(socket, 200, QByteArray("application/json"), QByteArray("{}"));
                    return;
                }

                respond(socket, 404, QByteArray("application/json"), QByteArray("{\"message\":\"not found\"}"));
            });
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
        }
    }

    QTcpServer mServer;
    QString mOid;
    qint64 mSize = 0;
    int mUploadBatchRequestCount = 0;
    int mUploadRequestCount = 0;
};

class LocalLfsAuthHeaderServer
{
public:
    bool start()
    {
        QObject::connect(&mServer, &QTcpServer::newConnection, &mServer, [this]() { handleNewConnections(); });
        return mServer.listen(QHostAddress::LocalHost, 0);
    }

    QString remoteUrl() const
    {
        return QStringLiteral("http://127.0.0.1:%1/test.git").arg(mServer.serverPort());
    }

    void requireHeader(const QByteArray& name, const QByteArray& value)
    {
        mRequiredName = name;
        mRequiredValue = value;
    }

    int batchRequestCount() const
    {
        return mBatchRequestCount;
    }

    int authorizedRequestCount() const
    {
        return mAuthorizedRequestCount;
    }

private:
    static void respond(QTcpSocket* socket, int status, const QByteArray& contentType, const QByteArray& body)
    {
        const QByteArray statusText = status == 200 ? QByteArray("OK") : QByteArray("Unauthorized");
        const QByteArray response =
            "HTTP/1.1 " + QByteArray::number(status) + " " + statusText + "\r\n"
            "Content-Type: " + contentType + "\r\n"
            "Connection: close\r\n"
            "Content-Length: " + QByteArray::number(body.size()) + "\r\n"
            "\r\n" + body;
        socket->write(response);
        socket->flush();
        socket->disconnectFromHost();
    }

    void handleNewConnections()
    {
        while (mServer.hasPendingConnections()) {
            QTcpSocket* socket = mServer.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
                const QByteArray request = socket->readAll();
                if (request.isEmpty()) {
                    return;
                }

                const QByteArray firstLine = request.split('\n').value(0).trimmed();
                if (!firstLine.contains("/objects/batch")) {
                    respond(socket, 404, QByteArray("application/json"), QByteArray("{\"message\":\"not found\"}"));
                    return;
                }

                mBatchRequestCount++;
                bool hasRequiredHeader = false;
                const QByteArray requiredNameLower = mRequiredName.toLower();
                const QList<QByteArray> lines = request.split('\n');
                for (const QByteArray& rawLine : lines) {
                    const QByteArray line = rawLine.trimmed();
                    if (line.isEmpty()) {
                        break;
                    }
                    const int colonIndex = line.indexOf(':');
                    if (colonIndex <= 0) {
                        continue;
                    }
                    const QByteArray headerName = line.left(colonIndex).trimmed().toLower();
                    const QByteArray headerValue = line.mid(colonIndex + 1).trimmed();
                    if (headerName == requiredNameLower && headerValue == mRequiredValue) {
                        hasRequiredHeader = true;
                        break;
                    }
                }
                if (hasRequiredHeader) {
                    mAuthorizedRequestCount++;
                    const QByteArray body =
                        "{\"transfer\":\"basic\",\"objects\":[{\"oid\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size\":1,\"actions\":{}}]}";
                    respond(socket, 200, QByteArray("application/vnd.git-lfs+json"), body);
                } else {
                    const QByteArray body = QByteArray("{\"message\":\"missing auth header\"}");
                    respond(socket, 401, QByteArray("application/json"), body);
                }
            });
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
        }
    }

    QTcpServer mServer;
    QByteArray mRequiredName = QByteArray("X-QQuickGit-Auth");
    QByteArray mRequiredValue = QByteArray("scoped-token");
    int mBatchRequestCount = 0;
    int mAuthorizedRequestCount = 0;
};

bool findFirstLfsPointerInRepo(const QString& repoPath, LfsPointer* pointerOut, QString* relativePathOut)
{
    if (!pointerOut) {
        return false;
    }

    QDirIterator it(repoPath, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString filePath = it.next();
        if (filePath.contains(QStringLiteral("/.git/"))) {
            continue;
        }

        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            continue;
        }

        const QByteArray data = file.read(1024);
        if (data.isEmpty()) {
            continue;
        }

        LfsPointer pointer;
        if (LfsPointer::parse(data, &pointer)) {
            *pointerOut = pointer;
            if (relativePathOut) {
                *relativePathOut = QDir(repoPath).relativeFilePath(filePath);
            }
            return true;
        }
    }

    return false;
}

bool findLfsPointerByOidInRepo(const QString& repoPath,
                               const QString& oid,
                               LfsPointer* pointerOut,
                               QString* relativePathOut)
{
    if (!pointerOut || oid.isEmpty()) {
        return false;
    }

    QDirIterator it(repoPath, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString filePath = it.next();
        if (filePath.contains(QStringLiteral("/.git/"))) {
            continue;
        }

        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            continue;
        }

        const QByteArray data = file.read(1024);
        if (data.isEmpty()) {
            continue;
        }

        LfsPointer pointer;
        if (!LfsPointer::parse(data, &pointer)) {
            continue;
        }

        if (pointer.oid == oid) {
            *pointerOut = pointer;
            if (relativePathOut) {
                *relativePathOut = QDir(repoPath).relativeFilePath(filePath);
            }
            return true;
        }
    }

    return false;
}

QString gitDirPathFromWorkTree(const QString& workTreePath)
{
    git_repository* repo = nullptr;
    if (git_repository_open(&repo, workTreePath.toLocal8Bit().constData()) != GIT_OK || !repo) {
        return QString();
    }

    const char* gitPath = git_repository_path(repo);
    const QString result = gitPath ? QDir(QString::fromUtf8(gitPath)).absolutePath() : QString();
    git_repository_free(repo);
    return result;
}

void requireGitFutureSuccess(QFuture<Monad::ResultBase> future, int timeoutMs = 60 * 1000)
{
    REQUIRE(AsyncFuture::waitForFinished(future, timeoutMs));
    INFO("Git future error:" << future.result().errorMessage().toStdString()
         << "code:" << future.result().errorCode());
    REQUIRE(!future.result().hasError());
}

QString envOrDefault(const char* key, const QString& fallback)
{
    const QByteArray value = qgetenv(key);
    if (value.isEmpty()) {
        return fallback;
    }
    return QString::fromUtf8(value);
}

QString lfsTestRepoUrl()
{
    return envOrDefault("QQGIT_LFS_TEST_REPO_URL",
                        QStringLiteral("https://github.com/vpicaver/lfs-test.git"));
}

QString lfsAuthEndpoint()
{
    return envOrDefault("QQGIT_LFS_TEST_AUTH_LFS_URL", QString());
}

QString lfsAuthUsername()
{
    return envOrDefault("QQGIT_LFS_TEST_AUTH_USERNAME", QString());
}

QString lfsAuthToken()
{
    return envOrDefault("QQGIT_LFS_TEST_AUTH_TOKEN", QString());
}

QStringList missingUploadAuthEnvVars()
{
    QStringList missing;
    if (lfsAuthEndpoint().isEmpty()) {
        missing << QStringLiteral("QQGIT_LFS_TEST_AUTH_LFS_URL (e.g. https://github.com/vpicaver/lfs-test.git/info/lfs)");
    }
    if (lfsAuthUsername().isEmpty()) {
        missing << QStringLiteral("QQGIT_LFS_TEST_AUTH_USERNAME (e.g. vpicaver)");
    }
    if (lfsAuthToken().isEmpty()) {
        missing << QStringLiteral("QQGIT_LFS_TEST_AUTH_TOKEN (e.g. github_pat_xxx)");
    }
    return missing;
}

QByteArray basicAuthHeader(const QString& username, const QString& token)
{
    if (username.isEmpty() || token.isEmpty()) {
        return QByteArray();
    }
    const QByteArray credentials = (username + ":" + token).toUtf8().toBase64();
    return QByteArray("Basic ") + credentials;
}

class StaticLfsAuthProvider : public LfsAuthProvider
{
public:
    explicit StaticLfsAuthProvider(QByteArray header)
        : mHeader(std::move(header))
    {
    }

    QByteArray authorizationHeader(const QUrl&) const override
    {
        return mHeader;
    }

private:
    QByteArray mHeader;
};

class EnvLfsAuthProvider : public LfsAuthProvider
{
public:
    EnvLfsAuthProvider(QString username, QString token)
        : mHeader(basicAuthHeader(username, token))
    {
    }

    QByteArray authorizationHeader(const QUrl&) const override
    {
        return mHeader;
    }

private:
    QByteArray mHeader;
};

class ScopedLfsAuthProvider
{
public:
    explicit ScopedLfsAuthProvider(std::shared_ptr<LfsAuthProvider> provider)
        : mPrevious(LfsBatchClient::lfsAuthProvider())
    {
        LfsBatchClient::setLfsAuthProvider(std::move(provider));
    }

    ~ScopedLfsAuthProvider()
    {
        LfsBatchClient::setLfsAuthProvider(mPrevious);
    }

private:
    std::shared_ptr<LfsAuthProvider> mPrevious;
};

#if defined(Q_OS_UNIX)
class ScopedFileSizeLimit
{
public:
    bool apply(rlim_t softLimitBytes)
    {
        if (getrlimit(RLIMIT_FSIZE, &mPrevious) != 0) {
            return false;
        }

        rlimit updated = mPrevious;
        updated.rlim_cur = softLimitBytes;
        if (setrlimit(RLIMIT_FSIZE, &updated) != 0) {
            return false;
        }
        mActive = true;
        return true;
    }

    ~ScopedFileSizeLimit()
    {
        if (mActive) {
            setrlimit(RLIMIT_FSIZE, &mPrevious);
        }
    }

private:
    rlimit mPrevious{};
    bool mActive = false;
};

class ScopedSignalHandler
{
public:
    ScopedSignalHandler(int signalNumber, void (*handler)(int))
        : mSignal(signalNumber)
    {
        mPrevious = std::signal(signalNumber, handler);
    }

    ~ScopedSignalHandler()
    {
        std::signal(mSignal, mPrevious);
    }

private:
    int mSignal;
    void (*mPrevious)(int) = SIG_DFL;
};
#endif

bool setGitConfigString(const QString& workTreePath, const char* key, const QString& value)
{
    git_repository* repo = nullptr;
    if (git_repository_open(&repo, workTreePath.toLocal8Bit().constData()) != GIT_OK || !repo) {
        return false;
    }

    git_config* repoConfig = nullptr;
    int configResult = git_repository_config(&repoConfig, repo);
    if (configResult != GIT_OK || !repoConfig) {
        git_repository_free(repo);
        return false;
    }

    git_config* localConfig = nullptr;
    int localResult = git_config_open_level(&localConfig, repoConfig, GIT_CONFIG_LEVEL_LOCAL);
    if (localResult != GIT_OK || !localConfig) {
        localConfig = repoConfig;
    }

    const int setResult = git_config_set_string(localConfig, key, value.toUtf8().constData());

    git_buf verifyValue = GIT_BUF_INIT;
    const int verifyResult = git_config_get_string_buf(&verifyValue, localConfig, key);
    git_buf_dispose(&verifyValue);

    if (localConfig != repoConfig) {
        git_config_free(localConfig);
    }
    git_config_free(repoConfig);
    git_repository_free(repo);
    return setResult == GIT_OK && verifyResult == GIT_OK;
}

struct CountingWriteStream {
    git_writestream parent;
    size_t totalBytes = 0;
    size_t maxWrite = 0;
    size_t writeCalls = 0;
    bool closed = false;
};

int countingStreamWrite(git_writestream* stream, const char* buffer, size_t len)
{
    (void)buffer;
    auto* state = reinterpret_cast<CountingWriteStream*>(stream);
    state->totalBytes += len;
    state->writeCalls += 1;
    if (len > state->maxWrite) {
        state->maxWrite = len;
    }
    return GIT_OK;
}

int countingStreamClose(git_writestream* stream)
{
    auto* state = reinterpret_cast<CountingWriteStream*>(stream);
    state->closed = true;
    return GIT_OK;
}

void countingStreamFree(git_writestream* stream)
{
    delete reinterpret_cast<CountingWriteStream*>(stream);
}

}

TEST_CASE("LfsPointer round trip", "[LFS]") {
    LfsPointer pointer;
    pointer.oid = QStringLiteral("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    pointer.size = 1234;

    const QByteArray pointerText = pointer.toPointerText();
    REQUIRE(!pointerText.isEmpty());

    LfsPointer parsed;
    REQUIRE(LfsPointer::parse(pointerText, &parsed));
    CHECK(parsed.oid == pointer.oid);
    CHECK(parsed.size == pointer.size);
}

TEST_CASE("LfsPointer parse rejects traversal-style oid", "[LFS]") {
    const QByteArray pointerText =
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:../../../../tmp/evil\n"
        "size 12\n";

    LfsPointer parsed;
    CHECK_FALSE(LfsPointer::parse(pointerText, &parsed));
}

TEST_CASE("LfsStore store/read bytes", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), 0) == GIT_OK);
    REQUIRE(repo != nullptr);

    QByteArray payload;
    payload.append("binary", 6);
    payload.append('\0');
    payload.append("data", 4);
    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();

    LfsStore store(gitDirPath);
    auto storeResult = store.storeBytes(payload);
    REQUIRE(!storeResult.hasError());
    const LfsPointer pointer = storeResult.value();
    CHECK(pointer.size == payload.size());
    CHECK(!pointer.oid.isEmpty());

    auto readResult = store.readObject(pointer.oid);
    REQUIRE(!readResult.hasError());
    CHECK(readResult.value() == payload);

    git_repository_free(repo);
}

TEST_CASE("Lfs filter clean/smudge round trip", "[LFS]") {
    QTemporaryDir tempDir;

    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), 0) == GIT_OK);
    REQUIRE(repo != nullptr);
    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    auto store = std::make_shared<LfsStore>(gitDirPath, makeCustomPolicy(QStringLiteral("qquickgit-test")));
    LfsStoreRegistry::registerStore(store);

    const QString repoPath = tempDir.path();
    const QString attributesPath = QDir(repoPath).filePath(QStringLiteral(".gitattributes"));
    REQUIRE(writeTextFile(attributesPath, QByteArray("*.png filter=lfs diff=lfs merge=lfs -text\n")));

    const QByteArray payload("lfs-binary-\x01\x02\x03", 14);

    git_filter_list* cleanFilters = nullptr;
    REQUIRE(git_filter_list_load(&cleanFilters, repo, nullptr, "test.png", GIT_FILTER_TO_ODB, GIT_FILTER_DEFAULT) == GIT_OK);
    REQUIRE(cleanFilters != nullptr);
    CHECK(git_filter_list_contains(cleanFilters, "lfs") == 1);

    git_buf cleanOut = GIT_BUF_INIT;
    REQUIRE(git_filter_list_apply_to_buffer(&cleanOut, cleanFilters, payload.constData(), static_cast<size_t>(payload.size())) == GIT_OK);
    REQUIRE(cleanOut.size > 0);

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(QByteArray(cleanOut.ptr, static_cast<int>(cleanOut.size)), &pointer));
    CHECK(pointer.size == payload.size());
    CHECK(!pointer.oid.isEmpty());

    const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
    CHECK(QFile::exists(objectPath));

    git_filter_list* smudgeFilters = nullptr;
    REQUIRE(git_filter_list_load(&smudgeFilters, repo, nullptr, "test.png", GIT_FILTER_TO_WORKTREE, GIT_FILTER_DEFAULT) == GIT_OK);
    REQUIRE(smudgeFilters != nullptr);
    CHECK(git_filter_list_contains(smudgeFilters, "lfs") == 1);

    git_buf smudgeOut = GIT_BUF_INIT;
    REQUIRE(git_filter_list_apply_to_buffer(&smudgeOut,
                                            smudgeFilters,
                                            cleanOut.ptr,
                                            static_cast<size_t>(cleanOut.size)) == GIT_OK);
    REQUIRE(smudgeOut.size == static_cast<size_t>(payload.size()));
    CHECK(QByteArray(smudgeOut.ptr, static_cast<int>(smudgeOut.size)) == payload);

    git_buf_dispose(&cleanOut);
    git_buf_dispose(&smudgeOut);
    git_filter_list_free(cleanFilters);
    git_filter_list_free(smudgeFilters);
    LfsStoreRegistry::unregisterStore(gitDirPath, store);
    git_repository_free(repo);
}

TEST_CASE("Lfs filter keeps working tree PNG and stores pointer in ODB", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), 0) == GIT_OK);
    REQUIRE(repo != nullptr);
    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    auto store = std::make_shared<LfsStore>(gitDirPath, makeCustomPolicy(QStringLiteral("qquickgit-test")));
    LfsStoreRegistry::registerStore(store);

    const QString repoPath = tempDir.path();
    const QString attributesPath = QDir(repoPath).filePath(QStringLiteral(".gitattributes"));
    REQUIRE(writeTextFile(attributesPath, QByteArray("*.png filter=lfs diff=lfs merge=lfs -text\n")));

    const QString imageFileName = QStringLiteral("red.png");
    const QString imagePath = QDir(repoPath).filePath(imageFileName);

    QImage image(10, 10, QImage::Format_ARGB32);
    image.fill(Qt::red);
    REQUIRE(image.save(imagePath, "PNG"));

    const QByteArray workingTreeBytes = readFileBytes(imagePath);
    REQUIRE(!workingTreeBytes.isEmpty());
    REQUIRE(QFile::exists(imagePath));

    git_filter_list* cleanFilters = nullptr;
    REQUIRE(git_filter_list_load(&cleanFilters, repo, nullptr, "red.png", GIT_FILTER_TO_ODB, GIT_FILTER_DEFAULT) == GIT_OK);
    REQUIRE(cleanFilters != nullptr);
    CHECK(git_filter_list_contains(cleanFilters, "lfs") == 1);

    git_buf cleanOut = GIT_BUF_INIT;
    REQUIRE(git_filter_list_apply_to_file(&cleanOut, cleanFilters, repo, "red.png") == GIT_OK);
    REQUIRE(cleanOut.size > 0);

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(QByteArray(cleanOut.ptr, static_cast<int>(cleanOut.size)), &pointer));
    CHECK(pointer.size == workingTreeBytes.size());

    const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
    CHECK(QFile::exists(objectPath));

    CHECK(QFile::exists(imagePath));
    const QByteArray workingTreeBytesAfter = readFileBytes(imagePath);
    CHECK(workingTreeBytesAfter == workingTreeBytes);

    git_filter_list* smudgeFilters = nullptr;
    REQUIRE(git_filter_list_load(&smudgeFilters, repo, nullptr, "red.png", GIT_FILTER_TO_WORKTREE, GIT_FILTER_DEFAULT) == GIT_OK);
    REQUIRE(smudgeFilters != nullptr);
    CHECK(git_filter_list_contains(smudgeFilters, "lfs") == 1);

    git_buf smudgeOut = GIT_BUF_INIT;
    REQUIRE(git_filter_list_apply_to_buffer(&smudgeOut,
                                            smudgeFilters,
                                            cleanOut.ptr,
                                            static_cast<size_t>(cleanOut.size)) == GIT_OK);
    REQUIRE(smudgeOut.size == static_cast<size_t>(workingTreeBytes.size()));
    CHECK(QByteArray(smudgeOut.ptr, static_cast<int>(smudgeOut.size)) == workingTreeBytes);

    git_buf_dispose(&cleanOut);
    git_buf_dispose(&smudgeOut);
    git_filter_list_free(cleanFilters);
    git_filter_list_free(smudgeFilters);
    LfsStoreRegistry::unregisterStore(gitDirPath, store);
    git_repository_free(repo);
}

TEST_CASE("Lfs commit via GitRepository stores pointer and checkout restores PNG", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    repository.initRepository();

    const QString attributesPath = repoDir.filePath(QStringLiteral(".gitattributes"));
    REQUIRE(QFile::exists(attributesPath));

    const QString imageFileName = QStringLiteral("red.png");
    const QString imagePath = repoDir.filePath(imageFileName);

    QImage image(10, 10, QImage::Format_ARGB32);
    image.fill(Qt::red);
    REQUIRE(image.save(imagePath, "PNG"));

    const QByteArray workingTreeBytes = readFileBytes(imagePath);
    REQUIRE(!workingTreeBytes.isEmpty());

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    repository.setAccount(&account);

    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add png"), QStringLiteral("LFS test")));

    CHECK(QFile::exists(imagePath));
    CHECK(readFileBytes(imagePath) == workingTreeBytes);

    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoDir.absolutePath().toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(repo != nullptr);

    const QByteArray blobData = readBlobFromHead(repo, "red.png");
    REQUIRE(!blobData.isEmpty());

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(blobData, &pointer));
    CHECK(pointer.size == workingTreeBytes.size());
    CHECK(!pointer.oid.isEmpty());

    QFile file(imagePath);
    REQUIRE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    file.write("corrupt");
    file.close();

    requireGitFutureSuccess(repository.reset(QStringLiteral("HEAD"), GitRepository::ResetMode::Hard));
    CHECK(readFileBytes(imagePath) == workingTreeBytes);
    repository.checkStatus();
    CHECK(repository.modifiedFileCount() == 0);

    git_repository_free(repo);
}

TEST_CASE("Lfs commits keep working tree PNG for multiple commits", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());
    tempDir.setAutoRemove(false);

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    repository.initRepository();

    const QString attributesPath = repoDir.filePath(QStringLiteral(".gitattributes"));
    REQUIRE(QFile::exists(attributesPath));

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    repository.setAccount(&account);

    const QString imageFileName = QStringLiteral("color.png");
    const QString imagePath = repoDir.filePath(imageFileName);

    const QByteArray redBytes = createPngFile(imagePath, Qt::red);
    REQUIRE(!redBytes.isEmpty());
    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add red"), QStringLiteral("LFS red")));

    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoDir.absolutePath().toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(repo != nullptr);
    const QString redCommit = headOidString(repo);
    REQUIRE(!redCommit.isEmpty());

    const QByteArray greenBytes = createPngFile(imagePath, Qt::green);
    REQUIRE(!greenBytes.isEmpty());
    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add green"), QStringLiteral("LFS green")));
    const QString greenCommit = headOidString(repo);
    REQUIRE(!greenCommit.isEmpty());

    const QByteArray blueBytes = createPngFile(imagePath, Qt::blue);
    REQUIRE(!blueBytes.isEmpty());
    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add blue"), QStringLiteral("LFS blue")));
    const QString blueCommit = headOidString(repo);
    REQUIRE(!blueCommit.isEmpty());

    repository.createBranch(QStringLiteral("check"), QStringLiteral("HEAD"), false);

    requireGitFutureSuccess(repository.reset(redCommit, GitRepository::ResetMode::Hard));
    CHECK(readFileBytes(imagePath) == redBytes);

    requireGitFutureSuccess(repository.reset(greenCommit, GitRepository::ResetMode::Hard));
    CHECK(readFileBytes(imagePath) == greenBytes);

    requireGitFutureSuccess(repository.reset(blueCommit, GitRepository::ResetMode::Hard));
    CHECK(readFileBytes(imagePath) == blueBytes);

    git_repository_free(repo);
}

TEST_CASE("Lfs hydration preserves executable bit after reset", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    repository.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    repository.setAccount(&account);

    const QString imageFileName = QStringLiteral("exec.png");
    const QString imagePath = repoDir.filePath(imageFileName);
    const QByteArray workingTreeBytes = createPngFile(imagePath, Qt::red);
    REQUIRE(!workingTreeBytes.isEmpty());

    QFile::Permissions permissions = QFileInfo(imagePath).permissions();
    permissions |= QFileDevice::ExeOwner;
    REQUIRE(QFile::setPermissions(imagePath, permissions));
    INFO(permissionDebugString(imagePath).toStdString());
    REQUIRE(hasOwnerExecutePermission(imagePath));

    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add executable png"), QStringLiteral("LFS exec")));

    QFile file(imagePath);
    REQUIRE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    REQUIRE(file.write("corrupt") == 7);
    file.close();

    QFile::Permissions qtPermissionsBeforeClear = QFileInfo(imagePath).permissions();
    QFile::Permissions qtPermissionsAfterClear = qtPermissionsBeforeClear;
    qtPermissionsAfterClear &= ~QFileDevice::ExeOwner;
    qtPermissionsAfterClear &= ~QFileDevice::ExeUser;
    qtPermissionsAfterClear &= ~QFileDevice::ExeGroup;
    qtPermissionsAfterClear &= ~QFileDevice::ExeOther;
    INFO(QStringLiteral("Qt perms clear attempt before=0x%1 after=0x%2")
             .arg(QString::number(static_cast<uint>(qtPermissionsBeforeClear), 16))
             .arg(QString::number(static_cast<uint>(qtPermissionsAfterClear), 16))
             .toStdString());
    REQUIRE(QFile::setPermissions(imagePath, qtPermissionsAfterClear));
    INFO(permissionDebugString(imagePath).toStdString());

    QString chmodError;
    // REQUIRE(clearExecuteBits(imagePath, &chmodError));
    INFO(chmodError.toStdString());
    INFO(permissionDebugString(imagePath).toStdString());
    REQUIRE(!hasOwnerExecutePermission(imagePath));

    requireGitFutureSuccess(repository.reset(QStringLiteral("HEAD"), GitRepository::ResetMode::Hard));
    INFO(permissionDebugString(imagePath).toStdString());
    CHECK(readFileBytes(imagePath) == workingTreeBytes);
    CHECK(hasOwnerExecutePermission(imagePath));
    repository.checkStatus();
    CHECK(repository.modifiedFileCount() == 0);
}

TEST_CASE("Lfs reset falls back to pointer when object is missing and no remote exists", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    repository.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    repository.setAccount(&account);

    const QString imagePath = repoDir.filePath(QStringLiteral("fallback.png"));
    const QByteArray workingTreeBytes = createPngFile(imagePath, Qt::red);
    REQUIRE(!workingTreeBytes.isEmpty());
    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add fallback png"), QStringLiteral("LFS fallback")));

    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoDir.absolutePath().toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(repo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    const QByteArray blobData = readBlobFromHead(repo, "fallback.png");
    REQUIRE(!blobData.isEmpty());
    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(blobData, &pointer));

    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
    REQUIRE(!objectPath.isEmpty());
    REQUIRE(QFileInfo::exists(objectPath));
    REQUIRE(QFile::remove(objectPath));

    REQUIRE(writeTextFile(imagePath, QByteArray("dirty\n")));
    REQUIRE(readFileBytes(imagePath) == QByteArray("dirty\n"));

    auto resetFuture = repository.reset(QStringLiteral("HEAD"), GitRepository::ResetMode::Hard);
    REQUIRE(AsyncFuture::waitForFinished(resetFuture, 60 * 1000));
    INFO("Reset error:" << resetFuture.result().errorMessage().toStdString()
         << "code:" << resetFuture.result().errorCode());

    // Expected behavior: no-remote/offline fetch errors should fall back to pointer text.
    CHECK(!resetFuture.result().hasError());

    const QByteArray postResetBytes = readFileBytes(imagePath);
    LfsPointer pointerAfterReset;
    CHECK(LfsPointer::parse(postResetBytes, &pointerAfterReset));
    CHECK(pointerAfterReset.oid == pointer.oid);
    CHECK(pointerAfterReset.size == pointer.size);
}

TEST_CASE("Lfs reset does not issue duplicate batch fetch attempts for missing object", "[LFS][regression][P2]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LocalLfsBatchServer server;
    REQUIRE(server.start());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    repository.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    repository.setAccount(&account);

    const QString imagePath = repoDir.filePath(QStringLiteral("duplicate-fetch.png"));
    const QByteArray workingTreeBytes = createPngFile(imagePath, Qt::green);
    REQUIRE(!workingTreeBytes.isEmpty());
    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add duplicate fetch png"),
                                         QStringLiteral("LFS duplicate fetch")));

    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoDir.absolutePath().toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(repo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    const QByteArray blobData = readBlobFromHead(repo, "duplicate-fetch.png");
    REQUIRE(!blobData.isEmpty());
    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(blobData, &pointer));

    const QString batchResponseBody = QStringLiteral(
        "{\"transfer\":\"basic\",\"objects\":[{\"oid\":\"%1\",\"size\":%2,"
        "\"error\":{\"code\":404,\"message\":\"missing\"}}]}")
        .arg(pointer.oid)
        .arg(pointer.size);
    server.setBatchResponse(batchResponseBody.toUtf8());

    const QString remoteUrl = QStringLiteral("http://127.0.0.1:%1/test.git").arg(server.port());
    REQUIRE(configureRemoteUrl(repoDir.absolutePath(), QStringLiteral("origin"), remoteUrl));

    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
    REQUIRE(!objectPath.isEmpty());
    REQUIRE(QFileInfo::exists(objectPath));
    REQUIRE(QFile::remove(objectPath));

    REQUIRE(writeTextFile(imagePath, QByteArray("dirty\n")));

    auto resetFuture = repository.reset(QStringLiteral("HEAD"), GitRepository::ResetMode::Hard);
    REQUIRE(AsyncFuture::waitForFinished(resetFuture, 60 * 1000));
    INFO("Reset error:" << resetFuture.result().errorMessage().toStdString()
         << "code:" << resetFuture.result().errorCode());

    QElapsedTimer settle;
    settle.start();
    while (settle.elapsed() < 1500) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    }

    // Fixed behavior: smudge does not start background network fetches.
    CHECK(server.batchRequestCount() == 1);
}

TEST_CASE("Lfs batch applies URL-scoped http.extraheader from git config", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LocalLfsAuthHeaderServer server;
    REQUIRE(server.start());

    GitRepository repository;
    repository.setDirectory(QDir(tempDir.path()));
    repository.initRepository();

    REQUIRE(configureRemoteUrl(tempDir.path(), QStringLiteral("origin"), server.remoteUrl()));

    const QString extraHeaderKey = QStringLiteral("http.%1/.extraheader").arg(server.remoteUrl());
    REQUIRE(setGitConfigString(tempDir.path(),
                               extraHeaderKey.toUtf8().constData(),
                               QStringLiteral("X-QQuickGit-Auth: scoped-token")));

    const QString gitDirPath = gitDirPathFromWorkTree(tempDir.path());
    REQUIRE(!gitDirPath.isEmpty());

    LfsBatchClient client(gitDirPath);
    const LfsBatchClient::ObjectSpec objectSpec{
        QStringLiteral("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        1
    };

    auto batchFuture = client.batch(QStringLiteral("download"), {objectSpec});
    REQUIRE(AsyncFuture::waitForFinished(batchFuture, 60 * 1000));
    INFO("Batch error:" << batchFuture.result().errorMessage().toStdString()
         << "code:" << batchFuture.result().errorCode());

    REQUIRE(server.batchRequestCount() == 1);
    CHECK(server.authorizedRequestCount() == 1);
    REQUIRE(!batchFuture.result().hasError());
}

TEST_CASE("Lfs batch does not apply URL-scoped http.extraheader when only path case differs",
          "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LocalLfsAuthHeaderServer server;
    REQUIRE(server.start());

    GitRepository repository;
    repository.setDirectory(QDir(tempDir.path()));
    repository.initRepository();

    const QString remoteUrl = server.remoteUrl();
    REQUIRE(configureRemoteUrl(tempDir.path(), QStringLiteral("origin"), remoteUrl));

    QString mismatchedScopeUrl = remoteUrl;
    mismatchedScopeUrl.replace(QStringLiteral("/test.git"), QStringLiteral("/Test.git"));
    REQUIRE(mismatchedScopeUrl != remoteUrl);

    const QString extraHeaderKey = QStringLiteral("http.%1/.extraheader").arg(mismatchedScopeUrl);
    REQUIRE(setGitConfigString(tempDir.path(),
                               extraHeaderKey.toUtf8().constData(),
                               QStringLiteral("X-QQuickGit-Auth: scoped-token")));

    const QString gitDirPath = gitDirPathFromWorkTree(tempDir.path());
    REQUIRE(!gitDirPath.isEmpty());

    LfsBatchClient client(gitDirPath);
    const LfsBatchClient::ObjectSpec objectSpec{
        QStringLiteral("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        1
    };

    auto batchFuture = client.batch(QStringLiteral("download"), {objectSpec});
    REQUIRE(AsyncFuture::waitForFinished(batchFuture, 60 * 1000));

    REQUIRE(server.batchRequestCount() == 1);
    CHECK(server.authorizedRequestCount() == 0);
    CHECK(batchFuture.result().hasError());
}

TEST_CASE("Lfs policy updates managed .gitattributes section", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    repository.initRepository();

    const QString attributesPath = repoDir.filePath(QStringLiteral(".gitattributes"));
    const QByteArray initialContents = readFileBytes(attributesPath);
    const QByteArray beginMarker = QByteArray("# qquickgit-test:begin-lfs");
    const QByteArray endMarker = QByteArray("# qquickgit-test:end-lfs");
    REQUIRE(initialContents.contains(beginMarker));
    REQUIRE(initialContents.contains(endMarker));

    LfsPolicy updatedPolicy;
    updatedPolicy.setAttributesSectionTag(QStringLiteral("qquickgit-test"));
    updatedPolicy.setRule(QStringLiteral("png"), [](const QString&, const QByteArray*) { return true; });
    updatedPolicy.setRule(QStringLiteral("pdf"), [](const QString&, const QByteArray*) { return true; });
    repository.setLfsPolicy(updatedPolicy);

    const QByteArray updatedContents = readFileBytes(attributesPath);
    REQUIRE(updatedContents.contains(beginMarker));
    REQUIRE(updatedContents.contains(endMarker));
    CHECK(updatedContents.contains(QByteArray("*.png filter=lfs diff=lfs merge=lfs -text")));
    CHECK(updatedContents.contains(QByteArray("*.pdf filter=lfs diff=lfs merge=lfs -text")));
}

TEST_CASE("Lfs empty policy does not write managed .gitattributes section", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.initRepository();

    const QString attributesPath = repoDir.filePath(QStringLiteral(".gitattributes"));
    const QByteArray contents = readFileBytes(attributesPath);
    CHECK(!contents.contains(QByteArray("begin-lfs")));
    CHECK(!contents.contains(QByteArray("end-lfs")));
}

TEST_CASE("GitRepository resetHard discards local changes", "[GitRepository]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    repository.initRepository();

    Account account;
    account.setName(QStringLiteral("Reset Tester"));
    account.setEmail(QStringLiteral("reset@test.invalid"));
    repository.setAccount(&account);

    const QString filePath = repoDir.filePath(QStringLiteral("note.txt"));
    REQUIRE(writeTextFile(filePath, QByteArray("original\n")));
    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Initial"), QStringLiteral("add note")));

    REQUIRE(writeTextFile(filePath, QByteArray("modified\n")));
    CHECK(readFileBytes(filePath) == QByteArray("modified\n"));

    requireGitFutureSuccess(repository.reset(QStringLiteral("HEAD"), GitRepository::ResetMode::Hard));
    CHECK(readFileBytes(filePath) == QByteArray("original\n"));

    repository.checkStatus();
    CHECK(repository.modifiedFileCount() == 0);
}

TEST_CASE("LfsStoreRegistry keeps store when other repository is alive", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    std::shared_ptr<LfsStore> storeA;
    {
        const QDir repoDir(tempDir.path());
        GitRepository repoA;
        repoA.setDirectory(repoDir);
        repoA.initRepository();
        storeA = repoA.lfsStore();
        REQUIRE(storeA);

        {
            GitRepository repoB;
            repoB.setDirectory(repoDir);
            repoB.initRepository();
            auto storeB = repoB.lfsStore();
            REQUIRE(storeB);
            REQUIRE(storeB == LfsStoreRegistry::storeFor(storeB->gitDirPath()));
        }

        REQUIRE(LfsStoreRegistry::storeFor(storeA->gitDirPath()) == storeA);
    }
}

TEST_CASE("Lfs filter streams large files without buffering", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    repository.initRepository();

    Account account;
    account.setName(QStringLiteral("Stream Tester"));
    account.setEmail(QStringLiteral("stream@test.invalid"));
    repository.setAccount(&account);

    const QString largeFileName = QStringLiteral("large.png");
    const QString largeFilePath = repoDir.filePath(largeFileName);

    QByteArray chunk(1024 * 256, 'a');
    {
        QFile file(largeFilePath);
        REQUIRE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        for (int i = 0; i < 8; ++i) {
            REQUIRE(file.write(chunk) == chunk.size());
        }
    }

    const QByteArray workingTreeBytes = readFileBytes(largeFilePath);
    REQUIRE(workingTreeBytes.size() == chunk.size() * 8);

    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add large file"), QStringLiteral("LFS streaming")));

    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoDir.absolutePath().toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(repo != nullptr);

    const QByteArray blobData = readBlobFromHead(repo, "large.png");
    REQUIRE(!blobData.isEmpty());

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(blobData, &pointer));
    CHECK(pointer.size == workingTreeBytes.size());

    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
    CHECK(QFile::exists(objectPath));

    git_repository_free(repo);
}

TEST_CASE("Lfs filter svg eligibility fails with relative path when CWD differs", "[LFS][svg]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    repository.initRepository();

    repository.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));

    const QString svgPath = repoDir.filePath(QStringLiteral("test.svg"));
    const QByteArray svgData =
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"10\" height=\"10\">"
        "<image href=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB\"/>"
        "</svg>";
    REQUIRE(writeTextFile(svgPath, svgData));

    const QString oldCwd = QDir::currentPath();
    QTemporaryDir otherDir;
    REQUIRE(otherDir.isValid());
    REQUIRE(QDir::setCurrent(otherDir.path()));

    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoDir.absolutePath().toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(repo != nullptr);

    git_filter_list* cleanFilters = nullptr;
    REQUIRE(git_filter_list_load(&cleanFilters, repo, nullptr, "test.svg", GIT_FILTER_TO_ODB, GIT_FILTER_DEFAULT) == GIT_OK);
    REQUIRE(cleanFilters != nullptr);

    git_buf cleanOut = GIT_BUF_INIT;
    REQUIRE(git_filter_list_apply_to_file(&cleanOut, cleanFilters, repo, "test.svg") == GIT_OK);
    REQUIRE(cleanOut.size > 0);

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(QByteArray(cleanOut.ptr, static_cast<int>(cleanOut.size)), &pointer));
    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
    CHECK(QFile::exists(objectPath));

    git_buf_dispose(&cleanOut);
    git_filter_list_free(cleanFilters);
    git_repository_free(repo);

    QDir::setCurrent(oldCwd);
}

TEST_CASE("Lfs smudge streams non-pointer file without buffering", "[LFS]") {
    // Note: GitRepository::initGitEngine() in tests/qquickgit-test-main.cpp
    // registers QQuickGit's LFS filter with libgit2. This test uses libgit2
    // streaming APIs directly, but it still exercises QQuickGit::LfsFilter.
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), 0) == GIT_OK);
    REQUIRE(repo != nullptr);

    const QString repoPath = tempDir.path();
    const QString attributesPath = QDir(repoPath).filePath(QStringLiteral(".gitattributes"));
    REQUIRE(writeTextFile(attributesPath, QByteArray("*.bin filter=lfs diff=lfs merge=lfs -text\n")));

    const QString fileName = QStringLiteral("not-pointer.bin");
    const QString filePath = QDir(repoPath).filePath(fileName);
    const int chunkSize = 128 * 1024;
    const int chunkCount = 20;
    const QByteArray header("not-lfs\n");
    {
        QFile file(filePath);
        REQUIRE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        REQUIRE(file.write(header) == header.size());
        QByteArray chunk(chunkSize, 'x');
        for (int i = 0; i < chunkCount; ++i) {
            REQUIRE(file.write(chunk) == chunk.size());
        }
    }

    const size_t expectedSize = static_cast<size_t>(header.size() + chunkSize * chunkCount);
    REQUIRE(static_cast<size_t>(QFileInfo(filePath).size()) == expectedSize);

    git_filter_list* smudgeFilters = nullptr;
    REQUIRE(git_filter_list_load(&smudgeFilters, repo, nullptr, "not-pointer.bin", GIT_FILTER_TO_WORKTREE, GIT_FILTER_DEFAULT) == GIT_OK);
    REQUIRE(smudgeFilters != nullptr);
    CHECK(git_filter_list_contains(smudgeFilters, "lfs") == 1);

    auto* sink = new CountingWriteStream{};
    sink->parent.write = countingStreamWrite;
    sink->parent.close = countingStreamClose;
    sink->parent.free = countingStreamFree;

    REQUIRE(git_filter_list_stream_file(smudgeFilters, repo, "not-pointer.bin", &sink->parent) == GIT_OK);

    CHECK(sink->totalBytes == expectedSize);
    CHECK(sink->writeCalls > 1);
    CHECK(sink->maxWrite <= static_cast<size_t>(chunkSize));

    sink->parent.free(&sink->parent);
    git_filter_list_free(smudgeFilters);
    git_repository_free(repo);
}

TEST_CASE("Lfs clean write failure discards temporary object file", "[LFS][regression][P2]") {
#if !defined(Q_OS_UNIX)
    SKIP("Requires RLIMIT_FSIZE to force deterministic write failure");
#else
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), 0) == GIT_OK);
    REQUIRE(repo != nullptr);

    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    auto store = std::make_shared<LfsStore>(gitDirPath, makeCustomPolicy(QStringLiteral("qquickgit-test")));
    LfsStoreRegistry::registerStore(store);

    const QString attributesPath = QDir(tempDir.path()).filePath(QStringLiteral(".gitattributes"));
    REQUIRE(writeTextFile(attributesPath, QByteArray("*.png filter=lfs diff=lfs merge=lfs -text\n")));

    const QString tmpDirPath = QDir(gitDirPath).filePath(QStringLiteral("lfs/tmp"));
    QDir().mkpath(tmpDirPath);
    const QDir tmpDir(tmpDirPath);
    const int beforeCount = tmpDir.entryList(QDir::Files | QDir::NoDotAndDotDot).size();
    const QString objectsDirPath = QDir(gitDirPath).filePath(QStringLiteral("lfs/objects"));
    QDir().mkpath(objectsDirPath);
    const int objectFilesBefore = countFilesRecursively(objectsDirPath);

    ScopedSignalHandler ignoreSigXfsz(SIGXFSZ, SIG_IGN);
    ScopedFileSizeLimit fileSizeLimit;
    REQUIRE(fileSizeLimit.apply(1024));

    const QByteArray payload(64 * 1024, 'x');
    git_filter_list* cleanFilters = nullptr;
    REQUIRE(git_filter_list_load(&cleanFilters, repo, nullptr, "write-fail.png", GIT_FILTER_TO_ODB, GIT_FILTER_DEFAULT) == GIT_OK);
    REQUIRE(cleanFilters != nullptr);

    git_buf cleanOut = GIT_BUF_INIT;
    const int applyResult = git_filter_list_apply_to_buffer(&cleanOut,
                                                            cleanFilters,
                                                            payload.constData(),
                                                            static_cast<size_t>(payload.size()));
    CHECK(applyResult != GIT_OK);

    git_buf_dispose(&cleanOut);
    git_filter_list_free(cleanFilters);

    const int afterCount = tmpDir.entryList(QDir::Files | QDir::NoDotAndDotDot).size();
    CHECK(afterCount == beforeCount);
    const int objectFilesAfter = countFilesRecursively(objectsDirPath);
    CHECK(objectFilesAfter == objectFilesBefore);

    LfsStoreRegistry::unregisterStore(gitDirPath, store);
    git_repository_free(repo);
#endif
}

TEST_CASE("LfsBatchClient batch and download against GitHub", "[LFS][network]") {
    const QString expectedOid = QStringLiteral("181a7d98e96a130662d153a385ead3976d304acc5f3ad905d34e4fe870535243");
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QString repoPath = QDir(tempDir.path()).filePath(QStringLiteral("lfs-test"));
    GitRepository repository;
    repository.setDirectory(QDir(repoPath));

    auto cloneFuture = repository.clone(QUrl(lfsTestRepoUrl()));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(repo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    const QByteArray pointerBlob = readBlobFromHead(repo, "fixtures/seed.bin");
    REQUIRE(!pointerBlob.isEmpty());

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(pointerBlob, &pointer));
    REQUIRE(pointer.oid == expectedOid);

    const QString gitDirPath = gitDirPathFromWorkTree(repoPath);
    REQUIRE(!gitDirPath.isEmpty());

    LfsBatchClient client(gitDirPath);
    LfsStore store(gitDirPath);
    const LfsBatchClient::ObjectSpec spec{pointer.oid, pointer.size};

    auto batchFuture = client.batch(QStringLiteral("download"), {spec});
    REQUIRE(AsyncFuture::waitForFinished(batchFuture, 60 * 1000));
    INFO("Batch error:" << batchFuture.result().errorMessage().toStdString());
    REQUIRE(!batchFuture.result().hasError());

    const auto response = batchFuture.result().value();
    const LfsBatchClient::ObjectResponse* objectResponse = nullptr;
    for (const auto& object : response.objects) {
        if (object.oid == pointer.oid) {
            objectResponse = &object;
            break;
        }
    }
    REQUIRE(objectResponse != nullptr);
    REQUIRE(objectResponse->errorMessage.isEmpty());
    REQUIRE(objectResponse->actions.contains(QStringLiteral("download")));

    const auto downloadAction = objectResponse->actions.value(QStringLiteral("download"));
    auto downloadFuture = client.downloadObject(downloadAction, store, pointer);
    REQUIRE(AsyncFuture::waitForFinished(downloadFuture, 60 * 1000));
    INFO("Download error:" << downloadFuture.result().errorMessage().toStdString());
    REQUIRE(!downloadFuture.result().hasError());

    auto readResult = store.readObject(pointer.oid);
    INFO("Read error:" << readResult.errorMessage().toStdString());
    REQUIRE(!readResult.hasError());
    CHECK(readResult.value().size() == pointer.size);
    const QString downloadedSha256 =
        QString::fromLatin1(QCryptographicHash::hash(readResult.value(), QCryptographicHash::Sha256).toHex());
    CHECK(downloadedSha256 == expectedOid);
}

TEST_CASE("LfsBatchClient uploadObject validates inputs before network", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), 0) == GIT_OK);
    REQUIRE(repo != nullptr);

    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    LfsBatchClient client(gitDirPath);

    {
        LfsBatchClient::Action action;
        const QString missingPath = QDir(tempDir.path()).filePath(QStringLiteral("missing-object"));
        LfsPointer pointer;
        pointer.oid = QStringLiteral("oid");
        pointer.size = 1;

        auto future = client.uploadObject(action, missingPath, pointer);
        REQUIRE(AsyncFuture::waitForFinished(future, 1000));
        REQUIRE(future.result().hasError());
        CHECK(future.result().errorCode() == static_cast<int>(LfsFetchErrorCode::Protocol));
    }

    {
        const QString objectPath = QDir(tempDir.path()).filePath(QStringLiteral("object.bin"));
        REQUIRE(writeTextFile(objectPath, QByteArray("abc")));

        LfsBatchClient::Action action;
        action.href = QUrl(QStringLiteral("https://github.com/vpicaver/lfs-test.git/info/lfs/objects"));

        LfsPointer pointer;
        pointer.oid = QStringLiteral("oid");
        pointer.size = 5;

        auto future = client.uploadObject(action, objectPath, pointer);
        REQUIRE(AsyncFuture::waitForFinished(future, 1000));
        REQUIRE(future.result().hasError());
        CHECK(future.result().errorCode() == static_cast<int>(LfsFetchErrorCode::Protocol));
    }

    git_repository_free(repo);
}

TEST_CASE("LfsBatchClient download hash mismatch keeps existing cached object", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LocalLfsDownloadServer server;
    REQUIRE(server.start());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), 0) == GIT_OK);
    REQUIRE(repo != nullptr);

    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    REQUIRE(!gitDirPath.isEmpty());
    LfsStore store(gitDirPath);
    LfsBatchClient client(gitDirPath);

    const QByteArray expectedBytes("expected-mismatch-payload");
    const QByteArray actualBytes("actual-cached-object-data");
    REQUIRE(expectedBytes.size() == actualBytes.size());
    REQUIRE(expectedBytes != actualBytes);

    const QString expectedOid =
        QString::fromLatin1(QCryptographicHash::hash(expectedBytes, QCryptographicHash::Sha256).toHex());
    LfsPointer expectedPointer;
    expectedPointer.oid = expectedOid;
    expectedPointer.size = expectedBytes.size();

    auto existingStoreResult = store.storeBytes(actualBytes);
    INFO("Seed object error:" << existingStoreResult.errorMessage().toStdString());
    REQUIRE(!existingStoreResult.hasError());
    const LfsPointer existingPointer = existingStoreResult.value();
    REQUIRE(existingPointer.oid != expectedPointer.oid);

    const QString existingObjectPath = LfsStore::objectPath(gitDirPath, existingPointer.oid);
    REQUIRE(!existingObjectPath.isEmpty());
    REQUIRE(QFileInfo::exists(existingObjectPath));

    server.setObject(expectedPointer.oid, actualBytes);
    LfsBatchClient::Action action;
    action.href = QUrl(QStringLiteral("%1/objects/%2")
                           .arg(server.endpoint())
                           .arg(expectedPointer.oid));

    auto downloadFuture = client.downloadObject(action, store, expectedPointer);
    REQUIRE(AsyncFuture::waitForFinished(downloadFuture, 60 * 1000));
    INFO("Download error:" << downloadFuture.result().errorMessage().toStdString()
         << "code:" << downloadFuture.result().errorCode());
    REQUIRE(downloadFuture.result().hasError());
    CHECK(downloadFuture.result().errorCode() == static_cast<int>(LfsFetchErrorCode::Protocol));
    CHECK(downloadFuture.result().errorMessage().contains(QStringLiteral("hash mismatch")));

    CHECK(QFileInfo::exists(existingObjectPath));
    auto readExistingResult = store.readObject(existingPointer.oid);
    INFO("Read existing object error:" << readExistingResult.errorMessage().toStdString());
    REQUIRE(!readExistingResult.hasError());
    CHECK(readExistingResult.value() == actualBytes);

    git_repository_free(repo);
}

TEST_CASE("LfsBatchClient can install LfsAuthProvider", "[LFS]") {
    const auto previous = LfsBatchClient::lfsAuthProvider();
    auto provider = std::make_shared<StaticLfsAuthProvider>(QByteArrayLiteral("Bearer test-token"));

    LfsBatchClient::setLfsAuthProvider(provider);
    CHECK(LfsBatchClient::lfsAuthProvider() == provider);

    LfsBatchClient::setLfsAuthProvider(previous);
}

TEST_CASE("LfsStore fetchObject keeps working when caller releases store early", "[LFS][network]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QString repoPath = QDir(tempDir.path()).filePath(QStringLiteral("lfs-test"));
    GitRepository repository;
    repository.setDirectory(QDir(repoPath));

    auto cloneFuture = repository.clone(QUrl(lfsTestRepoUrl()));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(repo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    const QByteArray pointerBlob = readBlobFromHead(repo, "fixtures/seed.bin");
    REQUIRE(!pointerBlob.isEmpty());

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(pointerBlob, &pointer));

    const QString gitDirPath = gitDirPathFromWorkTree(repoPath);
    REQUIRE(!gitDirPath.isEmpty());
    const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
    REQUIRE(!objectPath.isEmpty());
    if (QFile::exists(objectPath)) {
        REQUIRE(QFile::remove(objectPath));
    }

    std::shared_ptr<LfsStore> store = std::make_shared<LfsStore>(gitDirPath, LfsPolicy());
    auto fetchFuture = store->fetchObject(pointer);
    store.reset();

    REQUIRE(AsyncFuture::waitForFinished(fetchFuture, 60 * 1000));

    REQUIRE(fetchFuture.isCanceled());

    CHECK(!QFile::exists(objectPath));
}

TEST_CASE("Lfs checkout populates working-tree bytes for known pointer", "[LFS][network]") {
    const QString expectedOid = QStringLiteral("181a7d98e96a130662d153a385ead3976d304acc5f3ad905d34e4fe870535243");
    QTemporaryDir tempDir;
    tempDir.setAutoRemove(false);
    REQUIRE(tempDir.isValid());

    const QString repoPath = QDir(tempDir.path()).filePath(QStringLiteral("lfs-test-checkout"));
    GitRepository repository;
    repository.setDirectory(QDir(repoPath));

    auto cloneFuture = repository.clone(QUrl(lfsTestRepoUrl()));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(repo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    const QString pointerPath = QStringLiteral("fixtures/seed.bin");
    const QByteArray pointerBlob = readBlobFromHead(repo, pointerPath.toUtf8().constData());
    REQUIRE(!pointerBlob.isEmpty());

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(pointerBlob, &pointer));
    REQUIRE(pointer.oid == expectedOid);
    INFO("Pointer path:" << pointerPath.toStdString());

    requireGitFutureSuccess(repository.reset(QStringLiteral("HEAD"), GitRepository::ResetMode::Hard));

    const QString workingFilePath = QDir(repoPath).filePath(pointerPath);
    const QByteArray workingBytes = readFileBytes(workingFilePath);
    REQUIRE(!workingBytes.isEmpty());
    CHECK(workingBytes.size() == pointer.size);

    LfsPointer parsedPointer;
    CHECK(!LfsPointer::parse(workingBytes, &parsedPointer));

    const QString workingSha256 =
        QString::fromLatin1(QCryptographicHash::hash(workingBytes, QCryptographicHash::Sha256).toHex());
    CHECK(workingSha256.toStdString() == expectedOid.toStdString());
}

TEST_CASE("Lfs clone hydrates working-tree bytes without explicit reset", "[LFS][network][regression][P2]") {
    const QString expectedOid = QStringLiteral("181a7d98e96a130662d153a385ead3976d304acc5f3ad905d34e4fe870535243");
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QString repoPath = QDir(tempDir.path()).filePath(QStringLiteral("lfs-test-clone-hydration"));
    GitRepository repository;
    repository.setDirectory(QDir(repoPath));

    auto cloneFuture = repository.clone(QUrl(lfsTestRepoUrl()));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    QByteArray workingBytes;
    bool foundExpectedContent = false;
    QDirIterator it(repoPath, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString filePath = it.next();
        if (filePath.contains(QStringLiteral("/.git/"))) {
            continue;
        }
        const QByteArray fileBytes = readFileBytes(filePath);
        if (fileBytes.isEmpty()) {
            continue;
        }
        LfsPointer parsedPointer;
        if (LfsPointer::parse(fileBytes, &parsedPointer)) {
            continue;
        }
        const QString sha256 =
            QString::fromLatin1(QCryptographicHash::hash(fileBytes, QCryptographicHash::Sha256).toHex());
        if (sha256 == expectedOid) {
            workingBytes = fileBytes;
            foundExpectedContent = true;
            break;
        }
    }
    REQUIRE(foundExpectedContent);

    const QString workingSha256 =
        QString::fromLatin1(QCryptographicHash::hash(workingBytes, QCryptographicHash::Sha256).toHex());
    CHECK(workingSha256 == expectedOid);
}

TEST_CASE("Lfs policy configured before clone remains active for subsequent commits", "[LFS][regression][P2]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-policy-clone"));
    const QString consumerPath = QDir(tempDir.path()).filePath(QStringLiteral("consumer-policy-clone"));
    const QString imageFileName = QStringLiteral("post-clone.png");
    const QString policyTag = QStringLiteral("qquickgit-test");

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    REQUIRE(writeTextFile(QDir(authorPath).filePath(QStringLiteral("README.md")), QByteArray("seed\n")));
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Initial"), QStringLiteral("Seed repository")));

    GitRepository consumer;
    consumer.setDirectory(QDir(consumerPath));
    consumer.setLfsPolicy(makeCustomPolicy(policyTag));
    consumer.setAccount(&account);

    requireGitFutureSuccess(consumer.clone(QUrl::fromLocalFile(authorPath)));

    // Regression guard: clone should initialize repository-scoped LFS store/policy state.
    REQUIRE(consumer.lfsStore() != nullptr);

    const QString attributesPath = QDir(consumerPath).filePath(QStringLiteral(".gitattributes"));
    const QByteArray attributesContents = readFileBytes(attributesPath);
    REQUIRE(attributesContents.contains(QByteArray("# qquickgit-test:begin-lfs")));
    REQUIRE(attributesContents.contains(QByteArray("*.png filter=lfs diff=lfs merge=lfs -text")));

    const QString imagePath = QDir(consumerPath).filePath(imageFileName);
    const QByteArray workingTreeBytes = createPngFile(imagePath, Qt::blue);
    REQUIRE(!workingTreeBytes.isEmpty());
    REQUIRE_NOTHROW(consumer.commitAll(QStringLiteral("Add post-clone png"), QStringLiteral("LFS pointer expected")));

    git_repository* consumerRepo = nullptr;
    REQUIRE(git_repository_open(&consumerRepo, consumerPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(consumerRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> consumerRepoHolder(consumerRepo, &git_repository_free);

    const QByteArray committedBlob = readBlobFromHead(consumerRepo, imageFileName.toUtf8().constData());
    REQUIRE(!committedBlob.isEmpty());

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(committedBlob, &pointer));
    CHECK(pointer.size == workingTreeBytes.size());
    CHECK(!pointer.oid.isEmpty());
}

TEST_CASE("Lfs pull fast-forward hydrates from local object store", "[LFS][regression][P2]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author"));
    const QString consumerPath = QDir(tempDir.path()).filePath(QStringLiteral("consumer"));
    const QString trackedFileName = QStringLiteral("pull-fastforward.png");

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray initialBytes = createPngFile(authorFilePath, Qt::red);
    REQUIRE(!initialBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add LFS file"), QStringLiteral("LFS pull baseline")));

    GitRepository consumer;
    consumer.setDirectory(QDir(consumerPath));
    auto cloneFuture = consumer.clone(QUrl::fromLocalFile(authorPath));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Consumer clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    const QByteArray updatedBytes = createPngFile(authorFilePath, Qt::blue);
    REQUIRE(!updatedBytes.isEmpty());

    const QString consumerGitDirPath = gitDirPathFromWorkTree(consumerPath);
    REQUIRE(!consumerGitDirPath.isEmpty());
    LfsStore consumerStore(consumerGitDirPath);
    auto seedResult = consumerStore.storeBytes(updatedBytes);
    INFO("Seed error:" << seedResult.errorMessage().toStdString());
    REQUIRE(!seedResult.hasError());
    const LfsPointer seededPointer = seedResult.value();

    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Update LFS file"), QStringLiteral("LFS pull update")));

    auto pullFuture = consumer.pull();
    REQUIRE(AsyncFuture::waitForFinished(pullFuture, 60 * 1000));
    INFO("Pull error:" << pullFuture.result().errorMessage().toStdString()
         << "code:" << pullFuture.result().errorCode());
    REQUIRE(!pullFuture.result().hasError());
    CHECK(pullFuture.result().value().state() == GitRepository::MergeResult::FastForward);

    const QString consumerFilePath = QDir(consumerPath).filePath(trackedFileName);
    const QByteArray workingBytes = readFileBytes(consumerFilePath);
    REQUIRE(!workingBytes.isEmpty());
    CHECK(workingBytes.size() == seededPointer.size);

    LfsPointer parsedPointer;
    CHECK_FALSE(LfsPointer::parse(workingBytes, &parsedPointer));
    CHECK(workingBytes == updatedBytes);

    const QString workingSha256 =
        QString::fromLatin1(QCryptographicHash::hash(workingBytes, QCryptographicHash::Sha256).toHex());
    CHECK(workingSha256 == seededPointer.oid);
}

TEST_CASE("Lfs pull fast-forward hydrates by fetching missing LFS object", "[LFS][regression][P2]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LocalLfsDownloadServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-fetch"));
    const QString consumerPath = QDir(tempDir.path()).filePath(QStringLiteral("consumer-fetch"));
    const QString trackedFileName = QStringLiteral("pull-fastforward-fetch.png");

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray initialBytes = createPngFile(authorFilePath, Qt::red);
    REQUIRE(!initialBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add LFS file"), QStringLiteral("LFS pull fetch baseline")));

    GitRepository consumer;
    consumer.setDirectory(QDir(consumerPath));
    auto cloneFuture = consumer.clone(QUrl::fromLocalFile(authorPath));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Consumer clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    const QByteArray updatedBytes = createPngFile(authorFilePath, Qt::green);
    REQUIRE(!updatedBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Update LFS file"), QStringLiteral("LFS pull fetch update")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QByteArray authorBlobData = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!authorBlobData.isEmpty());
    LfsPointer expectedPointer;
    REQUIRE(LfsPointer::parse(authorBlobData, &expectedPointer));
    REQUIRE(expectedPointer.size == updatedBytes.size());

    REQUIRE(setGitConfigString(consumerPath, "lfs.url", lfsServer.endpoint()));
    lfsServer.setObject(expectedPointer.oid, updatedBytes);

    const QString consumerGitDirPath = gitDirPathFromWorkTree(consumerPath);
    REQUIRE(!consumerGitDirPath.isEmpty());
    const QString missingObjectPath = LfsStore::objectPath(consumerGitDirPath, expectedPointer.oid);
    REQUIRE(!missingObjectPath.isEmpty());
    if (QFileInfo::exists(missingObjectPath)) {
        REQUIRE(QFile::remove(missingObjectPath));
    }

    auto pullFuture = consumer.pull();
    REQUIRE(AsyncFuture::waitForFinished(pullFuture, 60 * 1000));
    INFO("Pull error:" << pullFuture.result().errorMessage().toStdString()
         << "code:" << pullFuture.result().errorCode());
    REQUIRE(!pullFuture.result().hasError());
    CHECK(pullFuture.result().value().state() == GitRepository::MergeResult::FastForward);

    const QString consumerFilePath = QDir(consumerPath).filePath(trackedFileName);
    const QByteArray workingBytes = readFileBytes(consumerFilePath);
    REQUIRE(!workingBytes.isEmpty());
    CHECK(workingBytes.size() == expectedPointer.size);

    LfsPointer parsedPointer;
    CHECK_FALSE(LfsPointer::parse(workingBytes, &parsedPointer));
    CHECK(workingBytes == updatedBytes);

    const QString workingSha256 =
        QString::fromLatin1(QCryptographicHash::hash(workingBytes, QCryptographicHash::Sha256).toHex());
    CHECK(workingSha256.toStdString() == expectedPointer.oid.toStdString());

    CHECK(lfsServer.batchRequestCount() > 0);
    CHECK(lfsServer.objectRequestCount() > 0);
}

TEST_CASE("Lfs push uploads tracked objects before git push", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LocalLfsUploadServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-push"));
    const QString remotePath = QDir(tempDir.path()).filePath(QStringLiteral("remote-push.git"));
    const QString trackedFileName = QStringLiteral("push-upload.png");

    git_repository* remoteRepo = nullptr;
    REQUIRE(git_repository_init(&remoteRepo, remotePath.toLocal8Bit().constData(), 1) == GIT_OK);
    REQUIRE(remoteRepo != nullptr);
    git_repository_free(remoteRepo);

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray workingBytes = createPngFile(authorFilePath, Qt::red);
    REQUIRE(!workingBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add LFS file"), QStringLiteral("LFS push upload")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QByteArray committedBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!committedBlob.isEmpty());
    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(committedBlob, &pointer));
    REQUIRE(pointer.size == workingBytes.size());

    lfsServer.setExpectedObject(pointer.oid, pointer.size);

    REQUIRE(configureRemoteUrl(authorPath, QStringLiteral("origin"), QUrl::fromLocalFile(remotePath).toString()));
    REQUIRE(setGitConfigString(authorPath, "lfs.url", lfsServer.endpoint()));

    auto pushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(pushFuture, 60 * 1000));
    INFO("Push error:" << pushFuture.result().errorMessage().toStdString()
         << "code:" << pushFuture.result().errorCode());
    REQUIRE(!pushFuture.result().hasError());

    // Regression guard: push must upload LFS objects before refs are updated remotely.
    CHECK(lfsServer.uploadBatchRequestCount() > 0);
    CHECK(lfsServer.uploadRequestCount() > 0);
}

TEST_CASE("LfsBatchClient upload and round-trip download against GitHub", "[LFS][network][upload]") {
    const QStringList missingEnv = missingUploadAuthEnvVars();
    if (!missingEnv.isEmpty()) {
        const QString skipMessage =
            QStringLiteral("Missing required env var(s): %1").arg(missingEnv.join(QStringLiteral(", ")));
        SKIP(skipMessage.toStdString());
    }
    const QString authLfsUrl = lfsAuthEndpoint();
    const QString username = lfsAuthUsername();
    const QString token = lfsAuthToken();

    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QString repoPath = QDir(tempDir.path()).filePath(QStringLiteral("lfs-test-upload"));
    GitRepository repository;
    repository.setDirectory(QDir(repoPath));

    auto cloneFuture = repository.clone(QUrl(lfsTestRepoUrl()));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    ScopedLfsAuthProvider authProvider(std::make_shared<EnvLfsAuthProvider>(username, token));

    REQUIRE(setGitConfigString(repoPath, "lfs.url", authLfsUrl));

    const QString gitDirPath = gitDirPathFromWorkTree(repoPath);
    REQUIRE(!gitDirPath.isEmpty());

    LfsBatchClient client(gitDirPath);
    LfsStore store(gitDirPath);

    const QByteArray payload = QByteArray("qquickgit-lfs-upload-")
                               + QByteArray::number(QDateTime::currentMSecsSinceEpoch());
    auto pointerResult = store.storeBytes(payload);
    REQUIRE(!pointerResult.hasError());
    const LfsPointer pointer = pointerResult.value();

    const LfsBatchClient::ObjectSpec spec{pointer.oid, pointer.size};
    auto batchFuture = client.batch(QStringLiteral("upload"), {spec});
    REQUIRE(AsyncFuture::waitForFinished(batchFuture, 60 * 1000));
    INFO("Upload batch error:" << batchFuture.result().errorMessage().toStdString());
    REQUIRE(!batchFuture.result().hasError());

    const auto response = batchFuture.result().value();
    REQUIRE(!response.objects.isEmpty());
    const auto& object = response.objects.first();
    INFO("Upload object error:" << object.errorMessage.toStdString());
    INFO("Upload object error code:" << object.errorCode);
    INFO("Upload object actions:" << object.actions.keys().join(QStringLiteral(", ")).toStdString());
    REQUIRE(object.errorMessage.isEmpty());

    if (object.actions.contains(QStringLiteral("upload"))) {
        auto uploadFuture = client.uploadObject(object.actions.value(QStringLiteral("upload")),
                                                LfsStore::objectPath(gitDirPath, pointer.oid),
                                                pointer);
        REQUIRE(AsyncFuture::waitForFinished(uploadFuture, 60 * 1000));
        INFO("Upload error:" << uploadFuture.result().errorMessage().toStdString());
        REQUIRE(!uploadFuture.result().hasError());
    }

    if (object.actions.contains(QStringLiteral("verify"))) {
        auto verifyFuture = client.verifyObject(object.actions.value(QStringLiteral("verify")), pointer);
        REQUIRE(AsyncFuture::waitForFinished(verifyFuture, 60 * 1000));
        INFO("Verify error:" << verifyFuture.result().errorMessage().toStdString());
        REQUIRE(!verifyFuture.result().hasError());
    }

    auto downloadBatchFuture = client.batch(QStringLiteral("download"), {spec});
    REQUIRE(AsyncFuture::waitForFinished(downloadBatchFuture, 60 * 1000));
    INFO("Download batch error:" << downloadBatchFuture.result().errorMessage().toStdString());
    REQUIRE(!downloadBatchFuture.result().hasError());

    const auto downloadResponse = downloadBatchFuture.result().value();
    REQUIRE(!downloadResponse.objects.isEmpty());
    const auto& downloadObject = downloadResponse.objects.first();
    INFO("Download object error:" << downloadObject.errorMessage.toStdString());
    INFO("Download object error code:" << downloadObject.errorCode);
    INFO("Download object actions:" << downloadObject.actions.keys().join(QStringLiteral(", ")).toStdString());
    REQUIRE(downloadObject.errorMessage.isEmpty());
    REQUIRE(downloadObject.actions.contains(QStringLiteral("download")));

    const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
    REQUIRE(QFile::remove(objectPath));

    auto downloadFuture = client.downloadObject(downloadObject.actions.value(QStringLiteral("download")),
                                                store,
                                                pointer);
    REQUIRE(AsyncFuture::waitForFinished(downloadFuture, 60 * 1000));
    INFO("Download error:" << downloadFuture.result().errorMessage().toStdString());
    REQUIRE(!downloadFuture.result().hasError());

    auto readResult = store.readObject(pointer.oid);
    REQUIRE(!readResult.hasError());
    CHECK(readResult.value() == payload);
}
