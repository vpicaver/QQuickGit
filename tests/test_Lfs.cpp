// Catch includes
#include <catch2/catch_test_macros.hpp>

// libgit2
#include "git2.h"
#include "git2/filter.h"

// Our includes
#include "GitRepository.h"
#include "TestUtilities.h"
#include "Account.h"
#include "LfsAuthProvider.h"
#include "LfsBatchClient.h"
#include "LfsStore.h"
#include "LfsServer.h"
#include "ProgressState.h"
#include "SshLfsAuthenticator.h"
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

QString headTreeOidString(git_repository* repo)
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

    git_commit* commit = nullptr;
    if (git_commit_lookup(&commit, repo, headId) != GIT_OK) {
        git_reference_free(head);
        return QString();
    }

    git_tree* tree = nullptr;
    if (git_commit_tree(&tree, commit) != GIT_OK) {
        git_commit_free(commit);
        git_reference_free(head);
        return QString();
    }

    const git_oid* treeId = git_tree_id(tree);
    const char* oidStr = treeId ? git_oid_tostr_s(treeId) : nullptr;
    const QString result = oidStr ? QString::fromLatin1(oidStr) : QString();

    git_tree_free(tree);
    git_commit_free(commit);
    git_reference_free(head);
    return result;
}

struct GitStatusEntryInfo
{
    unsigned int status = 0;
    QString path;
};

QList<GitStatusEntryInfo> statusEntries(git_repository* repo)
{
    QList<GitStatusEntryInfo> entries;
    if (repo == nullptr) {
        return entries;
    }

    git_status_list* list = nullptr;
    git_status_options options = GIT_STATUS_OPTIONS_INIT;
    options.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
    options.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS;

    if (git_status_list_new(&list, repo, &options) != GIT_OK || list == nullptr) {
        return entries;
    }

    const size_t count = git_status_list_entrycount(list);
    entries.reserve(static_cast<qsizetype>(count));
    for (size_t i = 0; i < count; ++i) {
        const git_status_entry* entry = git_status_byindex(list, i);
        if (entry == nullptr) {
            continue;
        }

        QString path;
        if (entry->index_to_workdir != nullptr && entry->index_to_workdir->new_file.path != nullptr) {
            path = QString::fromUtf8(entry->index_to_workdir->new_file.path);
        } else if (entry->head_to_index != nullptr && entry->head_to_index->new_file.path != nullptr) {
            path = QString::fromUtf8(entry->head_to_index->new_file.path);
        }

        entries.append({static_cast<unsigned int>(entry->status), path});
    }

    git_status_list_free(list);
    return entries;
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

    quint16 port() const
    {
        return mServer.serverPort();
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

class LocalGitAdvertiseAuthServer
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

    QString remoteUrlWithCredentials(const QString& user, const QString& password) const
    {
        QUrl url(remoteUrl());
        url.setUserName(user);
        url.setPassword(password);
        return url.toString();
    }

    void setCredentials(const QString& user, const QString& password)
    {
        mRequiredAuthHeader = makeBasicAuthHeader(user, password);
    }

    int advertiseRequestCount() const
    {
        return mAdvertiseRequestCount;
    }

    int authorizedAdvertiseRequestCount() const
    {
        return mAuthorizedAdvertiseRequestCount;
    }

    int unauthorizedAdvertiseRequestCount() const
    {
        return mUnauthorizedAdvertiseRequestCount;
    }

private:
    static QByteArray makeBasicAuthHeader(const QString& user, const QString& password)
    {
        if (user.isEmpty() || password.isEmpty()) {
            return QByteArray();
        }
        const QByteArray credentials = (user + ":" + password).toUtf8().toBase64();
        return QByteArray("Basic ") + credentials;
    }

    static QByteArray pktLine(const QByteArray& payload)
    {
        const int len = payload.size() + 4;
        return QByteArray::number(len, 16).rightJustified(4, '0') + payload;
    }

    static QByteArray advertiseBody(const QByteArray& oidHex)
    {
        QByteArray firstRef = oidHex + QByteArray(" refs/heads/remote-only");
        firstRef.append('\0');
        firstRef += QByteArray("report-status delete-refs ofs-delta\n");
        return pktLine(QByteArray("# service=git-receive-pack\n"))
               + QByteArray("0000")
               + pktLine(firstRef)
               + QByteArray("0000");
    }

    static void respond(QTcpSocket* socket,
                        int status,
                        const QByteArray& statusText,
                        const QByteArray& contentType,
                        const QByteArray& body,
                        const QByteArray& extraHeaders = QByteArray())
    {
        QByteArray response =
            "HTTP/1.1 " + QByteArray::number(status) + " " + statusText + "\r\n"
            "Content-Type: " + contentType + "\r\n"
            "Connection: close\r\n"
            "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
        if (!extraHeaders.isEmpty()) {
            response += extraHeaders;
            if (!extraHeaders.endsWith("\r\n")) {
                response += "\r\n";
            }
        }
        response += "\r\n";
        response += body;
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

                const QList<QByteArray> lines = request.split('\n');
                const QByteArray firstLine = lines.value(0).trimmed();
                const QByteArray method = firstLine.split(' ').value(0).trimmed();
                const QByteArray path = firstLine.split(' ').value(1).trimmed();

                if (method == "GET" && path.startsWith("/test.git/info/refs?service=git-receive-pack")) {
                    mAdvertiseRequestCount++;

                    QByteArray authHeaderValue;
                    for (const QByteArray& rawLine : lines) {
                        const QByteArray line = rawLine.trimmed();
                        if (line.isEmpty()) {
                            break;
                        }
                        const int colonIndex = line.indexOf(':');
                        if (colonIndex <= 0) {
                            continue;
                        }
                        const QByteArray key = line.left(colonIndex).trimmed().toLower();
                        const QByteArray value = line.mid(colonIndex + 1).trimmed();
                        if (key == QByteArray("authorization")) {
                            authHeaderValue = value;
                            break;
                        }
                    }

                    if (mRequireInitialChallenge && !mIssuedChallenge) {
                        mIssuedChallenge = true;
                        mUnauthorizedAdvertiseRequestCount++;
                        respond(socket,
                                401,
                                QByteArray("Unauthorized"),
                                QByteArray("text/plain"),
                                QByteArray("auth required"),
                                QByteArray("WWW-Authenticate: Basic realm=\"qquickgit-test\"\r\n"));
                        return;
                    }

                    if (authHeaderValue == mRequiredAuthHeader) {
                        mAuthorizedAdvertiseRequestCount++;
                        respond(socket,
                                200,
                                QByteArray("OK"),
                                QByteArray("application/x-git-receive-pack-advertisement"),
                                advertiseBody(mAdvertisedOid));
                    } else {
                        mUnauthorizedAdvertiseRequestCount++;
                        respond(socket,
                                401,
                                QByteArray("Unauthorized"),
                                QByteArray("text/plain"),
                                QByteArray("auth required"),
                                QByteArray("WWW-Authenticate: Basic realm=\"qquickgit-test\"\r\n"));
                    }
                    return;
                }

                respond(socket,
                        404,
                        QByteArray("Not Found"),
                        QByteArray("text/plain"),
                        QByteArray("unsupported"));
            });
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
        }
    }

    QTcpServer mServer;
    QByteArray mRequiredAuthHeader = makeBasicAuthHeader(QStringLiteral("planner"), QStringLiteral("secret"));
    QByteArray mAdvertisedOid = QByteArray("1111111111111111111111111111111111111111");
    bool mRequireInitialChallenge = true;
    bool mIssuedChallenge = false;
    int mAdvertiseRequestCount = 0;
    int mAuthorizedAdvertiseRequestCount = 0;
    int mUnauthorizedAdvertiseRequestCount = 0;
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

bool findFirstLfsPointerInIndex(const QString& repoPath, LfsPointer* pointerOut, QString* relativePathOut)
{
    if (!pointerOut) {
        return false;
    }

    git_repository* repo = nullptr;
    if (git_repository_open(&repo, repoPath.toLocal8Bit().constData()) != GIT_OK || !repo) {
        return false;
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    git_index* index = nullptr;
    if (git_repository_index(&index, repo) != GIT_OK || !index) {
        return false;
    }
    std::unique_ptr<git_index, decltype(&git_index_free)> indexHolder(index, &git_index_free);

    const size_t entryCount = git_index_entrycount(index);
    for (size_t i = 0; i < entryCount; ++i) {
        const git_index_entry* entry = git_index_get_byindex(index, i);
        if (!entry || !entry->path) {
            continue;
        }

        git_blob* blob = nullptr;
        if (git_blob_lookup(&blob, repo, &entry->id) != GIT_OK || !blob) {
            continue;
        }
        std::unique_ptr<git_blob, decltype(&git_blob_free)> blobHolder(blob, &git_blob_free);

        const char* rawData = static_cast<const char*>(git_blob_rawcontent(blob));
        const size_t rawSize = git_blob_rawsize(blob);
        if (!rawData || rawSize == 0) {
            continue;
        }

        LfsPointer pointer;
        if (!LfsPointer::parse(QByteArray(rawData, static_cast<int>(rawSize)), &pointer)) {
            continue;
        }

        *pointerOut = pointer;
        if (relativePathOut) {
            *relativePathOut = QString::fromUtf8(entry->path);
        }
        return true;
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

QString lfsEndpointFromRepoUrl(const QString& repoUrl)
{
    QUrl url(repoUrl);
    if (!url.isValid() || url.scheme().isEmpty() || url.host().isEmpty()) {
        return QString();
    }

    QString path = url.path();
    if (path.endsWith(QStringLiteral("/"))) {
        path.chop(1);
    }
    if (path.endsWith(QStringLiteral("/info/lfs"), Qt::CaseInsensitive)) {
        url.setPath(path);
        return url.toString();
    }

    path += QStringLiteral("/info/lfs");
    url.setPath(path);
    return url.toString();
}

QString lfsAuthUsername()
{
    return envOrDefault("QQGIT_LFS_TEST_AUTH_USERNAME", QString());
}

QString lfsAuthToken()
{
    return envOrDefault("QQGIT_LFS_TEST_AUTH_TOKEN", QString());
}

QString sshLfsTestRemoteUrl()
{
    return envOrDefault("QQGIT_SSH_LFS_TEST_REMOTE_URL",
                        QStringLiteral("ssh://git@github.com/vpicaver/lfs-test.git"));
}

QStringList missingSshLfsDownloadEnvVars()
{
    QStringList missing;
    if (qgetenv("QQGIT_SSH_LFS_TEST_ENABLE") != QByteArray("1")) {
        missing << QStringLiteral("QQGIT_SSH_LFS_TEST_ENABLE=1");
    }
    if (sshLfsTestRemoteUrl().isEmpty()) {
        missing << QStringLiteral("QQGIT_SSH_LFS_TEST_REMOTE_URL (e.g. ssh://git@github.com/<owner>/<repo>.git)");
    }
    return missing;
}

QStringList missingSshLfsUploadEnvVars()
{
    return missingSshLfsDownloadEnvVars();
}

bool hasHeaderCaseInsensitive(const QMap<QByteArray, QByteArray>& headers, const QByteArray& key)
{
    for (auto it = headers.begin(); it != headers.end(); ++it) {
        if (it.key().compare(key, Qt::CaseInsensitive) == 0) {
            return true;
        }
    }
    return false;
}

QStringList missingUploadAuthEnvVars()
{
    return missingSshLfsUploadEnvVars();
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

bool setBareRemoteBranchToOrphanCommit(const QString& bareRepoPath,
                                       const QString& branchName,
                                       QString* commitOidOut = nullptr)
{
    git_repository* repo = nullptr;
    if (git_repository_open(&repo, bareRepoPath.toLocal8Bit().constData()) != GIT_OK || !repo) {
        return false;
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    git_signature* signature = nullptr;
    if (git_signature_now(&signature, "Remote Rewriter", "remote@test.invalid") != GIT_OK || !signature) {
        return false;
    }
    std::unique_ptr<git_signature, decltype(&git_signature_free)> signatureHolder(signature, &git_signature_free);

    static const QByteArray remoteBlobContents("remote rewritten tip\n");
    git_oid blobOid;
    if (git_blob_create_frombuffer(&blobOid,
                                   repo,
                                   remoteBlobContents.constData(),
                                   static_cast<size_t>(remoteBlobContents.size())) != GIT_OK) {
        return false;
    }

    git_treebuilder* treeBuilder = nullptr;
    if (git_treebuilder_new(&treeBuilder, repo, nullptr) != GIT_OK || !treeBuilder) {
        return false;
    }
    std::unique_ptr<git_treebuilder, decltype(&git_treebuilder_free)> treeBuilderHolder(treeBuilder,
                                                                                         &git_treebuilder_free);

    if (git_treebuilder_insert(nullptr, treeBuilder, "remote-tip.txt", &blobOid, GIT_FILEMODE_BLOB) != GIT_OK) {
        return false;
    }

    git_oid treeOid;
    if (git_treebuilder_write(&treeOid, treeBuilder) != GIT_OK) {
        return false;
    }

    git_tree* tree = nullptr;
    if (git_tree_lookup(&tree, repo, &treeOid) != GIT_OK || !tree) {
        return false;
    }
    std::unique_ptr<git_tree, decltype(&git_tree_free)> treeHolder(tree, &git_tree_free);

    const QByteArray refName = QByteArray("refs/heads/") + branchName.toUtf8();
    git_oid commitOid;
    if (git_commit_create_v(&commitOid,
                            repo,
                            refName.constData(),
                            signature,
                            signature,
                            nullptr,
                            "Remote tip rewritten out-of-band",
                            tree,
                            0) != GIT_OK) {
        return false;
    }

    if (commitOidOut) {
        *commitOidOut = QString::fromLatin1(git_oid_tostr_s(&commitOid));
    }
    return true;
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

TEST_CASE("LfsPointer parse accepts nullptr out-pointer", "[LFS]") {
    LfsPointer pointer;
    pointer.oid = QStringLiteral("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    pointer.size = 42;
    const QByteArray validPointer = pointer.toPointerText();
    REQUIRE(!validPointer.isEmpty());

    CHECK(LfsPointer::parse(validPointer, nullptr));
    CHECK_FALSE(LfsPointer::parse(QByteArray("not a pointer"), nullptr));
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

TEST_CASE("Lfs filter clean is idempotent for existing LFS pointer", "[LFS]") {
    // Applying the clean filter to a file that already contains an LFS pointer
    // (e.g. an unhydrated clone) must emit the same pointer unchanged. Without
    // this the pointer would be double-encoded as a new LFS object with a
    // different OID, breaking subsequent sync/download.
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

    // Stage a binary payload through the clean filter to obtain its canonical LFS pointer.
    const QByteArray binaryPayload("lfs-binary-\x01\x02\x03", 14);
    git_filter_list* cleanFilters = nullptr;
    REQUIRE(git_filter_list_load(&cleanFilters, repo, nullptr, "test.png", GIT_FILTER_TO_ODB, GIT_FILTER_DEFAULT) == GIT_OK);

    git_buf firstCleanOut = GIT_BUF_INIT;
    REQUIRE(git_filter_list_apply_to_buffer(&firstCleanOut, cleanFilters, binaryPayload.constData(), static_cast<size_t>(binaryPayload.size())) == GIT_OK);
    const QByteArray firstPointerText(firstCleanOut.ptr, static_cast<int>(firstCleanOut.size));

    LfsPointer firstPointer;
    REQUIRE(LfsPointer::parse(firstPointerText, &firstPointer));

    git_buf_dispose(&firstCleanOut);
    git_filter_list_free(cleanFilters);

    // Now apply the clean filter again to the pointer text itself (simulating
    // re-staging an unhydrated working-tree file that contains pointer text).
    git_filter_list* cleanFilters2 = nullptr;
    REQUIRE(git_filter_list_load(&cleanFilters2, repo, nullptr, "test.png", GIT_FILTER_TO_ODB, GIT_FILTER_DEFAULT) == GIT_OK);

    git_buf secondCleanOut = GIT_BUF_INIT;
    REQUIRE(git_filter_list_apply_to_buffer(&secondCleanOut, cleanFilters2, firstPointerText.constData(), static_cast<size_t>(firstPointerText.size())) == GIT_OK);
    const QByteArray secondPointerText(secondCleanOut.ptr, static_cast<int>(secondCleanOut.size));

    LfsPointer secondPointer;
    REQUIRE(LfsPointer::parse(secondPointerText, &secondPointer));

    // The OID and size must be identical — the clean filter must be idempotent.
    CHECK(secondPointer.oid == firstPointer.oid);
    CHECK(secondPointer.size == firstPointer.size);

    git_buf_dispose(&secondCleanOut);
    git_filter_list_free(cleanFilters2);
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
#ifdef Q_OS_WIN
    SKIP("NTFS does not support Unix executable permission bits");
#endif
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

    // Expected behavior: no-remote fetch errors should fall back to pointer text.
    // Offline errors are hard failures and do not fall back.
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

TEST_CASE("Lfs hydration skips pointer blobs missing from working tree", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QString repoPath = QDir(tempDir.path()).filePath(QStringLiteral("strict-hydration-repo"));
    GitRepository repository;
    repository.setDirectory(QDir(repoPath));
    repository.initRepository();

    const QString bareRemotePath = QDir(tempDir.path()).filePath(QStringLiteral("strict-hydration-remote.git"));
    TestUtilities::initBareRepo(bareRemotePath);

    REQUIRE(configureRemoteUrl(repoPath,
                               QStringLiteral("origin"),
                               QUrl::fromLocalFile(bareRemotePath).toString()));

    const QByteArray payload("strict-hydration-payload");
    const QString payloadOid =
        QString::fromLatin1(QCryptographicHash::hash(payload, QCryptographicHash::Sha256).toHex());
    LfsPointer pointer;
    pointer.oid = payloadOid;
    pointer.size = payload.size();

    git_repository* rawRepo = nullptr;
    REQUIRE(git_repository_open(&rawRepo, repoPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(rawRepo != nullptr);

    const QByteArray pointerText = pointer.toPointerText();
    REQUIRE(!pointerText.isEmpty());

    git_oid pointerBlobOid;
    REQUIRE(git_blob_create_frombuffer(&pointerBlobOid,
                                       rawRepo,
                                       pointerText.constData(),
                                       static_cast<size_t>(pointerText.size())) == GIT_OK);

    git_index* index = nullptr;
    REQUIRE(git_repository_index(&index, rawRepo) == GIT_OK);
    REQUIRE(index != nullptr);

    git_index_entry entry{};
    entry.mode = GIT_FILEMODE_BLOB;
    entry.id = pointerBlobOid;
    const QByteArray stagedOnlyPath("staged-only.bin");
    entry.path = stagedOnlyPath.constData();

    REQUIRE(git_index_add(index, &entry) == GIT_OK);
    REQUIRE(git_index_write(index) == GIT_OK);

    git_index_free(index);
    git_repository_free(rawRepo);

    CHECK(!QFileInfo::exists(QDir(repoPath).filePath(QString::fromUtf8(stagedOnlyPath))));

    auto fetchFuture = repository.fetch(QStringLiteral("origin"));
    QStringList progressTexts;
    AsyncFuture::observe(fetchFuture).onProgress([&progressTexts, fetchFuture]() mutable {
        const ProgressState state = ProgressState::fromJson(fetchFuture.progressText());
        progressTexts.append(state.text());
    });

    REQUIRE(AsyncFuture::waitForFinished(fetchFuture, 60 * 1000));
    INFO("Fetch error:" << fetchFuture.result().errorMessage().toStdString());
    REQUIRE(!fetchFuture.result().hasError());
    INFO("Observed progress texts:" << progressTexts.join(QStringLiteral(" | ")).toStdString());

    bool sawLfsHydrationProgress = false;
    for (const QString& text : std::as_const(progressTexts)) {
        if (text.contains(QStringLiteral("Downloading LFS"))
            || text.contains(QStringLiteral("Hydrating LFS files"))) {
            sawLfsHydrationProgress = true;
            break;
        }
    }
    CHECK(!sawLfsHydrationProgress);
}

TEST_CASE("Lfs fetch restores missing object for hydrated tracked file", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LfsServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-fetch-hydrated"));
    const QString consumerPath = QDir(tempDir.path()).filePath(QStringLiteral("consumer-fetch-hydrated"));
    const QString trackedFileName = QStringLiteral("fetch-hydrated.png");

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray initialBytes = createPngFile(authorFilePath, Qt::darkCyan);
    REQUIRE(!initialBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add LFS file"), QStringLiteral("LFS fetch hydrated baseline")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QByteArray authorBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!authorBlob.isEmpty());
    LfsPointer expectedPointer;
    REQUIRE(LfsPointer::parse(authorBlob, &expectedPointer));
    REQUIRE(expectedPointer.size == initialBytes.size());

    GitRepository consumer;
    consumer.setDirectory(QDir(consumerPath));
    auto cloneFuture = consumer.clone(QUrl::fromLocalFile(authorPath));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Consumer clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    const QString consumerGitDirPath = gitDirPathFromWorkTree(consumerPath);
    REQUIRE(!consumerGitDirPath.isEmpty());
    REQUIRE(setGitConfigString(consumerPath, "lfs.url", lfsServer.endpoint()));
    LfsStore consumerStore(consumerGitDirPath);
    auto seedResult = consumerStore.storeBytes(initialBytes);
    INFO("Seed error:" << seedResult.errorMessage().toStdString());
    REQUIRE(!seedResult.hasError());
    requireGitFutureSuccess(consumer.reset(QStringLiteral("HEAD"), GitRepository::ResetMode::Hard));

    const QString consumerFilePath = QDir(consumerPath).filePath(trackedFileName);
    REQUIRE(QFileInfo::exists(consumerFilePath));
    CHECK(readFileBytes(consumerFilePath) == initialBytes);

    lfsServer.setDownloadObject(expectedPointer.oid, initialBytes);

    const QString objectPath = LfsStore::objectPath(consumerGitDirPath, expectedPointer.oid);
    REQUIRE(!objectPath.isEmpty());
    REQUIRE(QFileInfo::exists(objectPath));
    REQUIRE(QFile::remove(objectPath));
    CHECK_FALSE(QFileInfo::exists(objectPath));

    auto fetchFuture = consumer.fetch();
    QStringList progressTexts;
    AsyncFuture::observe(fetchFuture).onProgress([&progressTexts, fetchFuture]() mutable {
        const ProgressState state = ProgressState::fromJson(fetchFuture.progressText());
        progressTexts.append(state.text());
    });

    REQUIRE(AsyncFuture::waitForFinished(fetchFuture, 60 * 1000));
    INFO("Fetch error:" << fetchFuture.result().errorMessage().toStdString()
         << "code:" << fetchFuture.result().errorCode());
    REQUIRE(!fetchFuture.result().hasError());
    REQUIRE(QFileInfo::exists(objectPath));
    CHECK(readFileBytes(consumerFilePath) == initialBytes);

    bool sawLfsProgress = false;
    for (const QString& text : std::as_const(progressTexts)) {
        if (text.contains(QStringLiteral("Downloading LFS"))
            || text.contains(QStringLiteral("Hydrating LFS files"))) {
            sawLfsProgress = true;
            break;
        }
    }
    INFO("Observed progress texts:" << progressTexts.join(QStringLiteral(" | ")).toStdString());
    CHECK(sawLfsProgress);
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

TEST_CASE("Lfs batch authenticates with remote.lfsurl when git remote is ssh", "[LFS][regression][P1]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LocalLfsAuthHeaderServer server;
    REQUIRE(server.start());

    GitRepository repository;
    repository.setDirectory(QDir(tempDir.path()));
    repository.initRepository();

    const QString sshRemoteUrl =
        QStringLiteral("ssh://git@127.0.0.1:%1/test.git").arg(server.port());
    REQUIRE(configureRemoteUrl(tempDir.path(), QStringLiteral("origin"), sshRemoteUrl));

    const QString lfsEndpoint = server.remoteUrl() + QStringLiteral("/info/lfs");
    REQUIRE(setGitConfigString(tempDir.path(),
                               "remote.origin.lfsurl",
                               lfsEndpoint));

    const QString extraHeaderKey = QStringLiteral("http.%1/.extraheader").arg(lfsEndpoint);
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

TEST_CASE("LfsStore canonicalizes git dir path for registry lookups", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), 0) == GIT_OK);
    REQUIRE(repo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    const QString realGitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    REQUIRE(!realGitDirPath.isEmpty());
    const QString canonicalGitDirPath = QFileInfo(realGitDirPath).canonicalFilePath();
    REQUIRE(!canonicalGitDirPath.isEmpty());

    const QString symlinkGitDirPath = QDir(tempDir.path()).filePath(QStringLiteral("gitdir-link"));
    if (!QFile::link(realGitDirPath, symlinkGitDirPath)
        || !QFileInfo(symlinkGitDirPath).isSymLink()) {
        SKIP("Could not create git directory symlink for canonical-path test");
    }
    REQUIRE(QFileInfo(symlinkGitDirPath).canonicalFilePath() == canonicalGitDirPath);

    auto store = std::make_shared<LfsStore>(symlinkGitDirPath);
    REQUIRE(store);
    CHECK(store->gitDirPath() == QDir(canonicalGitDirPath).absolutePath());

    LfsStoreRegistry::registerStore(store);
    REQUIRE(LfsStoreRegistry::storeFor(realGitDirPath) == store);
    REQUIRE(LfsStoreRegistry::storeFor(canonicalGitDirPath) == store);
    REQUIRE(LfsStoreRegistry::storeFor(symlinkGitDirPath) == store);

    LfsStoreRegistry::unregisterStore(realGitDirPath, store);
    CHECK(LfsStoreRegistry::storeFor(realGitDirPath) == nullptr);
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

    LfsServer server;
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

    server.setDownloadObject(expectedPointer.oid, actualBytes);
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

    LfsServer lfsServer;
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
    lfsServer.setDownloadObject(expectedPointer.oid, updatedBytes);

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

    CHECK(lfsServer.downloadBatchRequestCount() > 0);
    CHECK(lfsServer.downloadObjectRequestCount() > 0);
}

TEST_CASE("Lfs pull delete ignores hydrated file modifications", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LfsServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-reset-dirty"));
    const QString consumerPath = QDir(tempDir.path()).filePath(QStringLiteral("consumer-reset-dirty"));
    const QString remotePath = QDir(tempDir.path()).filePath(QStringLiteral("remote-reset-dirty.git"));
    const QString trackedFileName = QStringLiteral("reset-dirty.png");

    TestUtilities::initBareRepo(remotePath);

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
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add LFS file"), QStringLiteral("LFS reset dirty baseline")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QString baselineCommit = headOidString(authorRepo);
    REQUIRE(!baselineCommit.isEmpty());
    const QByteArray baselineBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!baselineBlob.isEmpty());
    LfsPointer baselinePointer;
    REQUIRE(LfsPointer::parse(baselineBlob, &baselinePointer));
    lfsServer.setExpectedUploadObject(baselinePointer.oid, baselinePointer.size);

    REQUIRE(configureRemoteUrl(authorPath, QStringLiteral("origin"), QUrl::fromLocalFile(remotePath).toString()));
    REQUIRE(setGitConfigString(authorPath, "lfs.url", lfsServer.endpoint()));
    auto baselinePushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(baselinePushFuture, 60 * 1000));
    INFO("Baseline push error:" << baselinePushFuture.result().errorMessage().toStdString()
         << "code:" << baselinePushFuture.result().errorCode());
    REQUIRE(!baselinePushFuture.result().hasError());

    GitRepository consumer;
    consumer.setDirectory(QDir(consumerPath));
    consumer.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    consumer.setAccount(&account);
    auto cloneFuture = consumer.clone(QUrl::fromLocalFile(remotePath));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Consumer clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    const QString consumerGitDirPath = gitDirPathFromWorkTree(consumerPath);
    REQUIRE(!consumerGitDirPath.isEmpty());
    REQUIRE(setGitConfigString(consumerPath, "lfs.url", lfsServer.endpoint()));
    LfsStore consumerStore(consumerGitDirPath);
    auto seedBaselineResult = consumerStore.storeBytes(initialBytes);
    INFO("Seed baseline error:" << seedBaselineResult.errorMessage().toStdString());
    REQUIRE(!seedBaselineResult.hasError());

    REQUIRE(QFile::remove(authorFilePath));
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Delete LFS file"), QStringLiteral("LFS reset dirty delete")));
    auto deletePushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(deletePushFuture, 60 * 1000));
    INFO("Delete push error:" << deletePushFuture.result().errorMessage().toStdString()
         << "code:" << deletePushFuture.result().errorCode());
    REQUIRE(!deletePushFuture.result().hasError());

    auto pullFuture = consumer.pull();
    REQUIRE(AsyncFuture::waitForFinished(pullFuture, 60 * 1000));
    INFO("Pull error:" << pullFuture.result().errorMessage().toStdString()
         << "code:" << pullFuture.result().errorCode());
    REQUIRE(!pullFuture.result().hasError());
    CHECK(pullFuture.result().value().state() == GitRepository::MergeResult::FastForward);

    const QString consumerFilePath = QDir(consumerPath).filePath(trackedFileName);
    CHECK_FALSE(QFileInfo::exists(consumerFilePath));

    consumer.checkStatus();
    CHECK(consumer.modifiedFileCount() == 0);

    git_repository* consumerRepo = nullptr;
    REQUIRE(git_repository_open(&consumerRepo, consumerPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(consumerRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> consumerRepoHolder(consumerRepo, &git_repository_free);

    const QList<GitStatusEntryInfo> entries = statusEntries(consumerRepo);
    CHECK(entries.isEmpty());
}

TEST_CASE("Lfs hydrated file state does not create spurious commit", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LfsServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-empty-commit"));
    const QString consumerPath = QDir(tempDir.path()).filePath(QStringLiteral("consumer-empty-commit"));
    const QString remotePath = QDir(tempDir.path()).filePath(QStringLiteral("remote-empty-commit.git"));
    const QString trackedFileName = QStringLiteral("empty-commit.png");

    TestUtilities::initBareRepo(remotePath);

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray initialBytes = createPngFile(authorFilePath, Qt::blue);
    REQUIRE(!initialBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add LFS file"), QStringLiteral("LFS empty commit baseline")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QString baselineCommit = headOidString(authorRepo);
    REQUIRE(!baselineCommit.isEmpty());
    const QByteArray baselineBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!baselineBlob.isEmpty());
    LfsPointer baselinePointer;
    REQUIRE(LfsPointer::parse(baselineBlob, &baselinePointer));
    lfsServer.setExpectedUploadObject(baselinePointer.oid, baselinePointer.size);

    REQUIRE(configureRemoteUrl(authorPath, QStringLiteral("origin"), QUrl::fromLocalFile(remotePath).toString()));
    REQUIRE(setGitConfigString(authorPath, "lfs.url", lfsServer.endpoint()));
    auto baselinePushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(baselinePushFuture, 60 * 1000));
    INFO("Baseline push error:" << baselinePushFuture.result().errorMessage().toStdString()
         << "code:" << baselinePushFuture.result().errorCode());
    REQUIRE(!baselinePushFuture.result().hasError());

    GitRepository consumer;
    consumer.setDirectory(QDir(consumerPath));
    consumer.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    consumer.setAccount(&account);
    auto cloneFuture = consumer.clone(QUrl::fromLocalFile(remotePath));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Consumer clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    const QString consumerGitDirPath = gitDirPathFromWorkTree(consumerPath);
    REQUIRE(!consumerGitDirPath.isEmpty());
    REQUIRE(setGitConfigString(consumerPath, "lfs.url", lfsServer.endpoint()));
    LfsStore consumerStore(consumerGitDirPath);
    auto seedBaselineResult = consumerStore.storeBytes(initialBytes);
    INFO("Seed baseline error:" << seedBaselineResult.errorMessage().toStdString());
    REQUIRE(!seedBaselineResult.hasError());

    REQUIRE(QFile::remove(authorFilePath));
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Delete LFS file"), QStringLiteral("LFS empty commit delete")));
    auto deletePushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(deletePushFuture, 60 * 1000));
    INFO("Delete push error:" << deletePushFuture.result().errorMessage().toStdString()
         << "code:" << deletePushFuture.result().errorCode());
    REQUIRE(!deletePushFuture.result().hasError());

    auto pullFuture = consumer.pull();
    REQUIRE(AsyncFuture::waitForFinished(pullFuture, 60 * 1000));
    INFO("Pull error:" << pullFuture.result().errorMessage().toStdString()
         << "code:" << pullFuture.result().errorCode());
    REQUIRE(!pullFuture.result().hasError());
    CHECK(pullFuture.result().value().state() == GitRepository::MergeResult::FastForward);

    consumer.checkStatus();
    REQUIRE(consumer.modifiedFileCount() == 0);

    git_repository* consumerRepo = nullptr;
    REQUIRE(git_repository_open(&consumerRepo, consumerPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(consumerRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> consumerRepoHolder(consumerRepo, &git_repository_free);

    const QString headBeforeCommit = headOidString(consumerRepo);
    const QString treeBeforeCommit = headTreeOidString(consumerRepo);
    REQUIRE(!treeBeforeCommit.isEmpty());

    REQUIRE_NOTHROW(consumer.commitAll(QStringLiteral("Empty local sync commit"),
                                       QStringLiteral("Should be a no-op when nothing really changed")));

    const QString headAfterCommit = headOidString(consumerRepo);
    const QString treeAfterCommit = headTreeOidString(consumerRepo);

    CHECK(headAfterCommit == headBeforeCommit);
    CHECK(treeAfterCommit == treeBeforeCommit);
    consumer.checkStatus();
    CHECK(consumer.modifiedFileCount() == 0);
}

TEST_CASE("Lfs real hydrated file edit remains dirty and commitable", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LfsServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-real-edit"));
    const QString consumerPath = QDir(tempDir.path()).filePath(QStringLiteral("consumer-real-edit"));
    const QString remotePath = QDir(tempDir.path()).filePath(QStringLiteral("remote-real-edit.git"));
    const QString trackedFileName = QStringLiteral("real-edit.png");

    TestUtilities::initBareRepo(remotePath);

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray initialBytes = createPngFile(authorFilePath, Qt::blue);
    REQUIRE(!initialBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add LFS file"), QStringLiteral("LFS real edit baseline")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QByteArray baselineBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!baselineBlob.isEmpty());
    LfsPointer baselinePointer;
    REQUIRE(LfsPointer::parse(baselineBlob, &baselinePointer));
    lfsServer.setExpectedUploadObject(baselinePointer.oid, baselinePointer.size);

    REQUIRE(configureRemoteUrl(authorPath, QStringLiteral("origin"), QUrl::fromLocalFile(remotePath).toString()));
    REQUIRE(setGitConfigString(authorPath, "lfs.url", lfsServer.endpoint()));
    auto baselinePushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(baselinePushFuture, 60 * 1000));
    INFO("Baseline push error:" << baselinePushFuture.result().errorMessage().toStdString()
         << "code:" << baselinePushFuture.result().errorCode());
    REQUIRE(!baselinePushFuture.result().hasError());

    GitRepository consumer;
    consumer.setDirectory(QDir(consumerPath));
    consumer.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    consumer.setAccount(&account);
    auto cloneFuture = consumer.clone(QUrl::fromLocalFile(remotePath));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Consumer clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    const QString consumerGitDirPath = gitDirPathFromWorkTree(consumerPath);
    REQUIRE(!consumerGitDirPath.isEmpty());
    REQUIRE(setGitConfigString(consumerPath, "lfs.url", lfsServer.endpoint()));
    LfsStore consumerStore(consumerGitDirPath);
    auto seedBaselineResult = consumerStore.storeBytes(initialBytes);
    INFO("Seed baseline error:" << seedBaselineResult.errorMessage().toStdString());
    REQUIRE(!seedBaselineResult.hasError());
    requireGitFutureSuccess(consumer.reset(QStringLiteral("HEAD"), GitRepository::ResetMode::Hard));

    const QString consumerFilePath = QDir(consumerPath).filePath(trackedFileName);
    const QByteArray hydratedBytes = readFileBytes(consumerFilePath);
    REQUIRE(hydratedBytes == initialBytes);

    const QByteArray editedBytes = createPngFile(consumerFilePath, Qt::red);
    REQUIRE(!editedBytes.isEmpty());
    REQUIRE(editedBytes != hydratedBytes);

    consumer.checkStatus();
    REQUIRE(consumer.modifiedFileCount() == 1);

    git_repository* consumerRepo = nullptr;
    REQUIRE(git_repository_open(&consumerRepo, consumerPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(consumerRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> consumerRepoHolder(consumerRepo, &git_repository_free);

    const QList<GitStatusEntryInfo> entriesBeforeCommit = statusEntries(consumerRepo);
    REQUIRE(entriesBeforeCommit.size() == 1);
    CHECK(entriesBeforeCommit.first().path == trackedFileName);
    CHECK((entriesBeforeCommit.first().status & GIT_STATUS_WT_MODIFIED) != 0);

    const QString headBeforeCommit = headOidString(consumerRepo);
    REQUIRE(!headBeforeCommit.isEmpty());

    REQUIRE_NOTHROW(consumer.commitAll(QStringLiteral("Update hydrated LFS file"),
                                       QStringLiteral("A real worktree edit should commit")));

    const QString headAfterCommit = headOidString(consumerRepo);
    CHECK(headAfterCommit != headBeforeCommit);

    const QByteArray committedBlob = readBlobFromHead(consumerRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!committedBlob.isEmpty());
    LfsPointer editedPointer;
    REQUIRE(LfsPointer::parse(committedBlob, &editedPointer));
    CHECK(editedPointer.oid != baselinePointer.oid);
    CHECK(editedPointer.size == editedBytes.size());

    consumer.checkStatus();
    CHECK(consumer.modifiedFileCount() == 0);
    CHECK(readFileBytes(consumerFilePath) == editedBytes);
}

TEST_CASE("Lfs push uploads tracked objects before git push", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LfsServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-push"));
    const QString remotePath = QDir(tempDir.path()).filePath(QStringLiteral("remote-push.git"));
    const QString trackedFileName = QStringLiteral("push-upload.png");

    TestUtilities::initBareRepo(remotePath);

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

    lfsServer.setExpectedUploadObject(pointer.oid, pointer.size);

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

TEST_CASE("Lfs push of new branch excludes remote-reachable LFS ancestors", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LfsServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-push-new-branch"));
    const QString remotePath = QDir(tempDir.path()).filePath(QStringLiteral("remote-push-new-branch.git"));
    const QString trackedFileName = QStringLiteral("baseline-lfs.png");

    TestUtilities::initBareRepo(remotePath);

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray baselineBytes = createPngFile(authorFilePath, Qt::blue);
    REQUIRE(!baselineBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add baseline LFS file"), QStringLiteral("LFS baseline")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QByteArray baselineBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!baselineBlob.isEmpty());
    LfsPointer baselinePointer;
    REQUIRE(LfsPointer::parse(baselineBlob, &baselinePointer));
    REQUIRE(baselinePointer.size == baselineBytes.size());

    lfsServer.setExpectedUploadObject(baselinePointer.oid, baselinePointer.size);

    REQUIRE(configureRemoteUrl(authorPath, QStringLiteral("origin"), QUrl::fromLocalFile(remotePath).toString()));
    REQUIRE(setGitConfigString(authorPath, "lfs.url", lfsServer.endpoint()));

    auto baselinePushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(baselinePushFuture, 60 * 1000));
    INFO("Baseline push error:" << baselinePushFuture.result().errorMessage().toStdString()
         << "code:" << baselinePushFuture.result().errorCode());
    REQUIRE(!baselinePushFuture.result().hasError());
    const int uploadBatchRequestsAfterBaseline = lfsServer.uploadBatchRequestCount();
    const int uploadRequestsAfterBaseline = lfsServer.uploadRequestCount();

    const QString gitDirPath = gitDirPathFromWorkTree(authorPath);
    REQUIRE(!gitDirPath.isEmpty());
    const QString prunedObjectPath = LfsStore::objectPath(gitDirPath, baselinePointer.oid);
    REQUIRE(!prunedObjectPath.isEmpty());
    REQUIRE(QFileInfo::exists(prunedObjectPath));
    REQUIRE(QFile::remove(prunedObjectPath));

    const QString topicBranch = QStringLiteral("topic-without-tracking");
    REQUIRE_NOTHROW(author.createBranch(topicBranch));

    const QString textPath = QDir(authorPath).filePath(QStringLiteral("topic-note.txt"));
    REQUIRE(writeTextFile(textPath, QByteArray("branch-only change\n")));
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Topic change"), QStringLiteral("No new LFS pointers")));

    git_reference* topicTracking = nullptr;
    const int trackingLookup = git_reference_lookup(&topicTracking,
                                                    authorRepo,
                                                    QStringLiteral("refs/remotes/origin/%1").arg(topicBranch).toUtf8().constData());
    CHECK(trackingLookup == GIT_ENOTFOUND);
    if (topicTracking) {
        git_reference_free(topicTracking);
    }

    auto topicPushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(topicPushFuture, 60 * 1000));
    INFO("Topic push error:" << topicPushFuture.result().errorMessage().toStdString()
         << "code:" << topicPushFuture.result().errorCode());
    REQUIRE(!topicPushFuture.result().hasError());
    CHECK(lfsServer.uploadBatchRequestCount() == uploadBatchRequestsAfterBaseline);
    CHECK(lfsServer.uploadRequestCount() == uploadRequestsAfterBaseline);

    git_repository* remoteRepoVerify = nullptr;
    REQUIRE(git_repository_open(&remoteRepoVerify, remotePath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(remoteRepoVerify != nullptr);
    git_reference* remoteTopicRef = nullptr;
    REQUIRE(git_reference_lookup(&remoteTopicRef,
                                 remoteRepoVerify,
                                 QStringLiteral("refs/heads/%1").arg(topicBranch).toUtf8().constData()) == GIT_OK);
    REQUIRE(remoteTopicRef != nullptr);
    git_reference_free(remoteTopicRef);
    git_repository_free(remoteRepoVerify);
}

TEST_CASE("Lfs push merge ignores LFS pointers only present in non-first-parent diff", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LfsServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-push-merge-parent-scan"));
    const QString remotePath = QDir(tempDir.path()).filePath(QStringLiteral("remote-push-merge-parent-scan.git"));
    const QString trackedFileName = QStringLiteral("merge-parent-lfs.png");

    TestUtilities::initBareRepo(remotePath);

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    REQUIRE(configureRemoteUrl(authorPath, QStringLiteral("origin"), QUrl::fromLocalFile(remotePath).toString()));
    REQUIRE(setGitConfigString(authorPath, "lfs.url", lfsServer.endpoint()));

    const QString baseFilePath = QDir(authorPath).filePath(QStringLiteral("base.txt"));
    REQUIRE(writeTextFile(baseFilePath, QByteArray("base commit\n")));
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Base"), QStringLiteral("Base commit")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QString baseOid = headOidString(authorRepo);
    REQUIRE_FALSE(baseOid.isEmpty());
    const QString baseBranch = author.headBranchName();
    REQUIRE_FALSE(baseBranch.isEmpty());

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray workingBytes = createPngFile(authorFilePath, Qt::darkGreen);
    REQUIRE(!workingBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add remote-tip LFS file"), QStringLiteral("LFS merge parent baseline")));

    const QByteArray baselineBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!baselineBlob.isEmpty());
    LfsPointer baselinePointer;
    REQUIRE(LfsPointer::parse(baselineBlob, &baselinePointer));
    REQUIRE(baselinePointer.size == workingBytes.size());

    lfsServer.setExpectedUploadObject(baselinePointer.oid, baselinePointer.size);

    auto baselinePushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(baselinePushFuture, 60 * 1000));
    INFO("Baseline push error:" << baselinePushFuture.result().errorMessage().toStdString()
         << "code:" << baselinePushFuture.result().errorCode());
    REQUIRE(!baselinePushFuture.result().hasError());
    const int uploadBatchRequestsAfterBaseline = lfsServer.uploadBatchRequestCount();
    const int uploadRequestsAfterBaseline = lfsServer.uploadRequestCount();

    const QString featureBranch = QStringLiteral("feature-non-lfs-parent");
    REQUIRE_NOTHROW(author.createBranch(featureBranch, baseOid));
    CHECK(author.headBranchName() == featureBranch);

    const QString featureFilePath = QDir(authorPath).filePath(QStringLiteral("feature.txt"));
    REQUIRE(writeTextFile(featureFilePath, QByteArray("feature branch commit\n")));
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Feature commit"), QStringLiteral("No LFS changes")));

    auto checkoutBaseFuture = author.checkout(QStringLiteral("refs/heads/%1").arg(baseBranch));
    REQUIRE(AsyncFuture::waitForFinished(checkoutBaseFuture, 60 * 1000));
    REQUIRE(!checkoutBaseFuture.result().hasError());
    CHECK(author.headBranchName() == baseBranch);

    const GitRepository::MergeResult mergeResult = author.merge({featureBranch});
    REQUIRE(mergeResult.state() == GitRepository::MergeResult::MergeCommitCreated);

    const QString gitDirPath = gitDirPathFromWorkTree(authorPath);
    REQUIRE(!gitDirPath.isEmpty());
    const QString prunedObjectPath = LfsStore::objectPath(gitDirPath, baselinePointer.oid);
    REQUIRE(!prunedObjectPath.isEmpty());
    REQUIRE(QFileInfo::exists(prunedObjectPath));
    REQUIRE(QFile::remove(prunedObjectPath));

    auto mergePushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(mergePushFuture, 60 * 1000));
    INFO("Merge push error:" << mergePushFuture.result().errorMessage().toStdString()
         << "code:" << mergePushFuture.result().errorCode());
    REQUIRE(!mergePushFuture.result().hasError());

    // Regression guard: merge push should not require uploading remote-tip LFS objects.
    CHECK(lfsServer.uploadBatchRequestCount() == uploadBatchRequestsAfterBaseline);
    CHECK(lfsServer.uploadRequestCount() == uploadRequestsAfterBaseline);
}

TEST_CASE("Lfs push does not trust stale remote-tracking refs over actual remote reachability", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LfsServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-push-stale-tracking"));
    const QString remotePath = QDir(tempDir.path()).filePath(QStringLiteral("remote-push-stale-tracking.git"));
    const QString trackedFileName = QStringLiteral("stale-tracking-lfs.png");

    TestUtilities::initBareRepo(remotePath);

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    REQUIRE(configureRemoteUrl(authorPath, QStringLiteral("origin"), QUrl::fromLocalFile(remotePath).toString()));
    REQUIRE(setGitConfigString(authorPath, "lfs.url", lfsServer.endpoint()));

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray baselineBytes = createPngFile(authorFilePath, Qt::red);
    REQUIRE(!baselineBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add baseline LFS file"), QStringLiteral("LFS baseline")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QByteArray baselineBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!baselineBlob.isEmpty());
    LfsPointer baselinePointer;
    REQUIRE(LfsPointer::parse(baselineBlob, &baselinePointer));
    REQUIRE(baselinePointer.size == baselineBytes.size());

    lfsServer.setExpectedUploadObject(baselinePointer.oid, baselinePointer.size);
    auto baselinePushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(baselinePushFuture, 60 * 1000));
    INFO("Baseline push error:" << baselinePushFuture.result().errorMessage().toStdString()
         << "code:" << baselinePushFuture.result().errorCode());
    REQUIRE(!baselinePushFuture.result().hasError());

    const int uploadBatchRequestsAfterBaseline = lfsServer.uploadBatchRequestCount();
    const int uploadRequestsAfterBaseline = lfsServer.uploadRequestCount();

    const QByteArray updatedBytes = createPngFile(authorFilePath, Qt::green);
    REQUIRE(!updatedBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Update LFS file"), QStringLiteral("LFS update")));

    const QByteArray updatedBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!updatedBlob.isEmpty());
    LfsPointer updatedPointer;
    REQUIRE(LfsPointer::parse(updatedBlob, &updatedPointer));
    REQUIRE(updatedPointer.size == updatedBytes.size());
    REQUIRE(updatedPointer.oid != baselinePointer.oid);

    git_reference* staleTracking = nullptr;
    const QByteArray trackingName = QByteArray("refs/remotes/origin/") + author.headBranchName().toUtf8();
    git_reference* headRef = nullptr;
    REQUIRE(git_repository_head(&headRef, authorRepo) == GIT_OK);
    REQUIRE(headRef != nullptr);
    const git_oid* updatedCommitOid = git_reference_target(headRef);
    REQUIRE(updatedCommitOid != nullptr);
    REQUIRE(git_reference_create(&staleTracking,
                                 authorRepo,
                                 trackingName.constData(),
                                 updatedCommitOid,
                                 1,
                                 "regression: stale tracking tip") == GIT_OK);
    if (staleTracking) {
        git_reference_free(staleTracking);
    }
    git_reference_free(headRef);

    lfsServer.setExpectedUploadObject(updatedPointer.oid, updatedPointer.size);
    auto updatePushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(updatePushFuture, 60 * 1000));
    INFO("Update push error:" << updatePushFuture.result().errorMessage().toStdString()
         << "code:" << updatePushFuture.result().errorCode());
    REQUIRE(!updatePushFuture.result().hasError());

    // Regression guard: stale local tracking refs must not suppress required uploads.
    CHECK(lfsServer.uploadBatchRequestCount() > uploadBatchRequestsAfterBaseline);
    CHECK(lfsServer.uploadRequestCount() > uploadRequestsAfterBaseline);
}

TEST_CASE("Lfs push does not fall back to stale tracking refs when remote tips are advertised but unknown locally",
          "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LfsServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-push-advertised-tip-fallback"));
    const QString remotePath = QDir(tempDir.path()).filePath(QStringLiteral("remote-push-advertised-tip-fallback.git"));
    const QString trackedFileName = QStringLiteral("advertised-tip-fallback-lfs.png");
    const QString topicBranch = QStringLiteral("topic-advertised-tip-fallback");

    TestUtilities::initBareRepo(remotePath);

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    REQUIRE(configureRemoteUrl(authorPath, QStringLiteral("origin"), QUrl::fromLocalFile(remotePath).toString()));
    REQUIRE(setGitConfigString(authorPath, "lfs.url", lfsServer.endpoint()));

    const QString baseFilePath = QDir(authorPath).filePath(QStringLiteral("base.txt"));
    REQUIRE(writeTextFile(baseFilePath, QByteArray("base commit\n")));
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Base"), QStringLiteral("Base commit")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QString baseOid = headOidString(authorRepo);
    REQUIRE_FALSE(baseOid.isEmpty());

    REQUIRE_NOTHROW(author.createBranch(topicBranch, baseOid));
    CHECK(author.headBranchName() == topicBranch);

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray workingBytes = createPngFile(authorFilePath, Qt::cyan);
    REQUIRE(!workingBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Topic LFS file"), QStringLiteral("LFS advertised tip fallback")));

    const QByteArray pointerBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!pointerBlob.isEmpty());
    LfsPointer topicPointer;
    REQUIRE(LfsPointer::parse(pointerBlob, &topicPointer));
    REQUIRE(topicPointer.size == workingBytes.size());

    git_reference* headRef = nullptr;
    REQUIRE(git_repository_head(&headRef, authorRepo) == GIT_OK);
    REQUIRE(headRef != nullptr);
    const git_oid* topicCommitOid = git_reference_target(headRef);
    REQUIRE(topicCommitOid != nullptr);

    const QByteArray staleTrackingName = QByteArray("refs/remotes/origin/") + topicBranch.toUtf8();
    git_reference* staleTrackingRef = nullptr;
    REQUIRE(git_reference_create(&staleTrackingRef,
                                 authorRepo,
                                 staleTrackingName.constData(),
                                 topicCommitOid,
                                 1,
                                 "regression: stale topic tracking tip") == GIT_OK);
    if (staleTrackingRef) {
        git_reference_free(staleTrackingRef);
    }
    git_reference_free(headRef);

    // Create an advertised remote head the pusher does not have locally.
    REQUIRE(setBareRemoteBranchToOrphanCommit(remotePath, QStringLiteral("remote-only")));

    const int uploadBatchRequestsBeforePush = lfsServer.uploadBatchRequestCount();
    const int uploadRequestsBeforePush = lfsServer.uploadRequestCount();
    lfsServer.setExpectedUploadObject(topicPointer.oid, topicPointer.size);

    auto pushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(pushFuture, 60 * 1000));
    INFO("Push error:" << pushFuture.result().errorMessage().toStdString()
         << "code:" << pushFuture.result().errorCode());
    REQUIRE(!pushFuture.result().hasError());

    // Regression guard: successful remote ls with unknown advertised tips must not
    // permit stale local tracking refs to suppress required uploads.
    CHECK(lfsServer.uploadBatchRequestCount() > uploadBatchRequestsBeforePush);
    CHECK(lfsServer.uploadRequestCount() > uploadRequestsBeforePush);
}

TEST_CASE("Lfs push planning uses non-SSH auth to list advertised tips before stale-tracking fallback",
          "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LfsServer lfsServer;
    REQUIRE(lfsServer.start());

    LocalGitAdvertiseAuthServer gitServer;
    REQUIRE(gitServer.start());
    gitServer.setCredentials(QStringLiteral("planner"), QStringLiteral("secret"));

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-push-http-auth-planning"));
    const QString trackedFileName = QStringLiteral("http-auth-planning-lfs.png");
    const QString topicBranch = QStringLiteral("topic-http-auth-planning");

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    REQUIRE(configureRemoteUrl(authorPath,
                               QStringLiteral("origin"),
                               gitServer.remoteUrlWithCredentials(QStringLiteral("planner"), QStringLiteral("secret"))));
    REQUIRE(setGitConfigString(authorPath, "lfs.url", lfsServer.endpoint()));

    const QString baseFilePath = QDir(authorPath).filePath(QStringLiteral("base.txt"));
    REQUIRE(writeTextFile(baseFilePath, QByteArray("base commit\n")));
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Base"), QStringLiteral("Base commit")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QString baseOid = headOidString(authorRepo);
    REQUIRE_FALSE(baseOid.isEmpty());
    REQUIRE_NOTHROW(author.createBranch(topicBranch, baseOid));
    CHECK(author.headBranchName() == topicBranch);

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray workingBytes = createPngFile(authorFilePath, Qt::darkYellow);
    REQUIRE(!workingBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Topic LFS file"), QStringLiteral("LFS HTTP auth planning")));

    const QByteArray pointerBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!pointerBlob.isEmpty());
    LfsPointer topicPointer;
    REQUIRE(LfsPointer::parse(pointerBlob, &topicPointer));
    REQUIRE(topicPointer.size == workingBytes.size());

    git_reference* headRef = nullptr;
    REQUIRE(git_repository_head(&headRef, authorRepo) == GIT_OK);
    REQUIRE(headRef != nullptr);
    const git_oid* topicCommitOid = git_reference_target(headRef);
    REQUIRE(topicCommitOid != nullptr);

    // If advertised tips cannot be listed, stale tracking would hide this commit and suppress upload.
    const QByteArray staleTrackingName = QByteArray("refs/remotes/origin/") + topicBranch.toUtf8();
    git_reference* staleTrackingRef = nullptr;
    REQUIRE(git_reference_create(&staleTrackingRef,
                                 authorRepo,
                                 staleTrackingName.constData(),
                                 topicCommitOid,
                                 1,
                                 "regression: stale topic tracking tip for auth listing") == GIT_OK);
    if (staleTrackingRef) {
        git_reference_free(staleTrackingRef);
    }
    git_reference_free(headRef);

    const int uploadBatchRequestsBeforePush = lfsServer.uploadBatchRequestCount();
    const int uploadRequestsBeforePush = lfsServer.uploadRequestCount();
    lfsServer.setExpectedUploadObject(topicPointer.oid, topicPointer.size);

    auto pushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(pushFuture, 60 * 1000));
    INFO("Push error:" << pushFuture.result().errorMessage().toStdString()
         << "code:" << pushFuture.result().errorCode());
    REQUIRE(pushFuture.result().hasError());

    CHECK(gitServer.advertiseRequestCount() > 0);
    CHECK(gitServer.unauthorizedAdvertiseRequestCount() > 0);
    CHECK(gitServer.authorizedAdvertiseRequestCount() > 0);

    // Regression guard: authenticated remote tip listing must remain authoritative so
    // stale local tracking refs do not suppress required LFS uploads.
    CHECK(lfsServer.uploadBatchRequestCount() > uploadBatchRequestsBeforePush);
    CHECK(lfsServer.uploadRequestCount() > uploadRequestsBeforePush);
}

TEST_CASE("Lfs push does not fail with missing-local-object when remote tips are undiscoverable", "[LFS][regression][P1]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-push-remote-tip-failure"));
    const QString trackedFileName = QStringLiteral("remote-tip-failure-lfs.png");

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray baselineBytes = createPngFile(authorFilePath, Qt::blue);
    REQUIRE(!baselineBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add baseline LFS file"), QStringLiteral("LFS baseline")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QByteArray baselineBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!baselineBlob.isEmpty());
    LfsPointer baselinePointer;
    REQUIRE(LfsPointer::parse(baselineBlob, &baselinePointer));

    const QString gitDirPath = gitDirPathFromWorkTree(authorPath);
    REQUIRE(!gitDirPath.isEmpty());
    const QString prunedObjectPath = LfsStore::objectPath(gitDirPath, baselinePointer.oid);
    REQUIRE(!prunedObjectPath.isEmpty());
    REQUIRE(QFileInfo::exists(prunedObjectPath));
    REQUIRE(QFile::remove(prunedObjectPath));

    const QString textPath = QDir(authorPath).filePath(QStringLiteral("note.txt"));
    REQUIRE(writeTextFile(textPath, QByteArray("non-lfs change\n")));
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Non-LFS change"), QStringLiteral("No new LFS pointer")));

    REQUIRE(configureRemoteUrl(authorPath,
                               QStringLiteral("origin"),
                               QStringLiteral("ssh://127.0.0.1:1/nonexistent/repo.git")));

    auto pushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(pushFuture, 60 * 1000));
    REQUIRE(pushFuture.result().hasError());
    INFO("Push error:" << pushFuture.result().errorMessage().toStdString()
         << "code:" << pushFuture.result().errorCode());

    // Regression guard: remote discovery/connect failures must not degrade into
    // false missing-local-object errors from scanning unrelated history.
    CHECK_FALSE(pushFuture.result().errorMessage().contains(QStringLiteral("Missing local LFS object")));
}

TEST_CASE("Lfs push rejects wildcard refspecs with explicit error", "[LFS][regression][P2]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    LfsServer lfsServer;
    REQUIRE(lfsServer.start());

    const QString authorPath = QDir(tempDir.path()).filePath(QStringLiteral("author-push-wildcard-refspec"));
    const QString remotePath = QDir(tempDir.path()).filePath(QStringLiteral("remote-push-wildcard-refspec.git"));
    const QString trackedFileName = QStringLiteral("wildcard-lfs.png");

    TestUtilities::initBareRepo(remotePath);

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.setLfsPolicy(makeCustomPolicy(QStringLiteral("qquickgit-test")));
    author.initRepository();

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    author.setAccount(&account);

    REQUIRE(configureRemoteUrl(authorPath, QStringLiteral("origin"), QUrl::fromLocalFile(remotePath).toString()));
    REQUIRE(setGitConfigString(authorPath, "lfs.url", lfsServer.endpoint()));

    const QString authorFilePath = QDir(authorPath).filePath(trackedFileName);
    const QByteArray workingBytes = createPngFile(authorFilePath, Qt::darkBlue);
    REQUIRE(!workingBytes.isEmpty());
    REQUIRE_NOTHROW(author.commitAll(QStringLiteral("Add LFS file"), QStringLiteral("LFS wildcard refspec")));

    git_repository* authorRepo = nullptr;
    REQUIRE(git_repository_open(&authorRepo, authorPath.toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(authorRepo != nullptr);
    std::unique_ptr<git_repository, decltype(&git_repository_free)> authorRepoHolder(authorRepo, &git_repository_free);

    const QByteArray committedBlob = readBlobFromHead(authorRepo, trackedFileName.toUtf8().constData());
    REQUIRE(!committedBlob.isEmpty());
    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(committedBlob, &pointer));
    REQUIRE(pointer.size == workingBytes.size());
    lfsServer.setExpectedUploadObject(pointer.oid, pointer.size);

    auto pushFuture = author.push(QStringLiteral("refs/heads/*:refs/heads/*"));
    REQUIRE(AsyncFuture::waitForFinished(pushFuture, 60 * 1000));
    INFO("Wildcard push error:" << pushFuture.result().errorMessage().toStdString()
         << "code:" << pushFuture.result().errorCode());
    REQUIRE(pushFuture.result().hasError());
    CHECK(pushFuture.result().errorMessage().contains(QStringLiteral("Wildcard push refspecs are not supported")));
    CHECK(lfsServer.uploadBatchRequestCount() == 0);
    CHECK(lfsServer.uploadRequestCount() == 0);
}

TEST_CASE("SshLfsAuthenticator download authenticates against GitHub", "[LFS][network][ssh][download]") {
    const QStringList missingEnv = missingSshLfsDownloadEnvVars();
    if (!missingEnv.isEmpty()) {
        const QString skipMessage =
            QStringLiteral("Missing required env var(s): %1").arg(missingEnv.join(QStringLiteral(", ")));
        SKIP(skipMessage.toStdString());
    }

    const auto future = SshLfsAuthenticator::authenticate(sshLfsTestRemoteUrl(),
                                                           SshLfsAuthenticator::Operation::Download);
    REQUIRE(AsyncFuture::waitForFinished(future, 90 * 1000));
    INFO("SSH download auth error:" << future.result().errorMessage().toStdString()
         << "code:" << future.result().errorCode());
    REQUIRE(!future.result().hasError());

    const auto auth = future.result().value();
    INFO("SSH download href:" << auth.href.toString().toStdString());
    CHECK(auth.href.isValid());
    CHECK(auth.href.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0);
    CHECK_FALSE(auth.href.host().isEmpty());
    CHECK(hasHeaderCaseInsensitive(auth.headers, QByteArray("Authorization")));
}

TEST_CASE("SshLfsAuthenticator upload authenticates against GitHub", "[LFS][network][ssh][upload]") {
    const QStringList missingEnv = missingSshLfsUploadEnvVars();
    if (!missingEnv.isEmpty()) {
        const QString skipMessage =
            QStringLiteral("Missing required env var(s): %1").arg(missingEnv.join(QStringLiteral(", ")));
        SKIP(skipMessage.toStdString());
    }

    const auto future = SshLfsAuthenticator::authenticate(sshLfsTestRemoteUrl(),
                                                           SshLfsAuthenticator::Operation::Upload);
    REQUIRE(AsyncFuture::waitForFinished(future, 90 * 1000));
    INFO("SSH upload auth error:" << future.result().errorMessage().toStdString()
         << "code:" << future.result().errorCode());
    REQUIRE(!future.result().hasError());

    const auto auth = future.result().value();
    INFO("SSH upload href:" << auth.href.toString().toStdString());
    CHECK(auth.href.isValid());
    CHECK(auth.href.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0);
    CHECK_FALSE(auth.href.host().isEmpty());
    CHECK(hasHeaderCaseInsensitive(auth.headers, QByteArray("Authorization")));
}

TEST_CASE("LfsBatchClient upload and round-trip download against GitHub", "[LFS][network][upload]") {
    const QStringList missingEnv = missingUploadAuthEnvVars();
    if (!missingEnv.isEmpty()) {
        const QString skipMessage =
            QStringLiteral("Missing required env var(s): %1").arg(missingEnv.join(QStringLiteral(", ")));
        SKIP(skipMessage.toStdString());
    }
    const QString sshRemoteUrl = sshLfsTestRemoteUrl();
    const QString sshLfsUrl = sshRemoteUrl.endsWith(QStringLiteral("/info/lfs"))
        ? sshRemoteUrl
        : (sshRemoteUrl + QStringLiteral("/info/lfs"));

    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QString repoPath = QDir(tempDir.path()).filePath(QStringLiteral("lfs-test-upload"));
    GitRepository repository;
    repository.setDirectory(QDir(repoPath));

    auto cloneFuture = repository.clone(QUrl(sshRemoteUrl));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 60 * 1000));
    INFO("Clone error:" << cloneFuture.result().errorMessage().toStdString());
    REQUIRE(!cloneFuture.result().hasError());

    // Explicitly disable static/global HTTP auth so this test validates SSH-derived auth headers.
    ScopedLfsAuthProvider authProvider(nullptr);

    REQUIRE(setGitConfigString(repoPath, "lfs.url", sshLfsUrl));

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
    INFO("Expected auth path: SSH git-lfs-authenticate -> RemoteAuth header");
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

TEST_CASE("GitRepository clone reports LFS hydration progress against GitHub SSH", "[LFS][network][ssh][progress][clone]") {
    const QStringList missingEnv = missingSshLfsDownloadEnvVars();
    if (!missingEnv.isEmpty()) {
        const QString skipMessage =
            QStringLiteral("Missing required env var(s): %1").arg(missingEnv.join(QStringLiteral(", ")));
        SKIP(skipMessage.toStdString());
    }

    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QString repoPath = QDir(tempDir.path()).filePath(QStringLiteral("lfs-progress-clone"));
    GitRepository repository;
    repository.setDirectory(QDir(repoPath));

    auto cloneFuture = repository.clone(QUrl(sshLfsTestRemoteUrl()));
    QStringList progressTexts;
    AsyncFuture::observe(cloneFuture).onProgress([&progressTexts, cloneFuture]() mutable {
        const ProgressState state = ProgressState::fromJson(cloneFuture.progressText());
        progressTexts.append(state.text());
    });

    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 120 * 1000));
    INFO("Clone error:" << cloneFuture.result().errorMessage().toStdString()
         << "code:" << cloneFuture.result().errorCode());
    REQUIRE(!cloneFuture.result().hasError());
    REQUIRE(!progressTexts.isEmpty());

    bool sawLfsProgress = false;
    for (const QString& text : std::as_const(progressTexts)) {
        if (text.contains(QStringLiteral("Downloading LFS objects"))
            || text.contains(QStringLiteral("Hydrating LFS files"))) {
            sawLfsProgress = true;
            break;
        }
    }
    INFO("Observed progress texts:" << progressTexts.join(QStringLiteral(" | ")).toStdString());
    CHECK(sawLfsProgress);
}

TEST_CASE("GitRepository fetch reports LFS hydration progress against GitHub SSH", "[LFS][network][ssh][progress][fetch]") {
    const QStringList missingEnv = missingSshLfsDownloadEnvVars();
    if (!missingEnv.isEmpty()) {
        const QString skipMessage =
            QStringLiteral("Missing required env var(s): %1").arg(missingEnv.join(QStringLiteral(", ")));
        SKIP(skipMessage.toStdString());
    }

    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QString repoPath = QDir(tempDir.path()).filePath(QStringLiteral("lfs-progress-fetch"));
    GitRepository repository;
    repository.setDirectory(QDir(repoPath));

    auto cloneFuture = repository.clone(QUrl(sshLfsTestRemoteUrl()));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 120 * 1000));
    INFO("Clone error:" << cloneFuture.result().errorMessage().toStdString()
         << "code:" << cloneFuture.result().errorCode());
    REQUIRE(!cloneFuture.result().hasError());

    LfsPointer pointer;
    QString pointerPath;
    const bool pointerFromWorkingTree = findFirstLfsPointerInRepo(repoPath, &pointer, &pointerPath);
    const bool pointerFromIndex = pointerFromWorkingTree
        ? true
        : findFirstLfsPointerInIndex(repoPath, &pointer, &pointerPath);
    INFO("Pointer source:"
         << (pointerFromWorkingTree ? "working-tree" : (pointerFromIndex ? "index" : "none")));
    INFO("Pointer path candidate:" << pointerPath.toStdString());
    REQUIRE(pointerFromIndex);
    REQUIRE(pointer.isValid());

    const QString gitDirPath = gitDirPathFromWorkTree(repoPath);
    REQUIRE(!gitDirPath.isEmpty());
    const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
    REQUIRE(!objectPath.isEmpty());
    if (QFileInfo::exists(objectPath)) {
        REQUIRE(QFile::remove(objectPath));
    }
    CHECK_FALSE(QFileInfo::exists(objectPath));

    auto fetchFuture = repository.fetch();
    QStringList progressTexts;
    AsyncFuture::observe(fetchFuture).onProgress([&progressTexts, fetchFuture]() mutable {
        const ProgressState state = ProgressState::fromJson(fetchFuture.progressText());
        progressTexts.append(state.text());
    });

    REQUIRE(AsyncFuture::waitForFinished(fetchFuture, 120 * 1000));
    INFO("Fetch error:" << fetchFuture.result().errorMessage().toStdString()
         << "code:" << fetchFuture.result().errorCode());
    REQUIRE(!fetchFuture.result().hasError());
    REQUIRE(QFileInfo::exists(objectPath));
    REQUIRE(!progressTexts.isEmpty());

    bool sawLfsProgress = false;
    for (const QString& text : std::as_const(progressTexts)) {
        if (text.contains(QStringLiteral("Downloading LFS objects"))
            || text.contains(QStringLiteral("Hydrating LFS files"))) {
            sawLfsProgress = true;
            break;
        }
    }
    INFO("Observed progress texts:" << progressTexts.join(QStringLiteral(" | ")).toStdString());
    CHECK(sawLfsProgress);
}
