#include "LfsBatchClient.h"

#include <QByteArray>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutex>
#include <QMutexLocker>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <memory>

#include "asyncfuture.h"
#include "git2.h"
#include "git2/config.h"
#include "git2/remote.h"

namespace {
constexpr int LfsBatchTimeoutMs = 30000;
constexpr const char* LfsJsonMime = "application/vnd.git-lfs+json";
constexpr int ErrorBodyPreviewBytes = 512;
QMutex gLfsAuthProviderMutex;
std::shared_ptr<QQuickGit::LfsAuthProvider> gLfsAuthProvider;

QString trimTrailingSlash(QString value)
{
    while (value.endsWith('/')) {
        value.chop(1);
    }
    return value;
}

QString toHeaderName(const QString& line)
{
    const int index = line.indexOf(':');
    if (index <= 0) {
        return QString();
    }
    return line.left(index).trimmed();
}

QByteArray toHeaderValue(const QString& line)
{
    const int index = line.indexOf(':');
    if (index < 0) {
        return QByteArray();
    }
    return line.mid(index + 1).trimmed().toUtf8();
}

QString responseBodyPreview(QNetworkReply* reply)
{
    if (!reply) {
        return QString();
    }

    const QByteArray body = reply->readAll();
    if (body.isEmpty()) {
        return QString();
    }

    const bool truncated = body.size() > ErrorBodyPreviewBytes;
    const QByteArray previewBytes = truncated ? body.left(ErrorBodyPreviewBytes) : body;
    const QString previewText = QString::fromUtf8(previewBytes).simplified();
    if (previewText.isEmpty()) {
        return QString();
    }

    if (truncated) {
        return QStringLiteral("%1 [truncated]").arg(previewText);
    }
    return previewText;
}

QString enrichReplyErrorMessage(const QString& baseMessage, QNetworkReply* reply, int httpStatus = 0)
{
    if (!reply) {
        return baseMessage;
    }

    QString message = baseMessage;
    message += QStringLiteral(" [networkError=%1").arg(static_cast<int>(reply->error()));

    const QString detail = reply->errorString();
    if (!detail.isEmpty()) {
        message += QStringLiteral(", detail=\"%1\"").arg(detail);
    }

    if (httpStatus > 0) {
        message += QStringLiteral(", httpStatus=%1").arg(httpStatus);
    }

    const QString bodyPreview = responseBodyPreview(reply);
    if (!bodyPreview.isEmpty()) {
        message += QStringLiteral(", response=\"%1\"").arg(bodyPreview);
    }

    message += QLatin1Char(']');
    return message;
}

}

namespace QQuickGit {

void LfsBatchClient::setLfsAuthProvider(std::shared_ptr<LfsAuthProvider> provider)
{
    QMutexLocker locker(&gLfsAuthProviderMutex);
    gLfsAuthProvider = std::move(provider);
}

std::shared_ptr<LfsAuthProvider> LfsBatchClient::lfsAuthProvider()
{
    QMutexLocker locker(&gLfsAuthProviderMutex);
    return gLfsAuthProvider;
}

LfsBatchClient::LfsBatchClient(QString gitDirPath, QObject* parent)
    : QObject(parent),
      mGitDirPath(std::move(gitDirPath)),
      mManager(new QNetworkAccessManager(this))
{
}

QFuture<Monad::Result<LfsBatchClient::BatchResponse>> LfsBatchClient::batch(const QString& operation,
                                                                            const QVector<ObjectSpec>& objects,
                                                                            const QString& remoteName) const
{
    git_repository* repo = nullptr;
    if (git_repository_open(&repo, mGitDirPath.toUtf8().constData()) != GIT_OK) {
        return AsyncFuture::completed(Monad::Result<BatchResponse>(QStringLiteral("Failed to open git repository"),
                                                                   static_cast<int>(LfsFetchErrorCode::NoRemote)));
    }

    auto repoGuard = git_repository_free;
    std::unique_ptr<git_repository, decltype(repoGuard)> repoHolder(repo, repoGuard);

    auto endpointResult = resolveLfsEndpoint(repo, remoteName);
    if (endpointResult.hasError()) {
        return AsyncFuture::completed(Monad::Result<BatchResponse>(endpointResult.errorMessage(), endpointResult.errorCode()));
    }

    QUrl endpoint = endpointResult.value();
    if (!isHttpUrl(endpoint)) {
        return AsyncFuture::completed(Monad::Result<BatchResponse>(QStringLiteral("Unsupported LFS remote URL"),
                                                                   static_cast<int>(LfsFetchErrorCode::NoRemote)));
    }

    QUrl batchUrl(endpoint);
    batchUrl.setPath(trimTrailingSlash(endpoint.path()) + QStringLiteral("/objects/batch"));

    QNetworkAccessManager manager;
    QNetworkRequest request(batchUrl);
    request.setHeader(QNetworkRequest::ContentTypeHeader, LfsJsonMime);
    request.setRawHeader("Accept", LfsJsonMime);

    applyAuthHeader(&request, endpoint);
    applyExtraHeaders(repo, endpoint, &request);

    const QByteArray payload = buildBatchRequestBody(operation, objects);

    auto deferred = AsyncFuture::deferred<Monad::Result<BatchResponse>>();
    deferred.reportStarted();

    request.setTransferTimeout(LfsBatchTimeoutMs);

    QNetworkReply* reply = mManager->post(request, payload);

    auto finish = [deferred, reply](const Monad::Result<BatchResponse>& result) mutable {
        deferred.complete(result);
        if (reply) {
            reply->deleteLater();
        }
    };

    QObject::connect(reply, &QNetworkReply::finished, reply, [reply, finish]() mutable {
        if (!reply) {
            finish(Monad::Result<BatchResponse>(QStringLiteral("Missing LFS reply"),
                                                static_cast<int>(LfsFetchErrorCode::Transfer)));
            return;
        }

        const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (reply->error() != QNetworkReply::NoError) {
            const QNetworkReply::NetworkError netError = reply->error();
            if (isOfflineError(netError)) {
                finish(Monad::Result<BatchResponse>(enrichReplyErrorMessage(QStringLiteral("LFS batch request failed (offline)"),
                                                                            reply,
                                                                            httpStatus),
                                                    static_cast<int>(LfsFetchErrorCode::Offline)));
            } else {
                finish(Monad::Result<BatchResponse>(enrichReplyErrorMessage(QStringLiteral("LFS batch request failed"),
                                                                            reply,
                                                                            httpStatus),
                                                    static_cast<int>(LfsFetchErrorCode::Transfer)));
            }
            return;
        }

        if (httpStatus >= 400) {
            int errorCode = static_cast<int>(LfsFetchErrorCode::Transfer);
            if (httpStatus == 401 || httpStatus == 403) {
                errorCode = static_cast<int>(LfsFetchErrorCode::Auth);
            }
            finish(Monad::Result<BatchResponse>(enrichReplyErrorMessage(QStringLiteral("LFS batch request failed (%1)").arg(httpStatus),
                                                                        reply,
                                                                        httpStatus),
                                                errorCode));
            return;
        }

        QJsonParseError parseError{};
        const QJsonDocument document = QJsonDocument::fromJson(reply->readAll(), &parseError);
        if (document.isNull() || !document.isObject()) {
            finish(Monad::Result<BatchResponse>(QStringLiteral("Invalid LFS batch response"),
                                                static_cast<int>(LfsFetchErrorCode::Protocol)));
            return;
        }

        BatchResponse response;
        const QJsonObject root = document.object();
        response.transfer = root.value(QStringLiteral("transfer")).toString();

        const QJsonArray objectsArray = root.value(QStringLiteral("objects")).toArray();
        response.objects.reserve(objectsArray.size());

        for (const auto& entry : objectsArray) {
            if (!entry.isObject()) {
                continue;
            }
            const QJsonObject object = entry.toObject();
            ObjectResponse objectResponse;
            objectResponse.oid = object.value(QStringLiteral("oid")).toString();
            objectResponse.size = static_cast<qint64>(object.value(QStringLiteral("size")).toDouble());

            const QJsonObject errorObject = object.value(QStringLiteral("error")).toObject();
            if (!errorObject.isEmpty()) {
                objectResponse.errorCode = errorObject.value(QStringLiteral("code")).toInt();
                objectResponse.errorMessage = errorObject.value(QStringLiteral("message")).toString();
            }

            const QJsonObject actions = object.value(QStringLiteral("actions")).toObject();
            for (auto it = actions.begin(); it != actions.end(); ++it) {
                if (!it.value().isObject()) {
                    continue;
                }
                const QJsonObject actionObject = it.value().toObject();
                Action action;
                action.href = QUrl(actionObject.value(QStringLiteral("href")).toString());
                const QJsonObject headers = actionObject.value(QStringLiteral("header")).toObject();
                for (auto headerIt = headers.begin(); headerIt != headers.end(); ++headerIt) {
                    action.headers.insert(headerIt.key().toUtf8(), headerIt.value().toString().toUtf8());
                }
                objectResponse.actions.insert(it.key(), action);
            }

            response.objects.push_back(objectResponse);
        }

        finish(Monad::Result<BatchResponse>(response));
    });

    return deferred.future();
}

QFuture<Monad::ResultBase> LfsBatchClient::downloadObject(const Action& action,
                                                          const LfsStore& store,
                                                          const LfsPointer& expected) const
{
    if (!action.href.isValid()) {
        return AsyncFuture::completed(Monad::ResultBase(QStringLiteral("Missing LFS download href"),
                                                        static_cast<int>(LfsFetchErrorCode::Protocol)));
    }

    auto beginResult = store.beginStore(expected.size);
    if (beginResult.hasError()) {
        return AsyncFuture::completed(Monad::ResultBase(beginResult.errorMessage(), beginResult.errorCode()));
    }

    auto writer = std::make_shared<LfsStore::StreamWriter>(beginResult.value());
    auto writeError = std::make_shared<Monad::ResultBase>();

    auto deferred = AsyncFuture::deferred<Monad::ResultBase>();
    deferred.reportStarted();

    QNetworkRequest request(action.href);
    applyHeaders(&request, action.headers);
    request.setTransferTimeout(LfsBatchTimeoutMs);

    applyAuthHeader(&request, action.href);

    git_repository* repo = nullptr;
    if (git_repository_open(&repo, mGitDirPath.toUtf8().constData()) == GIT_OK) {
        applyExtraHeaders(repo, action.href, &request);
        git_repository_free(repo);
    }

    QNetworkReply* reply = mManager->get(request);

    auto finish = [deferred, reply](const Monad::ResultBase& result) mutable {
        deferred.complete(result);
        if (reply) {
            reply->deleteLater();
        }
    };

    QObject::connect(reply, &QNetworkReply::readyRead, reply, [reply, writer, writeError]() mutable {
        if (writeError->hasError()) {
            return;
        }
        const QByteArray chunk = reply->readAll();
        if (!chunk.isEmpty()) {
            auto result = writer->write(chunk.constData(), static_cast<size_t>(chunk.size()));
            if (result.hasError()) {
                *writeError = result;
                reply->abort();
            }
        }
    });

    QObject::connect(reply, &QNetworkReply::destroyed, [reply, deferred]() mutable {
        if (deferred.future().isRunning()) {
            deferred.complete(Monad::ResultBase(QStringLiteral("LFS download request was deleted"), static_cast<int>(LfsFetchErrorCode::Transfer)));
        }
    });


    QObject::connect(reply, &QNetworkReply::finished, reply, [reply, writer, writeError, expected, finish, this]() mutable {
        if (!reply) {
            writer->discard();
            finish(Monad::ResultBase(QStringLiteral("Missing LFS reply"),
                                     static_cast<int>(LfsFetchErrorCode::Transfer)));
            return;
        }

        if (!writeError->hasError()) {
            const QByteArray remaining = reply->readAll();
            if (!remaining.isEmpty()) {
                auto result = writer->write(remaining.constData(), static_cast<size_t>(remaining.size()));
                if (result.hasError()) {
                    *writeError = result;
                }
            }
        }

        if (reply->error() != QNetworkReply::NoError) {
            const QNetworkReply::NetworkError netError = reply->error();
            writer->discard();
            if (isOfflineError(netError)) {
                finish(Monad::ResultBase(enrichReplyErrorMessage(QStringLiteral("LFS download failed (offline)"),
                                                                 reply),
                                         static_cast<int>(LfsFetchErrorCode::Offline)));
            } else {
                finish(Monad::ResultBase(enrichReplyErrorMessage(QStringLiteral("LFS download failed"),
                                                                 reply),
                                         static_cast<int>(LfsFetchErrorCode::Transfer)));
            }
            return;
        }

        const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (httpStatus >= 400) {
            writer->discard();
            int errorCode = static_cast<int>(LfsFetchErrorCode::Transfer);
            if (httpStatus == 401 || httpStatus == 403) {
                errorCode = static_cast<int>(LfsFetchErrorCode::Auth);
            } else if (httpStatus == 404) {
                errorCode = static_cast<int>(LfsFetchErrorCode::NotFound);
            }
            finish(Monad::ResultBase(enrichReplyErrorMessage(QStringLiteral("LFS download failed (%1)").arg(httpStatus),
                                                             reply,
                                                             httpStatus),
                                     errorCode));
            return;
        }

        if (writeError->hasError()) {
            writer->discard();
            finish(*writeError);
            return;
        }

        auto finalizeResult = writer->finalize();
        if (finalizeResult.hasError()) {
            finish(Monad::ResultBase(finalizeResult.errorMessage(), finalizeResult.errorCode()));
            return;
        }

        const LfsPointer actual = finalizeResult.value();
        if (actual.oid != expected.oid || actual.size != expected.size) {
            const QString objectPath = LfsStore::objectPath(mGitDirPath, actual.oid);
            if (!objectPath.isEmpty()) {
                QFile::remove(objectPath);
            }
            finish(Monad::ResultBase(QStringLiteral("LFS download hash mismatch"),
                                     static_cast<int>(LfsFetchErrorCode::Protocol)));
            return;
        }

        finish(Monad::ResultBase());
    });

    return deferred.future();
}

QFuture<Monad::ResultBase> LfsBatchClient::uploadObject(const Action& action,
                                                        const QString& objectPath,
                                                        const LfsPointer& pointer) const
{
    if (!action.href.isValid()) {
        return AsyncFuture::completed(Monad::ResultBase(QStringLiteral("Missing LFS upload href"),
                                                        static_cast<int>(LfsFetchErrorCode::Protocol)));
    }

    auto file = std::make_shared<QFile>(objectPath);
    if (!file->open(QIODevice::ReadOnly)) {
        return AsyncFuture::completed(Monad::ResultBase(QStringLiteral("Failed to open LFS object for upload"),
                                                        static_cast<int>(LfsFetchErrorCode::Transfer)));
    }

    if (file->size() != pointer.size) {
        return AsyncFuture::completed(Monad::ResultBase(QStringLiteral("LFS object size mismatch before upload"),
                                                        static_cast<int>(LfsFetchErrorCode::Protocol)));
    }

    auto deferred = AsyncFuture::deferred<Monad::ResultBase>();
    deferred.reportStarted();

    QNetworkRequest request(action.href);
    applyHeaders(&request, action.headers);
    request.setTransferTimeout(LfsBatchTimeoutMs);

    applyAuthHeader(&request, action.href);

    git_repository* repo = nullptr;
    if (git_repository_open(&repo, mGitDirPath.toUtf8().constData()) == GIT_OK) {
        applyExtraHeaders(repo, action.href, &request);
        git_repository_free(repo);
    }

    QNetworkReply* reply = mManager->put(request, file.get());

    auto finish = [deferred, reply, file](const Monad::ResultBase& result) mutable {
        deferred.complete(result);
        if (reply) {
            reply->deleteLater();
        }
    };

    QObject::connect(reply, &QNetworkReply::finished, reply, [reply, finish]() mutable {
        if (!reply) {
            finish(Monad::ResultBase(QStringLiteral("Missing LFS reply"),
                                     static_cast<int>(LfsFetchErrorCode::Transfer)));
            return;
        }

        if (reply->error() != QNetworkReply::NoError) {
            const QNetworkReply::NetworkError netError = reply->error();
            if (isOfflineError(netError)) {
                finish(Monad::ResultBase(enrichReplyErrorMessage(QStringLiteral("LFS upload failed (offline)"),
                                                                 reply),
                                         static_cast<int>(LfsFetchErrorCode::Offline)));
            } else {
                finish(Monad::ResultBase(enrichReplyErrorMessage(QStringLiteral("LFS upload failed"),
                                                                 reply),
                                         static_cast<int>(LfsFetchErrorCode::Transfer)));
            }
            return;
        }

        const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (httpStatus >= 400) {
            int errorCode = static_cast<int>(LfsFetchErrorCode::Transfer);
            if (httpStatus == 401 || httpStatus == 403) {
                errorCode = static_cast<int>(LfsFetchErrorCode::Auth);
            }
            finish(Monad::ResultBase(enrichReplyErrorMessage(QStringLiteral("LFS upload failed (%1)").arg(httpStatus),
                                                             reply,
                                                             httpStatus),
                                     errorCode));
            return;
        }

        finish(Monad::ResultBase());
    });

    return deferred.future();
}

QFuture<Monad::ResultBase> LfsBatchClient::verifyObject(const Action& action,
                                                        const LfsPointer& pointer) const
{
    if (!action.href.isValid()) {
        return AsyncFuture::completed(Monad::ResultBase(QStringLiteral("Missing LFS verify href"),
                                                        static_cast<int>(LfsFetchErrorCode::Protocol)));
    }

    auto deferred = AsyncFuture::deferred<Monad::ResultBase>();
    deferred.reportStarted();

    QNetworkRequest request(action.href);
    applyHeaders(&request, action.headers);
    request.setHeader(QNetworkRequest::ContentTypeHeader, LfsJsonMime);
    request.setRawHeader("Accept", LfsJsonMime);
    request.setTransferTimeout(LfsBatchTimeoutMs);

    applyAuthHeader(&request, action.href);

    git_repository* repo = nullptr;
    if (git_repository_open(&repo, mGitDirPath.toUtf8().constData()) == GIT_OK) {
        applyExtraHeaders(repo, action.href, &request);
        git_repository_free(repo);
    }

    QJsonObject body;
    body.insert(QStringLiteral("oid"), pointer.oid);
    body.insert(QStringLiteral("size"), static_cast<double>(pointer.size));
    const QByteArray payload = QJsonDocument(body).toJson(QJsonDocument::Compact);

    QNetworkReply* reply = mManager->post(request, payload);

    auto finish = [deferred, reply](const Monad::ResultBase& result) mutable {
        deferred.complete(result);
        if (reply) {
            reply->deleteLater();
        }
    };

    QObject::connect(reply, &QNetworkReply::finished, reply, [reply, finish]() mutable {
        if (!reply) {
            finish(Monad::ResultBase(QStringLiteral("Missing LFS reply"),
                                     static_cast<int>(LfsFetchErrorCode::Transfer)));
            return;
        }

        const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (reply->error() != QNetworkReply::NoError) {
            const QNetworkReply::NetworkError netError = reply->error();
            if (isOfflineError(netError)) {
                finish(Monad::ResultBase(enrichReplyErrorMessage(QStringLiteral("LFS verify failed (offline)"),
                                                                 reply,
                                                                 httpStatus),
                                         static_cast<int>(LfsFetchErrorCode::Offline)));
            } else {
                finish(Monad::ResultBase(enrichReplyErrorMessage(QStringLiteral("LFS verify failed"),
                                                                 reply,
                                                                 httpStatus),
                                         static_cast<int>(LfsFetchErrorCode::Transfer)));
            }
            return;
        }

        if (httpStatus >= 400) {
            int errorCode = static_cast<int>(LfsFetchErrorCode::Transfer);
            if (httpStatus == 401 || httpStatus == 403) {
                errorCode = static_cast<int>(LfsFetchErrorCode::Auth);
            } else if (httpStatus == 404) {
                errorCode = static_cast<int>(LfsFetchErrorCode::NotFound);
            }
            finish(Monad::ResultBase(enrichReplyErrorMessage(QStringLiteral("LFS verify failed (%1)").arg(httpStatus),
                                                             reply,
                                                             httpStatus),
                                     errorCode));
            return;
        }

        finish(Monad::ResultBase());
    });

    return deferred.future();
}

bool LfsBatchClient::isHttpUrl(const QUrl& url)
{
    const QString scheme = url.scheme().toLower();
    return scheme == QStringLiteral("http") || scheme == QStringLiteral("https");
}

bool LfsBatchClient::parseAuthFromUrl(const QUrl& url, QByteArray* headerOut)
{
    if (!headerOut) {
        return false;
    }
    const QString user = url.userName();
    const QString pass = url.password();
    if (user.isEmpty() && pass.isEmpty()) {
        return false;
    }
    const QByteArray credentials = (user + ":" + pass).toUtf8().toBase64();
    *headerOut = QByteArray("Basic ") + credentials;
    return true;
}

void LfsBatchClient::applyHeaders(QNetworkRequest* request, const QMap<QByteArray, QByteArray>& headers)
{
    if (!request) {
        return;
    }
    for (auto it = headers.begin(); it != headers.end(); ++it) {
        request->setRawHeader(it.key(), it.value());
    }
}

Monad::Result<QUrl> LfsBatchClient::resolveLfsEndpoint(git_repository* repo, const QString& remoteName)
{
    if (!repo) {
        return Monad::Result<QUrl>(QStringLiteral("Missing git repository"),
                                   static_cast<int>(LfsFetchErrorCode::NoRemote));
    }

    git_config* config = nullptr;
    const int repoConfigResult = git_repository_config(&config, repo);
    if (repoConfigResult != GIT_OK) {
        return Monad::Result<QUrl>(QStringLiteral("Failed to read git config"),
                                   static_cast<int>(LfsFetchErrorCode::NoRemote));
    }

    std::unique_ptr<git_config, decltype(&git_config_free)> configHolder(config, &git_config_free);

    git_buf lfsUrlBuf = GIT_BUF_INIT;
    const int lfsUrlResult = git_config_get_string_buf(&lfsUrlBuf, config, "lfs.url");
    const QString lfsUrlValue = (lfsUrlResult == GIT_OK && lfsUrlBuf.ptr)
        ? QString::fromUtf8(lfsUrlBuf.ptr)
        : QString();
    if (lfsUrlResult == GIT_OK && !lfsUrlValue.isEmpty()) {
        const QUrl configured = QUrl(lfsUrlValue);
        git_buf_dispose(&lfsUrlBuf);
        return Monad::Result<QUrl>(configured);
    }
    git_buf_dispose(&lfsUrlBuf);

    QString resolvedRemote = remoteName;
    if (resolvedRemote.isEmpty()) {
        resolvedRemote = defaultRemoteName(repo);
    }
    if (resolvedRemote.isEmpty()) {
        return Monad::Result<QUrl>(QStringLiteral("No git remote configured for LFS"),
                                   static_cast<int>(LfsFetchErrorCode::NoRemote));
    }

    const QString lfsUrlKey = QStringLiteral("remote.%1.lfsurl").arg(resolvedRemote);
    const QByteArray lfsKey = lfsUrlKey.toUtf8();
    git_buf remoteLfsUrlBuf = GIT_BUF_INIT;
    const int remoteLfsResult = git_config_get_string_buf(&remoteLfsUrlBuf, config, lfsKey.constData());
    const QString remoteLfsValue = (remoteLfsResult == GIT_OK && remoteLfsUrlBuf.ptr)
        ? QString::fromUtf8(remoteLfsUrlBuf.ptr)
        : QString();
    if (remoteLfsResult == GIT_OK && !remoteLfsValue.isEmpty()) {
        const QUrl configuredRemote = QUrl(remoteLfsValue);
        git_buf_dispose(&remoteLfsUrlBuf);
        return Monad::Result<QUrl>(configuredRemote);
    }
    git_buf_dispose(&remoteLfsUrlBuf);

    git_remote* remote = nullptr;
    if (git_remote_lookup(&remote, repo, resolvedRemote.toUtf8().constData()) != GIT_OK) {
        return Monad::Result<QUrl>(QStringLiteral("Failed to resolve git remote for LFS"),
                                   static_cast<int>(LfsFetchErrorCode::NoRemote));
    }

    std::unique_ptr<git_remote, decltype(&git_remote_free)> remoteHolder(remote, &git_remote_free);

    const char* remoteUrl = git_remote_url(remote);
    if (!remoteUrl) {
        return Monad::Result<QUrl>(QStringLiteral("Missing remote URL for LFS"),
                                   static_cast<int>(LfsFetchErrorCode::NoRemote));
    }

    QUrl url(QString::fromUtf8(remoteUrl));
    if (!isHttpUrl(url)) {
        return Monad::Result<QUrl>(QStringLiteral("Unsupported LFS remote URL"),
                                   static_cast<int>(LfsFetchErrorCode::NoRemote));
    }

    const QString path = trimTrailingSlash(url.path()) + QStringLiteral("/info/lfs");
    url.setPath(path);
    return Monad::Result<QUrl>(url);
}

QString LfsBatchClient::defaultRemoteName(git_repository* repo)
{
    if (!repo) {
        return QString();
    }

    git_strarray remotes{};
    if (git_remote_list(&remotes, repo) != GIT_OK || remotes.count == 0) {
        return QString();
    }

    QString firstRemote;
    for (size_t i = 0; i < remotes.count; ++i) {
        const QString name = QString::fromUtf8(remotes.strings[i]);
        if (name == QStringLiteral("origin")) {
            git_strarray_dispose(&remotes);
            return name;
        }
        if (firstRemote.isEmpty()) {
            firstRemote = name;
        }
    }

    git_strarray_dispose(&remotes);
    return firstRemote;
}

QByteArray LfsBatchClient::buildBatchRequestBody(const QString& operation, const QVector<ObjectSpec>& objects)
{
    QJsonObject root;
    root.insert(QStringLiteral("operation"), operation);

    QJsonArray transfers;
    transfers.append(QStringLiteral("basic"));
    root.insert(QStringLiteral("transfers"), transfers);

    QJsonArray objectArray;
    for (const auto& object : objects) {
        QJsonObject entry;
        entry.insert(QStringLiteral("oid"), object.oid);
        entry.insert(QStringLiteral("size"), static_cast<double>(object.size));
        objectArray.append(entry);
    }
    root.insert(QStringLiteral("objects"), objectArray);

    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

bool LfsBatchClient::isOfflineError(QNetworkReply::NetworkError error)
{
    switch (error) {
    case QNetworkReply::HostNotFoundError:
    case QNetworkReply::TimeoutError:
    case QNetworkReply::ConnectionRefusedError:
    case QNetworkReply::NetworkSessionFailedError:
    case QNetworkReply::TemporaryNetworkFailureError:
        return true;
    default:
        return false;
    }
}

void LfsBatchClient::applyAuthHeader(QNetworkRequest* request, const QUrl& url)
{
    if (!request || request->hasRawHeader("Authorization")) {
        return;
    }

    std::shared_ptr<LfsAuthProvider> provider;
    {
        QMutexLocker locker(&gLfsAuthProviderMutex);
        provider = gLfsAuthProvider;
    }

    if (provider) {
        const QByteArray provided = provider->authorizationHeader(url);
        if (!provided.isEmpty()) {
            request->setRawHeader("Authorization", provided);
            return;
        }
    }

    QByteArray authHeader;
    if (parseAuthFromUrl(url, &authHeader)) {
        request->setRawHeader("Authorization", authHeader);
    }
}

void LfsBatchClient::applyExtraHeaders(git_repository* repo, const QUrl& url, QNetworkRequest* request)
{
    if (!repo || !request) {
        return;
    }

    git_config* config = nullptr;
    if (git_repository_config(&config, repo) != GIT_OK) {
        return;
    }

    std::unique_ptr<git_config, decltype(&git_config_free)> configHolder(config, &git_config_free);

    const QString host = url.host();
    const QString urlKey = QStringLiteral("http.%1.extraheader").arg(host);

    const char* headerValue = nullptr;
    if (git_config_get_string(&headerValue, config, "http.extraheader") == GIT_OK && headerValue) {
        const QString headerLine = QString::fromUtf8(headerValue);
        const QString headerName = toHeaderName(headerLine);
        if (!headerName.isEmpty()) {
            request->setRawHeader(headerName.toUtf8(), toHeaderValue(headerLine));
        }
    }

    headerValue = nullptr;
    if (!host.isEmpty() && git_config_get_string(&headerValue, config, urlKey.toUtf8().constData()) == GIT_OK && headerValue) {
        const QString headerLine = QString::fromUtf8(headerValue);
        const QString headerName = toHeaderName(headerLine);
        if (!headerName.isEmpty()) {
            request->setRawHeader(headerName.toUtf8(), toHeaderValue(headerLine));
        }
    }
}

} // namespace QQuickGit
