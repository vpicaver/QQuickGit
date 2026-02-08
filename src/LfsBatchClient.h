#ifndef LFSBATCHCLIENT_H
#define LFSBATCHCLIENT_H

#include <QByteArray>
#include <QHash>
#include <QMap>
#include <QFuture>
#include <QObject>
#include <QNetworkReply>
#include <QUrl>
#include <QVector>
#include <memory>

struct git_repository;
class QNetworkRequest;
class QNetworkAccessManager;

#include "LfsAuthProvider.h"
#include "LfsStore.h"
#include "Monad/Result.h"

namespace QQuickGit {

class LfsBatchClient : public QObject
{
    Q_OBJECT

public:
    struct ObjectSpec {
        QString oid;
        qint64 size = 0;
    };

    struct Action {
        QUrl href;
        QMap<QByteArray, QByteArray> headers;
    };

    struct ObjectResponse {
        QString oid;
        qint64 size = 0;
        QHash<QString, Action> actions;
        int errorCode = 0;
        QString errorMessage;
    };

    struct BatchResponse {
        QString transfer;
        QVector<ObjectResponse> objects;
    };

    explicit LfsBatchClient(QString gitDirPath, QObject* parent = nullptr);

    QFuture<Monad::Result<BatchResponse>> batch(const QString& operation,
                                                const QVector<ObjectSpec>& objects,
                                                const QString& remoteName = QString()) const;

    QFuture<Monad::ResultBase> downloadObject(const Action& action,
                                              const LfsStore& store,
                                              const LfsPointer& expected) const;

    QFuture<Monad::ResultBase> uploadObject(const Action& action,
                                            const QString& objectPath,
                                            const LfsPointer& pointer) const;
    QFuture<Monad::ResultBase> verifyObject(const Action& action,
                                            const LfsPointer& pointer) const;

    static void setLfsAuthProvider(std::shared_ptr<LfsAuthProvider> provider);
    static std::shared_ptr<LfsAuthProvider> lfsAuthProvider();

private:
    QString mGitDirPath;
    QNetworkAccessManager* mManager = nullptr;

    static bool isHttpUrl(const QUrl& url);
    static bool parseAuthFromUrl(const QUrl& url, QByteArray* headerOut);
    static void applyHeaders(QNetworkRequest* request, const QMap<QByteArray, QByteArray>& headers);
    static Monad::Result<QUrl> resolveLfsEndpoint(git_repository* repo, const QString& remoteName);
    static QString defaultRemoteName(git_repository* repo);
    static QByteArray buildBatchRequestBody(const QString& operation, const QVector<ObjectSpec>& objects);
    static bool isOfflineError(QNetworkReply::NetworkError error);
    static void applyAuthHeader(QNetworkRequest* request, const QUrl& url);
    static void applyExtraHeaders(git_repository* repo, const QUrl& url, QNetworkRequest* request);
};

} // namespace QQuickGit

#endif // LFSBATCHCLIENT_H
