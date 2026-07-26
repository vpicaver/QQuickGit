#ifndef LFS_SERVER_H
#define LFS_SERVER_H

#include <QByteArray>
#include <QHash>
#include <QSet>
#include <QObject>
#include <QString>
#include <QTcpServer>

class QTcpSocket;

class LfsServer : public QObject
{
    Q_OBJECT

public:
    explicit LfsServer(QObject* parent = nullptr);

    bool start();
    QString endpoint() const;

    void setDownloadObject(const QString& oid, const QByteArray& bytes);
    void setExpectedUploadObject(const QString& oid, qint64 size);

    // Delays each object download and upload response so concurrent transfers overlap on the wire
    // long enough to be observed via maxConcurrentObjectRequests() / maxConcurrentUploadRequests().
    // 0 (default) responds synchronously.
    void setObjectResponseDelayMs(int delayMs);

    int downloadBatchRequestCount() const;
    int downloadObjectRequestCount() const;
    int maxConcurrentObjectRequests() const;
    int uploadBatchRequestCount() const;
    int uploadRequestCount() const;
    int maxConcurrentUploadRequests() const;

private:
    void handleNewConnections();
    bool handleRequest(QTcpSocket* socket, const QByteArray& request);
    void respond(QTcpSocket* socket, int status, const QByteArray& contentType, const QByteArray& body) const;

    QTcpServer mServer;
    QHash<QTcpSocket*, QByteArray> mPendingRequests;
    QHash<QString, QByteArray> mDownloadObjects;
    QHash<QString, qint64> mExpectedUploads;
    QSet<QString> mUploadedOids;
    int mDownloadBatchRequestCount = 0;
    int mDownloadObjectRequestCount = 0;
    int mObjectResponseDelayMs = 0;
    int mInFlightObjectRequests = 0;
    int mMaxConcurrentObjectRequests = 0;
    int mUploadBatchRequestCount = 0;
    int mUploadRequestCount = 0;
    int mInFlightUploadRequests = 0;
    int mMaxConcurrentUploadRequests = 0;
};

#endif // LFS_SERVER_H
