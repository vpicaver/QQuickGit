#ifndef LFS_SERVER_H
#define LFS_SERVER_H

#include <QByteArray>
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

    int downloadBatchRequestCount() const;
    int downloadObjectRequestCount() const;
    int uploadBatchRequestCount() const;
    int uploadRequestCount() const;

private:
    void handleNewConnections();
    void handleRequest(QTcpSocket* socket, const QByteArray& request);
    void respond(QTcpSocket* socket, int status, const QByteArray& contentType, const QByteArray& body) const;

    QTcpServer mServer;
    QString mDownloadOid;
    QByteArray mDownloadObjectBytes;
    QString mUploadOid;
    qint64 mUploadSize = 0;
    int mDownloadBatchRequestCount = 0;
    int mDownloadObjectRequestCount = 0;
    int mUploadBatchRequestCount = 0;
    int mUploadRequestCount = 0;
};

#endif // LFS_SERVER_H
