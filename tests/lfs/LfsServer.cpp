#include "LfsServer.h"

#include <QDebug>
#include <QHostAddress>
#include <QTcpSocket>

LfsServer::LfsServer(QObject* parent)
    : QObject(parent)
{
}

bool LfsServer::start()
{
    QObject::connect(&mServer, &QTcpServer::newConnection, &mServer, [this]() { handleNewConnections(); });
    if (mServer.listen(QHostAddress::LocalHost, 0)) {
        return true;
    }
    return mServer.listen(QHostAddress::Any, 0);
}

QString LfsServer::endpoint() const
{
    return QStringLiteral("http://127.0.0.1:%1/info/lfs").arg(mServer.serverPort());
}

void LfsServer::setDownloadObject(const QString& oid, const QByteArray& bytes)
{
    mDownloadOid = oid;
    mDownloadObjectBytes = bytes;
}

void LfsServer::setExpectedUploadObject(const QString& oid, qint64 size)
{
    mUploadOid = oid;
    mUploadSize = size;
}

int LfsServer::downloadBatchRequestCount() const
{
    return mDownloadBatchRequestCount;
}

int LfsServer::downloadObjectRequestCount() const
{
    return mDownloadObjectRequestCount;
}

int LfsServer::uploadBatchRequestCount() const
{
    return mUploadBatchRequestCount;
}

int LfsServer::uploadRequestCount() const
{
    return mUploadRequestCount;
}

void LfsServer::handleNewConnections()
{
    while (mServer.hasPendingConnections()) {
        QTcpSocket* socket = mServer.nextPendingConnection();
        QObject::connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
            const QByteArray request = socket->readAll();
            if (request.isEmpty()) {
                return;
            }
            handleRequest(socket, request);
        });
        QObject::connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
    }
}

void LfsServer::handleRequest(QTcpSocket* socket, const QByteArray& request)
{
    const QByteArray firstLine = request.split('\n').value(0).trimmed();
    const QByteArray method = firstLine.split(' ').value(0).trimmed();
    const QByteArray path = firstLine.split(' ').value(1).trimmed();
    const int bodyStart = request.indexOf("\r\n\r\n");
    const QByteArray body = bodyStart >= 0 ? request.mid(bodyStart + 4) : QByteArray();

    qDebug() << "[LfsServer] request"
             << method
             << path
             << "bodyBytes=" << body.size();

    if (path.contains("/objects/batch")) {
        const bool isUpload = body.contains("\"operation\":\"upload\"");
        if (isUpload) {
            mUploadBatchRequestCount++;
            qDebug() << "[LfsServer] upload batch request count =" << mUploadBatchRequestCount
                     << "expectedOid=" << mUploadOid
                     << "expectedSize=" << mUploadSize;
            if (mUploadOid.isEmpty() || mUploadSize <= 0) {
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
                .arg(mUploadOid)
                .arg(mUploadSize)
                .arg(baseUrl)
                .toUtf8();
            respond(socket, 200, QByteArray("application/vnd.git-lfs+json"), responseBody);
            return;
        }

        mDownloadBatchRequestCount++;
        qDebug() << "[LfsServer] download batch request count =" << mDownloadBatchRequestCount;
        if (mDownloadOid.isEmpty() || mDownloadObjectBytes.isEmpty()) {
            respond(socket,
                    200,
                    QByteArray("application/vnd.git-lfs+json"),
                    QByteArray("{\"transfer\":\"basic\",\"objects\":[]}"));
            return;
        }

        const QString href = QStringLiteral("http://127.0.0.1:%1/objects/%2")
            .arg(mServer.serverPort())
            .arg(mDownloadOid);
        const QByteArray responseBody = QStringLiteral(
            "{\"transfer\":\"basic\",\"objects\":[{\"oid\":\"%1\",\"size\":%2,"
            "\"actions\":{\"download\":{\"href\":\"%3\"}}}]}")
            .arg(mDownloadOid)
            .arg(mDownloadObjectBytes.size())
            .arg(href)
            .toUtf8();
        respond(socket, 200, QByteArray("application/vnd.git-lfs+json"), responseBody);
        return;
    }

    if (method == "PUT" && path.contains("/upload/")) {
        mUploadRequestCount++;
        qDebug() << "[LfsServer] upload object request count =" << mUploadRequestCount;
        respond(socket, 200, QByteArray("application/json"), QByteArray("{}"));
        return;
    }

    const QByteArray objectPathPrefix("/objects/");
    const int objectPrefixIndex = path.indexOf(objectPathPrefix);
    if (objectPrefixIndex >= 0) {
        mDownloadObjectRequestCount++;
        qDebug() << "[LfsServer] download object request count =" << mDownloadObjectRequestCount;
        const QByteArray oidBytes = path.mid(objectPrefixIndex + objectPathPrefix.size());
        const QString requestedOid = QString::fromUtf8(oidBytes);
        if (!requestedOid.isEmpty() && requestedOid == mDownloadOid) {
            respond(socket, 200, QByteArray("application/octet-stream"), mDownloadObjectBytes);
        } else {
            respond(socket, 404, QByteArray("application/octet-stream"), QByteArray("missing"));
        }
        return;
    }

    respond(socket, 404, QByteArray("application/json"), QByteArray("{\"message\":\"not found\"}"));
}

void LfsServer::respond(QTcpSocket* socket,
                            int status,
                            const QByteArray& contentType,
                            const QByteArray& body) const
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
