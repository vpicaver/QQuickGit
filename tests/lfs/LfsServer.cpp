#include "LfsServer.h"

#include <QDebug>
#include <QHostAddress>
#include <QTcpSocket>

namespace {
int contentLengthFromHeaders(const QByteArray& request)
{
    const int headerEnd = request.indexOf("\r\n\r\n");
    if (headerEnd < 0) {
        return -1;
    }
    const QByteArray headerBlock = request.left(headerEnd);
    const QList<QByteArray> lines = headerBlock.split('\n');
    for (const QByteArray& rawLine : lines) {
        const QByteArray line = rawLine.trimmed();
        if (line.toLower().startsWith("content-length:")) {
            bool ok = false;
            const int value = line.mid(sizeof("Content-Length:") - 1).trimmed().toInt(&ok);
            return ok ? value : 0;
        }
    }
    return 0;
}
} // namespace

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
            const QByteArray chunk = socket->readAll();
            if (chunk.isEmpty()) {
                return;
            }
            QByteArray& pending = mPendingRequests[socket];
            pending.append(chunk);
            if (handleRequest(socket, pending)) {
                mPendingRequests.remove(socket);
            }
        });
        QObject::connect(socket, &QTcpSocket::disconnected, socket, [this, socket]() {
            mPendingRequests.remove(socket);
            socket->deleteLater();
        });
    }
}

bool LfsServer::handleRequest(QTcpSocket* socket, const QByteArray& request)
{
    if (!socket) {
        return true;
    }

    const int headerEnd = request.indexOf("\r\n\r\n");
    if (headerEnd < 0) {
        return false;
    }

    const int contentLength = contentLengthFromHeaders(request);
    const int bodyStart = headerEnd + 4;
    const int receivedBodyBytes = request.size() - bodyStart;
    if (contentLength >= 0 && receivedBodyBytes < contentLength) {
        qDebug() << "[LfsServer] waiting for full body" << receivedBodyBytes << "/" << contentLength;
        return false;
    }

    const QByteArray firstLine = request.split('\n').value(0).trimmed();
    const QByteArray method = firstLine.split(' ').value(0).trimmed();
    const QByteArray path = firstLine.split(' ').value(1).trimmed();
    const QByteArray body = request.mid(bodyStart, contentLength >= 0 ? contentLength : receivedBodyBytes);

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
                return true;
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
            return true;
        }

        mDownloadBatchRequestCount++;
        qDebug() << "[LfsServer] download batch request count =" << mDownloadBatchRequestCount;
        if (mDownloadOid.isEmpty() || mDownloadObjectBytes.isEmpty()) {
            respond(socket,
                    200,
                    QByteArray("application/vnd.git-lfs+json"),
                    QByteArray("{\"transfer\":\"basic\",\"objects\":[]}"));
            return true;
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
        return true;
    }

    if (method == "PUT" && path.contains("/upload/")) {
        mUploadRequestCount++;
        qDebug() << "[LfsServer] upload object request count =" << mUploadRequestCount
                 << "receivedBytes=" << body.size();
        respond(socket, 200, QByteArray("application/json"), QByteArray("{}"));
        return true;
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
        return true;
    }

    respond(socket, 404, QByteArray("application/json"), QByteArray("{\"message\":\"not found\"}"));
    return true;
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
