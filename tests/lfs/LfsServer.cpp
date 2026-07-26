#include "LfsServer.h"

#include <QDebug>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTcpSocket>
#include <QTimer>

#include <algorithm>

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

QJsonArray requestedObjectsFromBatchBody(const QByteArray& body)
{
    QJsonParseError parseError{};
    const QJsonDocument doc = QJsonDocument::fromJson(body, &parseError);
    if (doc.isNull() || !doc.isObject()) {
        return {};
    }
    return doc.object().value(QStringLiteral("objects")).toArray();
}

// Real Git LFS batch endpoints (e.g. GitHub) reject requests with more than 100 objects.
constexpr int kMaxBatchObjects = 100;
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
    if (oid.isEmpty()) {
        return;
    }
    mDownloadObjects.insert(oid, bytes);
}

void LfsServer::setExpectedUploadObject(const QString& oid, qint64 size)
{
    if (oid.isEmpty() || size <= 0) {
        return;
    }
    mExpectedUploads.insert(oid, size);
}

void LfsServer::setObjectResponseDelayMs(int delayMs)
{
    mObjectResponseDelayMs = std::max(0, delayMs);
}

int LfsServer::downloadBatchRequestCount() const
{
    return mDownloadBatchRequestCount;
}

int LfsServer::downloadObjectRequestCount() const
{
    return mDownloadObjectRequestCount;
}

int LfsServer::maxConcurrentObjectRequests() const
{
    return mMaxConcurrentObjectRequests;
}

int LfsServer::uploadBatchRequestCount() const
{
    return mUploadBatchRequestCount;
}

int LfsServer::uploadRequestCount() const
{
    return mUploadRequestCount;
}

int LfsServer::maxConcurrentUploadRequests() const
{
    return mMaxConcurrentUploadRequests;
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
        return false;
    }

    const QByteArray firstLine = request.split('\n').value(0).trimmed();
    const QByteArray method = firstLine.split(' ').value(0).trimmed();
    const QByteArray path = firstLine.split(' ').value(1).trimmed();
    const QByteArray body = request.mid(bodyStart, contentLength >= 0 ? contentLength : receivedBodyBytes);

    if (path.contains("/objects/batch")) {
        if (requestedObjectsFromBatchBody(body).size() > kMaxBatchObjects) {
            respond(socket, 413, QByteArray("application/vnd.git-lfs+json"),
                    QByteArray("{\"message\":\"More than 100 objects specified\"}"));
            return true;
        }

        const bool isUpload = body.contains("\"operation\":\"upload\"");
        if (isUpload) {
            mUploadBatchRequestCount++;
            const QString baseUrl = QStringLiteral("http://127.0.0.1:%1").arg(mServer.serverPort());
            QJsonArray responseObjects;
            const QJsonArray requestObjects = requestedObjectsFromBatchBody(body);
            for (const QJsonValue& value : requestObjects) {
                if (!value.isObject()) {
                    continue;
                }

                const QJsonObject requestObject = value.toObject();
                const QString oid = requestObject.value(QStringLiteral("oid")).toString();
                const qint64 size = static_cast<qint64>(requestObject.value(QStringLiteral("size")).toDouble(-1));
                if (oid.isEmpty()) {
                    continue;
                }

                QJsonObject responseObject;
                responseObject.insert(QStringLiteral("oid"), oid);
                responseObject.insert(QStringLiteral("size"),
                                      size >= 0 ? size : mExpectedUploads.value(oid, 0));

                if (!mUploadedOids.contains(oid) && mExpectedUploads.contains(oid)) {
                    QJsonObject uploadAction;
                    uploadAction.insert(QStringLiteral("href"),
                                        QStringLiteral("%1/upload/%2").arg(baseUrl, oid));
                    QJsonObject actions;
                    actions.insert(QStringLiteral("upload"), uploadAction);
                    responseObject.insert(QStringLiteral("actions"), actions);
                }

                responseObjects.append(responseObject);
            }

            const QByteArray responseBody = QJsonDocument(QJsonObject{
                {QStringLiteral("transfer"), QStringLiteral("basic")},
                {QStringLiteral("objects"), responseObjects}
            }).toJson(QJsonDocument::Compact);
            respond(socket, 200, QByteArray("application/vnd.git-lfs+json"), responseBody);
            return true;
        }

        mDownloadBatchRequestCount++;
        QJsonArray responseObjects;
        const QJsonArray requestObjects = requestedObjectsFromBatchBody(body);
        for (const QJsonValue& value : requestObjects) {
            const QString oid = value.toObject().value(QStringLiteral("oid")).toString();
            if (oid.isEmpty() || !mDownloadObjects.contains(oid)) {
                continue;
            }
            const QByteArray objectBytes = mDownloadObjects.value(oid);

            QJsonObject downloadAction;
            downloadAction.insert(QStringLiteral("href"),
                                  QStringLiteral("http://127.0.0.1:%1/objects/%2")
                                      .arg(mServer.serverPort())
                                      .arg(oid));
            QJsonObject actions;
            actions.insert(QStringLiteral("download"), downloadAction);

            QJsonObject responseObject;
            responseObject.insert(QStringLiteral("oid"), oid);
            responseObject.insert(QStringLiteral("size"), static_cast<qint64>(objectBytes.size()));
            responseObject.insert(QStringLiteral("actions"), actions);
            responseObjects.append(responseObject);
        }

        const QByteArray responseBody = QJsonDocument(QJsonObject{
            {QStringLiteral("transfer"), QStringLiteral("basic")},
            {QStringLiteral("objects"), responseObjects}
        }).toJson(QJsonDocument::Compact);
        respond(socket, 200, QByteArray("application/vnd.git-lfs+json"), responseBody);
        return true;
    }

    if (method == "PUT" && path.contains("/upload/")) {
        mUploadRequestCount++;
        const QByteArray uploadPrefix("/upload/");
        const int uploadPrefixIndex = path.indexOf(uploadPrefix);
        if (uploadPrefixIndex >= 0) {
            const QString oid = QString::fromUtf8(path.mid(uploadPrefixIndex + uploadPrefix.size()));
            if (!oid.isEmpty()) {
                mUploadedOids.insert(oid);
            }
        }

        mInFlightUploadRequests++;
        mMaxConcurrentUploadRequests = std::max(mMaxConcurrentUploadRequests, mInFlightUploadRequests);

        auto sendUploadResponse = [this, socket]() {
            mInFlightUploadRequests--;
            respond(socket, 200, QByteArray("application/json"), QByteArray("{}"));
        };

        // Mirror the download path: holding the response open lets several uploads overlap on the
        // wire so the test can observe the parallel upload window via maxConcurrentUploadRequests().
        // socket is the context object, so a disconnect cancels the pending response cleanly.
        if (mObjectResponseDelayMs > 0) {
            QTimer::singleShot(mObjectResponseDelayMs, socket, sendUploadResponse);
        } else {
            sendUploadResponse();
        }
        return true;
    }

    const QByteArray objectPathPrefix("/objects/");
    const int objectPrefixIndex = path.indexOf(objectPathPrefix);
    if (objectPrefixIndex >= 0) {
        mDownloadObjectRequestCount++;
        const QByteArray oidBytes = path.mid(objectPrefixIndex + objectPathPrefix.size());
        const QString requestedOid = QString::fromUtf8(oidBytes);

        mInFlightObjectRequests++;
        mMaxConcurrentObjectRequests = std::max(mMaxConcurrentObjectRequests, mInFlightObjectRequests);

        auto sendObject = [this, socket, requestedOid]() {
            mInFlightObjectRequests--;
            if (!requestedOid.isEmpty() && mDownloadObjects.contains(requestedOid)) {
                respond(socket, 200, QByteArray("application/octet-stream"), mDownloadObjects.value(requestedOid));
            } else {
                respond(socket, 404, QByteArray("application/octet-stream"), QByteArray("missing"));
            }
        };

        // Holding the response open lets several transfers overlap on the wire so the test can see
        // the parallel hydration window via maxConcurrentObjectRequests(). socket is the context
        // object, so a disconnect cancels the pending response cleanly.
        if (mObjectResponseDelayMs > 0) {
            QTimer::singleShot(mObjectResponseDelayMs, socket, sendObject);
        } else {
            sendObject();
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
    const auto reasonPhrase = [](int code) -> QByteArray {
        switch (code) {
        case 200: return QByteArray("OK");
        case 413: return QByteArray("Payload Too Large");
        default:  return QByteArray("Not Found");
        }
    };
    const QByteArray statusText = reasonPhrase(status);
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
