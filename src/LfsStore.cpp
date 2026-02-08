#include "LfsStore.h"
#include "LfsBatchClient.h"

#include "asyncfuture.h"

#include <QCryptographicHash>
#include <QByteArrayView>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QFile>
#include <QMutex>
#include <QMutexLocker>
#include <QUuid>
#include <QDebug>
#include <algorithm>

namespace {

const QByteArray LfsPointerVersionLine = "version https://git-lfs.github.com/spec/v1";

bool isValidSha256Oid(const QByteArray& oid)
{
    if (oid.size() != 64) {
        return false;
    }
    for (char ch : oid) {
        const bool isDigit = ch >= '0' && ch <= '9';
        const bool isLowerHex = ch >= 'a' && ch <= 'f';
        if (!isDigit && !isLowerHex) {
            return false;
        }
    }
    return true;
}

QString normalizeGitDirPath(const QString& gitDirPath)
{
    if (gitDirPath.isEmpty()) {
        return QString();
    }
    return QDir(gitDirPath).absolutePath();
}

QString lfsObjectsDir(const QString& gitDirPath)
{
    return QDir(gitDirPath).filePath(QStringLiteral("lfs/objects"));
}

QString oidToObjectPath(const QString& gitDirPath, const QString& oid)
{
    if (oid.size() < 4) {
        return QString();
    }
    const QString objectsDir = lfsObjectsDir(gitDirPath);
    const QString first = oid.mid(0, 2);
    const QString second = oid.mid(2, 2);
    return QDir(objectsDir).filePath(first + QLatin1Char('/') + second + QLatin1Char('/') + oid);
}

bool ensureDirForObjectPath(const QString& objectPath)
{
    const QFileInfo info(objectPath);
    const QDir dir(info.absolutePath());
    if (dir.exists()) {
        return true;
    }
    return QDir().mkpath(dir.absolutePath());
}

QString sha256HexForData(const QByteArray& data)
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(data);
    return QString::fromLatin1(hash.result().toHex());
}

QString sha256HexForFile(const QString& filePath, qint64* outSize, QString* error)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) {
            *error = file.errorString();
        }
        return QString();
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 size = 0;
    while (!file.atEnd()) {
        const QByteArray chunk = file.read(1024 * 128);
        if (chunk.isEmpty() && file.error() != QFile::NoError) {
            if (error) {
                *error = file.errorString();
            }
            return QString();
        }
        hash.addData(chunk);
        size += chunk.size();
    }

    if (outSize) {
        *outSize = size;
    }
    return QString::fromLatin1(hash.result().toHex());
}

} // namespace

namespace QQuickGit {

LfsStore::LfsStore(QString gitDirPath, LfsPolicy policy)
    : mGitDirPath(normalizeGitDirPath(gitDirPath)),
    mPolicy(std::move(policy))
{
}

LfsStore::StreamWriter::StreamWriter(QString gitDirPath, std::shared_ptr<QFile> file, QString tempPath)
    : mGitDirPath(std::move(gitDirPath)),
    mFile(std::move(file)),
    mHasher(std::make_shared<QCryptographicHash>(QCryptographicHash::Sha256)),
    mSize(0),
    mTempPath(std::move(tempPath))
{
}

LfsStore::StreamWriter::StreamWriter()
    : mHasher(std::make_shared<QCryptographicHash>(QCryptographicHash::Sha256)),
    mSize(0)
{
}

bool LfsStore::StreamWriter::isValid() const
{
    return mFile && mFile->isOpen();
}

Monad::ResultBase LfsStore::StreamWriter::write(const char* data, size_t len)
{
    if (!isValid()) {
        return Monad::ResultBase(QStringLiteral("LFS stream writer is not open"));
    }
    if (len == 0) {
        return Monad::ResultBase();
    }
    mHasher->addData(QByteArrayView(data, static_cast<qsizetype>(len)));
    const qint64 written = mFile->write(data, static_cast<qint64>(len));
    if (written != static_cast<qint64>(len)) {
        return Monad::ResultBase(QStringLiteral("Failed to write LFS stream data"));
    }
    mSize += written;
    return Monad::ResultBase();
}

Monad::Result<LfsPointer> LfsStore::StreamWriter::finalize()
{
    if (!isValid()) {
        return Monad::Result<LfsPointer>(QStringLiteral("LFS stream writer is not open"));
    }

    const QString oid = QString::fromLatin1(mHasher->result().toHex());
    const QString objectPath = oidToObjectPath(mGitDirPath, oid);
    if (objectPath.isEmpty()) {
        return Monad::Result<LfsPointer>(QStringLiteral("Invalid LFS object path"));
    }

    if (!ensureDirForObjectPath(objectPath)) {
        return Monad::Result<LfsPointer>(QStringLiteral("Failed to create LFS object directory"));
    }

    mFile->close();

    if (QFileInfo::exists(objectPath)) {
        QFile::remove(mTempPath);
    } else {
        if (!QFile::rename(mTempPath, objectPath)) {
            if (!QFile::copy(mTempPath, objectPath)) {
                return Monad::Result<LfsPointer>(QStringLiteral("Failed to move LFS object data"));
            }
            QFile::remove(mTempPath);
        }
    }

    LfsPointer pointer;
    pointer.oid = oid;
    pointer.size = mSize;
    return Monad::Result<LfsPointer>(pointer);
}

void LfsStore::StreamWriter::discard()
{
    if (mFile && mFile->isOpen()) {
        mFile->close();
    }
    if (!mTempPath.isEmpty()) {
        QFile::remove(mTempPath);
    }
}

Monad::Result<LfsStore::StreamWriter> LfsStore::beginStore(qint64 sizeHint) const
{
    if (mGitDirPath.isEmpty()) {
        return Monad::Result<LfsStore::StreamWriter>(QStringLiteral("Missing git directory"));
    }

    const QString tempDirPath = QDir(mGitDirPath).filePath(QStringLiteral("lfs/tmp"));
    if (!QDir().mkpath(tempDirPath)) {
        return Monad::Result<LfsStore::StreamWriter>(QStringLiteral("Failed to create LFS temp directory"));
    }

    Q_UNUSED(sizeHint);
    const QString tempFilePath = QDir(tempDirPath).filePath(QUuid::createUuid().toString(QUuid::WithoutBraces));
    auto file = std::make_shared<QFile>(tempFilePath);
    if (!file->open(QIODevice::WriteOnly)) {
        return Monad::Result<LfsStore::StreamWriter>(file->errorString());
    }

    StreamWriter writer(mGitDirPath, std::move(file), tempFilePath);
    return Monad::Result<LfsStore::StreamWriter>(writer);
}

void LfsStore::setPolicy(const LfsPolicy& policy)
{
    mPolicy = policy;
}

bool LfsPointer::isValid() const
{
    return !oid.isEmpty() && size >= 0;
}

QByteArray LfsPointer::toPointerText() const
{
    if (!isValid()) {
        return QByteArray();
    }
    QByteArray text;
    text.reserve(128);
    text.append(LfsPointerVersionLine);
    text.append('\n');
    text.append("oid sha256:");
    text.append(oid.toLatin1());
    text.append('\n');
    text.append("size ");
    text.append(QByteArray::number(size));
    text.append('\n');
    return text;
}

bool LfsPointer::parse(const QByteArray& data, LfsPointer* outPointer)
{
    if (!outPointer) {
        return false;
    }

    const QList<QByteArray> lines = data.split('\n');
    if (lines.isEmpty()) {
        return false;
    }

    QByteArray versionLine;
    QByteArray oidLine;
    QByteArray sizeLine;
    for (const QByteArray& line : lines) {
        const QByteArray trimmed = line.trimmed();
        if (trimmed.startsWith("version ")) {
            versionLine = trimmed;
        } else if (trimmed.startsWith("oid ")) {
            oidLine = trimmed;
        } else if (trimmed.startsWith("size ")) {
            sizeLine = trimmed;
        }
    }

    if (versionLine != LfsPointerVersionLine) {
        return false;
    }

    const QByteArray oidPrefix("oid sha256:");
    if (!oidLine.startsWith(oidPrefix)) {
        return false;
    }
    const QByteArray oidBytes = oidLine.mid(oidPrefix.size()).trimmed();
    if (!isValidSha256Oid(oidBytes)) {
        return false;
    }

    const QByteArray sizePrefix("size ");
    if (!sizeLine.startsWith(sizePrefix)) {
        return false;
    }
    bool ok = false;
    const qint64 size = sizeLine.mid(sizePrefix.size()).trimmed().toLongLong(&ok);
    if (!ok || size < 0) {
        return false;
    }

    outPointer->oid = QString::fromLatin1(oidBytes);
    outPointer->size = size;
    return outPointer->isValid();
}

bool LfsStore::isLfsEligible(const QString& filePath) const
{
    return mPolicy.isEligible(filePath, nullptr);
}

bool LfsStore::isLfsEligibleData(const QString& path, const QByteArray& data) const
{
    return mPolicy.isEligible(path, &data);
}

Monad::Result<LfsPointer> LfsStore::storeFile(const QString& filePath) const
{
    if (mGitDirPath.isEmpty()) {
        return Monad::Result<LfsPointer>(QStringLiteral("Missing git directory"));
    }

    qint64 size = 0;
    QString error;
    const QString oid = sha256HexForFile(filePath, &size, &error);
    if (oid.isEmpty()) {
        if (error.isEmpty()) {
            error = QStringLiteral("Failed to hash file for LFS");
        }
        return Monad::Result<LfsPointer>(error);
    }

    const QString objectPath = oidToObjectPath(mGitDirPath, oid);
    if (objectPath.isEmpty()) {
        return Monad::Result<LfsPointer>(QStringLiteral("Invalid LFS object path"));
    }

    if (!QFileInfo::exists(objectPath)) {
        if (!ensureDirForObjectPath(objectPath)) {
            return Monad::Result<LfsPointer>(QStringLiteral("Failed to create LFS object directory"));
        }

        QSaveFile file(objectPath);
        if (!file.open(QIODevice::WriteOnly)) {
            return Monad::Result<LfsPointer>(file.errorString());
        }

        QFile source(filePath);
        if (!source.open(QIODevice::ReadOnly)) {
            return Monad::Result<LfsPointer>(source.errorString());
        }

        while (!source.atEnd()) {
            const QByteArray chunk = source.read(1024 * 128);
            if (chunk.isEmpty() && source.error() != QFile::NoError) {
                return Monad::Result<LfsPointer>(source.errorString());
            }
            if (!chunk.isEmpty()) {
                if (file.write(chunk) != chunk.size()) {
                    return Monad::Result<LfsPointer>(QStringLiteral("Failed to write LFS object"));
                }
            }
        }

        if (!file.commit()) {
            return Monad::Result<LfsPointer>(QStringLiteral("Failed to commit LFS object"));
        }
    }

    LfsPointer pointer;
    pointer.oid = oid;
    pointer.size = size;
    return Monad::Result<LfsPointer>(pointer);
}

Monad::Result<LfsPointer> LfsStore::storeBytes(const QByteArray& data) const
{
    if (mGitDirPath.isEmpty()) {
        return Monad::Result<LfsPointer>(QStringLiteral("Missing git directory"));
    }

    const QString oid = sha256HexForData(data);
    const QString objectPath = oidToObjectPath(mGitDirPath, oid);
    if (objectPath.isEmpty()) {
        return Monad::Result<LfsPointer>(QStringLiteral("Invalid LFS object path"));
    }

    if (!QFileInfo::exists(objectPath)) {
        if (!ensureDirForObjectPath(objectPath)) {
            return Monad::Result<LfsPointer>(QStringLiteral("Failed to create LFS object directory"));
        }

        QSaveFile file(objectPath);
        if (!file.open(QIODevice::WriteOnly)) {
            return Monad::Result<LfsPointer>(file.errorString());
        }
        if (file.write(data) != data.size()) {
            return Monad::Result<LfsPointer>(QStringLiteral("Failed to write LFS object data"));
        }
        if (!file.commit()) {
            return Monad::Result<LfsPointer>(QStringLiteral("Failed to commit LFS object data"));
        }
    }

    LfsPointer pointer;
    pointer.oid = oid;
    pointer.size = data.size();
    return Monad::Result<LfsPointer>(pointer);
}

Monad::Result<QByteArray> LfsStore::readObject(const QString& oid) const
{
    const QString objectPath = oidToObjectPath(mGitDirPath, oid);
    if (objectPath.isEmpty()) {
        return Monad::Result<QByteArray>(QStringLiteral("Invalid LFS object path"));
    }

    QFile file(objectPath);
    if (!file.exists()) {
        return Monad::Result<QByteArray>(QStringLiteral("LFS object not found"));
    }
    if (!file.open(QIODevice::ReadOnly)) {
        return Monad::Result<QByteArray>(file.errorString());
    }

    return Monad::Result<QByteArray>(file.readAll());
}

QFuture<Monad::ResultBase> LfsStore::fetchObject(const LfsPointer& pointer, const QString& remoteName) const
{
    if (!pointer.isValid()) {
        return AsyncFuture::completed(Monad::ResultBase(QStringLiteral("Invalid LFS pointer"),
                                                        static_cast<int>(LfsFetchErrorCode::Protocol)));
    }

    const LfsPointer expected = pointer;
    LfsBatchClient::ObjectSpec spec{pointer.oid, pointer.size};
    // Never capture `this` across async continuations. Use a dedicated store instance
    // that stays alive for the full batch->download chain.
    auto downloadStore = std::make_shared<LfsStore>(mGitDirPath, mPolicy);

    auto client = batchClient();
    auto batchFuture = client->batch(QStringLiteral("download"), {spec}, remoteName);

    return AsyncFuture::observe(batchFuture)
        .context(client.get(),
                 [client, downloadStore, expected](const Monad::Result<LfsBatchClient::BatchResponse>& batchResult) {
        if (batchResult.hasError()) {
            return AsyncFuture::completed(Monad::ResultBase(batchResult.errorMessage(), batchResult.errorCode()));
        }

        const auto response = batchResult.value();
        if (response.objects.isEmpty()) {
            return AsyncFuture::completed(Monad::ResultBase(QStringLiteral("Missing LFS batch response objects"),
                                                            static_cast<int>(LfsFetchErrorCode::Protocol)));
        }

        const LfsBatchClient::ObjectResponse* objectResponse = nullptr;
        for (const auto& entry : response.objects) {
            if (entry.oid == expected.oid) {
                objectResponse = &entry;
                break;
            }
        }
        if (!objectResponse) {
            objectResponse = &response.objects.first();
        }

        if (!objectResponse->errorMessage.isEmpty()) {
            const int errorCode = objectResponse->errorCode == 404
                                      ? static_cast<int>(LfsFetchErrorCode::NotFound)
                                      : static_cast<int>(LfsFetchErrorCode::Transfer);
            return AsyncFuture::completed(Monad::ResultBase(objectResponse->errorMessage, errorCode));
        }

        if (!objectResponse->actions.contains(QStringLiteral("download"))) {
            return AsyncFuture::completed(Monad::ResultBase(QStringLiteral("Missing LFS download action"),
                                                            static_cast<int>(LfsFetchErrorCode::Protocol)));
        }

        return client->downloadObject(objectResponse->actions.value(QStringLiteral("download")), *downloadStore, expected);
    }, []() {
        return AsyncFuture::completed(
            Monad::ResultBase(QStringLiteral("LFS batch request canceled"),
                              static_cast<int>(LfsFetchErrorCode::Transfer)));
    }).future();
}

std::shared_ptr<LfsBatchClient> LfsStore::batchClient() const
{
    if (!mBatchClient) {
        mBatchClient = std::make_shared<LfsBatchClient>(mGitDirPath);
    }
    return mBatchClient;
}

QObject* LfsStore::lfsContext() const
{
    auto client = batchClient();
    return client.get();
}

bool LfsStore::shouldFallbackForFetchError(int errorCode)
{
    const auto code = static_cast<LfsFetchErrorCode>(errorCode);
    return code == LfsFetchErrorCode::NoRemote || code == LfsFetchErrorCode::Offline;
}

QString LfsStore::objectPath(const QString& gitDirPath, const QString& oid)
{
    return oidToObjectPath(gitDirPath, oid);
}

namespace {
QMutex registryMutex;
QHash<QString, QVector<std::weak_ptr<LfsStore>>> storeRegistry;

void compactStoresLocked(QVector<std::weak_ptr<LfsStore>>& stores)
{
    auto it = std::remove_if(stores.begin(), stores.end(),
                             [](const std::weak_ptr<LfsStore>& entry) {
                                 return entry.expired();
                             });
    stores.erase(it, stores.end());
}
} // namespace

void LfsStoreRegistry::registerStore(const std::shared_ptr<LfsStore>& store)
{
    if (!store) {
        return;
    }
    QMutexLocker locker(&registryMutex);
    const QString normalized = normalizeGitDirPath(store->gitDirPath());
    auto& stores = storeRegistry[normalized];
    compactStoresLocked(stores);
    stores.append(store);
}

void LfsStoreRegistry::unregisterStore(const QString& gitDirPath)
{
    const QString normalized = normalizeGitDirPath(gitDirPath);
    if (normalized.isEmpty()) {
        return;
    }
    QMutexLocker locker(&registryMutex);
    storeRegistry.remove(normalized);
}

void LfsStoreRegistry::unregisterStore(const QString& gitDirPath,
                                       const std::shared_ptr<LfsStore>& store)
{
    const QString normalized = normalizeGitDirPath(gitDirPath);
    if (normalized.isEmpty() || !store) {
        return;
    }
    QMutexLocker locker(&registryMutex);
    auto it = storeRegistry.find(normalized);
    if (it == storeRegistry.end()) {
        return;
    }
    auto& stores = it.value();
    for (auto entryIt = stores.begin(); entryIt != stores.end();) {
        if (entryIt->expired() || entryIt->lock() == store) {
            entryIt = stores.erase(entryIt);
        } else {
            ++entryIt;
        }
    }
    if (stores.isEmpty()) {
        storeRegistry.erase(it);
    }
}

std::shared_ptr<LfsStore> LfsStoreRegistry::storeFor(const QString& gitDirPath)
{
    const QString normalized = normalizeGitDirPath(gitDirPath);
    if (normalized.isEmpty()) {
        return {};
    }
    QMutexLocker locker(&registryMutex);
    auto it = storeRegistry.find(normalized);
    if (it == storeRegistry.end()) {
        return {};
    }
    auto& stores = it.value();
    compactStoresLocked(stores);
    for (auto entryIt = stores.crbegin(); entryIt != stores.crend(); ++entryIt) {
        if (auto store = entryIt->lock()) {
            return store;
        }
    }
    storeRegistry.erase(it);
    return {};
}

} // namespace QQuickGit
