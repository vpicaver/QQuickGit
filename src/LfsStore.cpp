#include "LfsStore.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QMutex>
#include <QMutexLocker>
#include <algorithm>

namespace {

const QByteArray LfsPointerVersionLine = "version https://git-lfs.github.com/spec/v1";

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
    : mGitDirPath(std::move(gitDirPath)),
    mPolicy(std::move(policy))
{
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
    if (oidBytes.isEmpty()) {
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

        if (!QFile::copy(filePath, objectPath)) {
            return Monad::Result<LfsPointer>(QStringLiteral("Failed to write LFS object"));
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
    auto& stores = storeRegistry[store->gitDirPath()];
    compactStoresLocked(stores);
    stores.append(store);
}

void LfsStoreRegistry::unregisterStore(const QString& gitDirPath)
{
    if (gitDirPath.isEmpty()) {
        return;
    }
    QMutexLocker locker(&registryMutex);
    storeRegistry.remove(gitDirPath);
}

void LfsStoreRegistry::unregisterStore(const QString& gitDirPath,
                                       const std::shared_ptr<LfsStore>& store)
{
    if (gitDirPath.isEmpty() || !store) {
        return;
    }
    QMutexLocker locker(&registryMutex);
    auto it = storeRegistry.find(gitDirPath);
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
    if (gitDirPath.isEmpty()) {
        return {};
    }
    QMutexLocker locker(&registryMutex);
    auto it = storeRegistry.find(gitDirPath);
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
