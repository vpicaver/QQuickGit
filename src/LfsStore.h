#ifndef LFSSTORE_H
#define LFSSTORE_H

#include <QByteArray>
#include <QString>

#include <memory>
#include <QCryptographicHash>
#include <QFile>

#include "LfsPolicy.h"
#include "Monad/Result.h"

namespace QQuickGit {

struct LfsPointer {
    QString oid;
    qint64 size = 0;

    bool isValid() const;
    QByteArray toPointerText() const;
    static bool parse(const QByteArray& data, LfsPointer* outPointer);
};

class LfsStore
{
public:
    explicit LfsStore(QString gitDirPath, LfsPolicy policy = LfsPolicy());

    const QString& gitDirPath() const { return mGitDirPath; }
    const LfsPolicy& policy() const { return mPolicy; }
    void setPolicy(const LfsPolicy& policy);

    bool isLfsEligible(const QString& filePath) const;
    bool isLfsEligibleData(const QString& path, const QByteArray& data) const;

    Monad::Result<LfsPointer> storeFile(const QString& filePath) const;

    Monad::Result<LfsPointer> storeBytes(const QByteArray& data) const;

    Monad::Result<QByteArray> readObject(const QString& oid) const;

    static QString objectPath(const QString& gitDirPath, const QString& oid);

    class StreamWriter {
    public:
        StreamWriter(QString gitDirPath, std::shared_ptr<QFile> file, QString tempPath);
        StreamWriter();

        bool isValid() const;
        Monad::ResultBase write(const char* data, size_t len);
        Monad::Result<LfsPointer> finalize();

    private:
        QString mGitDirPath;
        std::shared_ptr<QFile> mFile;
        std::shared_ptr<QCryptographicHash> mHasher;
        qint64 mSize = 0;
        QString mTempPath;
    };

    Monad::Result<StreamWriter> beginStore(qint64 sizeHint = -1) const;

private:
    QString mGitDirPath;
    LfsPolicy mPolicy;
};

class LfsStoreRegistry
{
public:
    static void registerStore(const std::shared_ptr<LfsStore>& store);
    static void unregisterStore(const QString& gitDirPath);
    static void unregisterStore(const QString& gitDirPath,
                                const std::shared_ptr<LfsStore>& store);
    static std::shared_ptr<LfsStore> storeFor(const QString& gitDirPath);
};

} // namespace QQuickGit

#endif // LFSSTORE_H
