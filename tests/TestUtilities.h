#ifndef TESTUTILITIES_H
#define TESTUTILITIES_H

//Qt includes
#include <QDir>
#include <QString>
#include <QModelIndex>
#include <QHash>
#include <QDateTime>

namespace QQuickGit { class GitRepository; }

class TestUtilities
{
public:
    TestUtilities();

    static QDir createUniqueTempDir();

    static QDir moveToNewTempDirectory(const QDir& oldDirectory);
    static void copyAndReplaceFolderContents(const QString &fromDir, const QString &toDir, bool copyAndRemove = false);

    static void createFileAndCommit(QQuickGit::GitRepository& repo, const QString& filename,
                                    const QString& content, const QString& message);
    static void createBinaryFileAndCommit(QQuickGit::GitRepository& repo, const QString& filename,
                                          const QByteArray& content, const QString& message);
    static void deleteFileAndCommit(QQuickGit::GitRepository& repo, const QString& filename,
                                    const QString& message);
    static QString getHeadSha(const QDir& dir);
    static void initBareRepo(const QString& path);

    struct IndexEntryTime {
        qint64 seconds = -1;
        qint64 nanoseconds = -1;
    };

    // Reads through a freshly opened repository so the result is what is on disk.
    static IndexEntryTime indexEntryModificationTime(const QDir& repoDir, const QString& path);

    // A whole second an hour in the past, so the index stamp never makes it racy.
    static QDateTime pastWholeSecond();
    static void setTrackedFilesModificationTime(const QDir& repoDir, const QDateTime& time);

    // Number of entries libgit2 hashes in a status walk that leaves the index as is.
    static size_t statusOidCalculations(const QDir& repoDir);
};

std::ostream& operator<<(std::ostream& os, const QVariantMap& map);
std::ostream& operator<<(std::ostream& os, const QModelIndex& index);
std::ostream& operator<<(std::ostream& os, const QStringList& list);
std::ostream& operator<<(std::ostream& os, const QHash<int, QByteArray>& hash);


#endif // TESTUTILITIES_H
