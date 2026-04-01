#ifndef TESTUTILITIES_H
#define TESTUTILITIES_H

//Qt includes
#include <QDir>
#include <QString>
#include <QModelIndex>
#include <QHash>

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
    static void deleteFileAndCommit(QQuickGit::GitRepository& repo, const QString& filename,
                                    const QString& message);
    static QString getHeadSha(const QDir& dir);
};

std::ostream& operator<<(std::ostream& os, const QVariantMap& map);
std::ostream& operator<<(std::ostream& os, const QModelIndex& index);
std::ostream& operator<<(std::ostream& os, const QStringList& list);
std::ostream& operator<<(std::ostream& os, const QHash<int, QByteArray>& hash);


#endif // TESTUTILITIES_H
