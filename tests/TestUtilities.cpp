//Our includes
#include "TestUtilities.h"
#include "GitRepository.h"
#include "Account.h"

//Qt includes
#include <QUuid>
#include <QJsonDocument>
#include <QDirIterator>
#include <QFile>
#include <QSignalSpy>
#include <QScopeGuard>

//libgit2
#include "git2.h"
#include "git2/sys/diff.h"

//Catch includes
#include <catch2/catch_test_macros.hpp>

// commitAll() emits refsChanged which triggers checkStatusAsync() in the background.
// This helper drains that pending async callback so it doesn't race with later test
// code that sets up dirty state and calls checkStatus() synchronously.
static void waitForAsyncStatusAfterCommit(QQuickGit::GitRepository& repo)
{
    QSignalSpy statusSpy(&repo, &QQuickGit::GitRepository::modifiedFileCountChanged);
    if (!statusSpy.wait(5000)) {
        QCoreApplication::processEvents();
    }
    repo.checkStatus();
}

using RepositoryHandle = std::unique_ptr<git_repository, decltype(&git_repository_free)>;
using IndexHandle = std::unique_ptr<git_index, decltype(&git_index_free)>;

static RepositoryHandle openRepository(const QDir& repoDir)
{
    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoDir.absolutePath().toLocal8Bit().constData()) == GIT_OK);
    return RepositoryHandle(repo, &git_repository_free);
}

static IndexHandle openIndex(git_repository* repo)
{
    git_index* index = nullptr;
    REQUIRE(git_repository_index(&index, repo) == GIT_OK);
    return IndexHandle(index, &git_index_free);
}

TestUtilities::TestUtilities()
{

}

QDir TestUtilities::createUniqueTempDir()
{
    QDir tempDir = QDir::temp();
    auto tempDirId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    REQUIRE(tempDir.mkdir(tempDirId)); //If this fails the folder already exist, remove it, try again
    tempDir.cd(tempDirId);
    return tempDir;
}

QDir TestUtilities::moveToNewTempDirectory(const QDir &oldDirectory)
{
    auto newTemp = TestUtilities::createUniqueTempDir();

    QDir dir;
    REQUIRE(dir.rmdir(newTemp.absolutePath()));

    CHECK(oldDirectory.exists());
    CHECK(!newTemp.exists());
    INFO("Old direcotry:" << oldDirectory.absolutePath().toStdString());
    INFO("New directory:" << newTemp.absolutePath().toStdString());
    CHECK(dir.rename(oldDirectory.absolutePath(), newTemp.absolutePath()));
    CHECK(newTemp.exists());

    return newTemp;
}

std::ostream& operator<<(std::ostream& os, const QVariantMap& map)
{
    QJsonDocument doc = QJsonDocument::fromVariant(map);
    os << "\"" << doc.toJson(QJsonDocument::Compact).toStdString() << "\"";
    return os;
}

std::ostream& operator<<(std::ostream& os, const QModelIndex& index)
{
    os << "model:" << index.model() << " (" << index.row() << "," << index.column() << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, const QStringList& list) {
    for (int i = 0; i < list.size(); ++i) {
        os << list.at(i).toStdString();
        if (i != list.size() - 1)
            os << ", ";
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const QHash<int, QByteArray>& hash)
{
    os << "{ ";
    for(auto it = hash.begin(); it != hash.end(); ++it) {
        if(it != hash.begin()) {
            os << ", ";
        }
        os << it.key() << " : " << it.value().toStdString();
    }
    os << " }";
    return os;
}

void TestUtilities::createFileAndCommit(QQuickGit::GitRepository& repo, const QString& filename,
                                        const QString& content, const QString& message)
{
    QDir dir = repo.directory();
    QFile file(dir.filePath(filename));
    REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate | QFile::Text));
    file.write(content.toUtf8());
    file.close();

    repo.checkStatus();

    QQuickGit::Account account;
    account.setName("Test Author");
    account.setEmail("test@example.com");
    repo.setAccount(&account);
    repo.commitAll(message, QString());
    waitForAsyncStatusAfterCommit(repo);
}

void TestUtilities::createBinaryFileAndCommit(QQuickGit::GitRepository& repo, const QString& filename,
                                              const QByteArray& content, const QString& message)
{
    QDir dir = repo.directory();
    QFile file(dir.filePath(filename));
    REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate));
    file.write(content);
    file.close();

    repo.checkStatus();

    QQuickGit::Account account;
    account.setName("Test Author");
    account.setEmail("test@example.com");
    repo.setAccount(&account);
    repo.commitAll(message, QString());
    waitForAsyncStatusAfterCommit(repo);
}

void TestUtilities::deleteFileAndCommit(QQuickGit::GitRepository& repo, const QString& filename,
                                        const QString& message)
{
    QDir dir = repo.directory();
    QFile::remove(dir.filePath(filename));

    repo.checkStatus();

    QQuickGit::Account account;
    account.setName("Test Author");
    account.setEmail("test@example.com");
    repo.setAccount(&account);
    repo.commitAll(message, QString());
    waitForAsyncStatusAfterCommit(repo);
}

QString TestUtilities::getHeadSha(const QDir& dir)
{
    git_repository* repo = nullptr;
    if (git_repository_open(&repo, dir.absolutePath().toLocal8Bit().constData()) != GIT_OK)
    {
        return {};
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)>
        repoHolder(repo, &git_repository_free);

    git_reference* headRef = nullptr;
    if (git_repository_head(&headRef, repo) != GIT_OK)
    {
        return {};
    }
    std::unique_ptr<git_reference, decltype(&git_reference_free)>
        refHolder(headRef, &git_reference_free);

    const git_oid* oid = git_reference_target(headRef);
    if (!oid)
    {
        return {};
    }

    char buffer[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(buffer, sizeof(buffer), oid);
    return QString::fromLatin1(buffer);
}

void TestUtilities::initBareRepo(const QString& path)
{
    git_repository_init_options opts = GIT_REPOSITORY_INIT_OPTIONS_INIT;
    opts.flags = GIT_REPOSITORY_INIT_BARE | GIT_REPOSITORY_INIT_MKPATH;
    opts.initial_head = "main";
    git_repository* repo = nullptr;
    REQUIRE(git_repository_init_ext(&repo, path.toLocal8Bit().constData(), &opts) == GIT_OK);
    REQUIRE(repo != nullptr);
    git_repository_free(repo);
}

TestUtilities::IndexEntryTime TestUtilities::indexEntryModificationTime(const QDir& repoDir, const QString& path)
{
    const auto repo = openRepository(repoDir);
    const auto index = openIndex(repo.get());

    const git_index_entry* entry = git_index_get_bypath(index.get(), path.toUtf8().constData(), 0);
    REQUIRE(entry != nullptr);

    return {entry->mtime.seconds, entry->mtime.nanoseconds};
}

QDateTime TestUtilities::pastWholeSecond()
{
    constexpr qint64 kSecondsInPast = 3600;
    const qint64 nowSeconds = QDateTime::currentSecsSinceEpoch();
    return QDateTime::fromSecsSinceEpoch(nowSeconds - kSecondsInPast);
}

void TestUtilities::setTrackedFilesModificationTime(const QDir& repoDir, const QDateTime& time)
{
    const auto repo = openRepository(repoDir);
    const auto index = openIndex(repo.get());

    const size_t entryCount = git_index_entrycount(index.get());
    REQUIRE(entryCount > 0);
    for (size_t i = 0; i < entryCount; ++i) {
        const git_index_entry* entry = git_index_get_byindex(index.get(), i);
        REQUIRE(entry != nullptr);
        QFile file(repoDir.filePath(QString::fromUtf8(entry->path)));
        REQUIRE(file.open(QFile::ReadWrite));
        REQUIRE(file.setFileTime(time, QFileDevice::FileModificationTime));
    }
}

size_t TestUtilities::statusOidCalculations(const QDir& repoDir)
{
    const auto repo = openRepository(repoDir);

    git_status_options opt = GIT_STATUS_OPTIONS_INIT;
    opt.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
    opt.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS;

    git_status_list* list = nullptr;
    REQUIRE(git_status_list_new(&list, repo.get(), &opt) == GIT_OK);
    auto listGuard = qScopeGuard([list]() { git_status_list_free(list); });

    git_diff_perfdata perf = GIT_DIFF_PERFDATA_INIT;
    REQUIRE(git_status_list_get_perfdata(&perf, list) == GIT_OK);
    return perf.oid_calculations;
}
