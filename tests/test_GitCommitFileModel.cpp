//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "TestUtilities.h"
#include "GitCommitFileModel.h"
#include "GitCommitInfo.h"
#include "GitRepository.h"

//Qt includes
#include <QTemporaryDir>
#include <QDir>
#include <QSignalSpy>
#include <QFile>
#include <QAbstractItemModel>

//libgit2
#include "git2.h"

using namespace QQuickGit;

namespace {

void waitForLoading(GitCommitInfo& info)
{
    if (!info.loading())
    {
        return;
    }
    QSignalSpy spy(&info, &GitCommitInfo::loadingChanged);
    REQUIRE(spy.wait(5000));
}

} // anonymous namespace

TEST_CASE("GitCommitFileModel populates from fileListReady", "[GitCommitFileModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial");
    TestUtilities::createFileAndCommit(repo, "file1.txt", "modified", "Change");
    QString sha = TestUtilities::getHeadSha(repo.directory());

    GitCommitInfo info;
    info.setRepository(&repo);

    GitCommitFileModel model;
    model.setCommitInfo(&info);

    info.setCommitSha(sha);
    waitForLoading(info);

    REQUIRE(model.rowCount() == 1);

    QModelIndex idx = model.index(0);
    CHECK(model.data(idx, GitCommitFileModel::FilePathRole).toString() == "file1.txt");
    CHECK(model.data(idx, GitCommitFileModel::StatusTextRole).toString() == "Modified");
    CHECK(model.data(idx, GitCommitFileModel::IsBinaryRole).toBool() == false);
    CHECK(model.data(idx, GitCommitFileModel::AddedLinesRole).toInt() == -1);
    CHECK(model.data(idx, GitCommitFileModel::LineStatsFetchedRole).toBool() == false);
}

TEST_CASE("GitCommitFileModel shows correct status for added files", "[GitCommitFileModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial");
    QString sha = TestUtilities::getHeadSha(repo.directory());

    GitCommitInfo info;
    info.setRepository(&repo);

    GitCommitFileModel model;
    model.setCommitInfo(&info);

    info.setCommitSha(sha);
    waitForLoading(info);

    REQUIRE(model.rowCount() == 1);

    QModelIndex idx = model.index(0);
    CHECK(model.data(idx, GitCommitFileModel::StatusTextRole).toString() == "Added");
}

TEST_CASE("GitCommitFileModel shows correct status for deleted files", "[GitCommitFileModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Add file");
    TestUtilities::deleteFileAndCommit(repo, "file1.txt", "Delete file");
    QString sha = TestUtilities::getHeadSha(repo.directory());

    GitCommitInfo info;
    info.setRepository(&repo);

    GitCommitFileModel model;
    model.setCommitInfo(&info);

    info.setCommitSha(sha);
    waitForLoading(info);

    REQUIRE(model.rowCount() == 1);

    QModelIndex idx = model.index(0);
    CHECK(model.data(idx, GitCommitFileModel::StatusTextRole).toString() == "Deleted");
    CHECK(model.data(idx, GitCommitFileModel::FilePathRole).toString() == "file1.txt");
}

TEST_CASE("GitCommitFileModel fetchLineStats updates via dataChanged", "[GitCommitFileModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    TestUtilities::createFileAndCommit(repo, "file1.txt", "line1\nline2\nline3\n", "Initial");
    TestUtilities::createFileAndCommit(repo, "file1.txt", "line1\nmodified\nline3\nnew line\n", "Change");
    QString sha = TestUtilities::getHeadSha(repo.directory());

    GitCommitInfo info;
    info.setRepository(&repo);

    GitCommitFileModel model;
    model.setCommitInfo(&info);

    info.setCommitSha(sha);
    waitForLoading(info);

    REQUIRE(model.rowCount() == 1);

    QSignalSpy dataChangedSpy(&model, &QAbstractItemModel::dataChanged);
    model.fetchLineStats(0);

    REQUIRE(dataChangedSpy.wait(5000));

    QModelIndex idx = model.index(0);
    CHECK(model.data(idx, GitCommitFileModel::LineStatsFetchedRole).toBool() == true);
    CHECK(model.data(idx, GitCommitFileModel::AddedLinesRole).toInt() >= 0);
    CHECK(model.data(idx, GitCommitFileModel::DeletedLinesRole).toInt() >= 0);
}

TEST_CASE("GitCommitFileModel fetchLineStats returns correct counts", "[GitCommitFileModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    // 3 lines initially
    TestUtilities::createFileAndCommit(repo, "file1.txt", "aaa\nbbb\nccc\n", "Initial");
    // Replace 1 line, add 2 lines → 1 deleted, 3 added
    TestUtilities::createFileAndCommit(repo, "file1.txt", "aaa\nBBB\nccc\nDDD\nEEE\n", "Change");
    QString sha = TestUtilities::getHeadSha(repo.directory());

    GitCommitInfo info;
    info.setRepository(&repo);

    GitCommitFileModel model;
    model.setCommitInfo(&info);

    info.setCommitSha(sha);
    waitForLoading(info);

    REQUIRE(model.rowCount() == 1);

    QSignalSpy dataChangedSpy(&model, &QAbstractItemModel::dataChanged);
    model.fetchLineStats(0);
    REQUIRE(dataChangedSpy.wait(5000));

    QModelIndex idx = model.index(0);
    CHECK(model.data(idx, GitCommitFileModel::AddedLinesRole).toInt() == 3);
    CHECK(model.data(idx, GitCommitFileModel::DeletedLinesRole).toInt() == 1);
}

TEST_CASE("GitCommitFileModel cached re-fetch is immediate", "[GitCommitFileModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial");
    TestUtilities::createFileAndCommit(repo, "file1.txt", "modified", "Change");
    QString sha = TestUtilities::getHeadSha(repo.directory());

    GitCommitInfo info;
    info.setRepository(&repo);

    GitCommitFileModel model;
    model.setCommitInfo(&info);

    info.setCommitSha(sha);
    waitForLoading(info);

    QSignalSpy dataChangedSpy(&model, &QAbstractItemModel::dataChanged);
    model.fetchLineStats(0);
    REQUIRE(dataChangedSpy.wait(5000));

    int prevCount = dataChangedSpy.count();
    model.fetchLineStats(0);
    CHECK(dataChangedSpy.count() == prevCount);
}

TEST_CASE("GitCommitFileModel SHA change resets model and clears line stats cache", "[GitCommitFileModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "First");
    QString sha1 = TestUtilities::getHeadSha(repo.directory());
    TestUtilities::createFileAndCommit(repo, "file2.txt", "world", "Second");
    QString sha2 = TestUtilities::getHeadSha(repo.directory());

    GitCommitInfo info;
    info.setRepository(&repo);

    GitCommitFileModel model;
    model.setCommitInfo(&info);

    info.setCommitSha(sha1);
    waitForLoading(info);

    // Fetch line stats for first commit
    QSignalSpy dataChangedSpy(&model, &QAbstractItemModel::dataChanged);
    model.fetchLineStats(0);
    REQUIRE(dataChangedSpy.wait(5000));
    CHECK(model.data(model.index(0), GitCommitFileModel::LineStatsFetchedRole).toBool() == true);

    // Switch to second commit
    QSignalSpy resetSpy(&model, &QAbstractItemModel::modelReset);
    info.setCommitSha(sha2);
    waitForLoading(info);

    CHECK(resetSpy.count() >= 1);
    CHECK(model.rowCount() >= 1);
    // Line stats cache should be cleared after reset
    CHECK(model.data(model.index(0), GitCommitFileModel::LineStatsFetchedRole).toBool() == false);
    CHECK(model.data(model.index(0), GitCommitFileModel::AddedLinesRole).toInt() == -1);
}

TEST_CASE("GitCommitFileModel empty commit has 0 rows", "[GitCommitFileModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial");

    // Create empty commit using libgit2 directly
    QDir dir = repo.directory();
    git_repository* rawRepo = nullptr;
    REQUIRE(git_repository_open(&rawRepo, dir.absolutePath().toLocal8Bit().constData()) == GIT_OK);
    std::unique_ptr<git_repository, decltype(&git_repository_free)>
        repoHolder(rawRepo, &git_repository_free);

    git_reference* headRef = nullptr;
    REQUIRE(git_repository_head(&headRef, rawRepo) == GIT_OK);
    std::unique_ptr<git_reference, decltype(&git_reference_free)>
        refHolder(headRef, &git_reference_free);

    git_commit* parentCommit = nullptr;
    REQUIRE(git_commit_lookup(&parentCommit, rawRepo, git_reference_target(headRef)) == GIT_OK);
    std::unique_ptr<git_commit, decltype(&git_commit_free)>
        parentHolder(parentCommit, &git_commit_free);

    git_tree* tree = nullptr;
    REQUIRE(git_commit_tree(&tree, parentCommit) == GIT_OK);
    std::unique_ptr<git_tree, decltype(&git_tree_free)>
        treeHolder(tree, &git_tree_free);

    git_signature* sig = nullptr;
    REQUIRE(git_signature_now(&sig, "Test", "test@test.com") == GIT_OK);
    std::unique_ptr<git_signature, decltype(&git_signature_free)>
        sigHolder(sig, &git_signature_free);

    git_oid emptyCommitOid;
    const git_commit* parents[] = { parentCommit };
    REQUIRE(git_commit_create(&emptyCommitOid, rawRepo, "HEAD", sig, sig,
                               nullptr, "Empty commit", tree, 1, parents) == GIT_OK);

    char shaBuffer[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(shaBuffer, sizeof(shaBuffer), &emptyCommitOid);
    QString emptySha = QString::fromLatin1(shaBuffer);

    GitCommitInfo info;
    info.setRepository(&repo);

    GitCommitFileModel model;
    model.setCommitInfo(&info);

    info.setCommitSha(emptySha);
    waitForLoading(info);

    CHECK(model.rowCount() == 0);
}

TEST_CASE("GitCommitFileModel role names are correct", "[GitCommitFileModel]")
{
    GitCommitFileModel model;
    auto roles = model.roleNames();

    CHECK(roles.contains(GitCommitFileModel::FilePathRole));
    CHECK(roles[GitCommitFileModel::FilePathRole] == "filePath");
    CHECK(roles.contains(GitCommitFileModel::OldFilePathRole));
    CHECK(roles[GitCommitFileModel::OldFilePathRole] == "oldFilePath");
    CHECK(roles.contains(GitCommitFileModel::StatusRole));
    CHECK(roles[GitCommitFileModel::StatusRole] == "status");
    CHECK(roles.contains(GitCommitFileModel::StatusTextRole));
    CHECK(roles[GitCommitFileModel::StatusTextRole] == "statusText");
    CHECK(roles.contains(GitCommitFileModel::IsBinaryRole));
    CHECK(roles[GitCommitFileModel::IsBinaryRole] == "isBinary");
    CHECK(roles.contains(GitCommitFileModel::IsImageRole));
    CHECK(roles[GitCommitFileModel::IsImageRole] == "isImage");
    CHECK(roles.contains(GitCommitFileModel::AddedLinesRole));
    CHECK(roles[GitCommitFileModel::AddedLinesRole] == "addedLines");
    CHECK(roles.contains(GitCommitFileModel::DeletedLinesRole));
    CHECK(roles[GitCommitFileModel::DeletedLinesRole] == "deletedLines");
    CHECK(roles.contains(GitCommitFileModel::LineStatsFetchedRole));
    CHECK(roles[GitCommitFileModel::LineStatsFetchedRole] == "lineStatsFetched");
}

TEST_CASE("GitCommitFileModel delegates loading and errorMessage to commitInfo", "[GitCommitFileModel]")
{
    GitCommitFileModel model;

    SECTION("Without commitInfo, loading is false and errorMessage is empty") {
        CHECK(model.loading() == false);
        CHECK(model.errorMessage().isEmpty());
    }

    SECTION("Mirrors commitInfo loading state") {
        QTemporaryDir tempDir;
        REQUIRE(tempDir.isValid());

        GitRepository repo;
        repo.setDirectory(QDir(tempDir.path()));
        repo.initRepository();

        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitCommitInfo info;
        info.setRepository(&repo);
        model.setCommitInfo(&info);

        info.setCommitSha(sha);

        // After loading completes, model.loading() should be false
        waitForLoading(info);
        CHECK(model.loading() == false);
    }

    SECTION("Mirrors commitInfo errorMessage") {
        QTemporaryDir tempDir;
        REQUIRE(tempDir.isValid());

        GitRepository repo;
        repo.setDirectory(QDir(tempDir.path()));
        repo.initRepository();

        GitCommitInfo info;
        info.setRepository(&repo);
        model.setCommitInfo(&info);

        info.setCommitSha("0000000000000000000000000000000000000000");
        waitForLoading(info);

        CHECK(!model.errorMessage().isEmpty());
    }
}

TEST_CASE("GitCommitFileModel handles out-of-bounds fetchLineStats gracefully", "[GitCommitFileModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial");
    TestUtilities::createFileAndCommit(repo, "file1.txt", "modified", "Change");
    QString sha = TestUtilities::getHeadSha(repo.directory());

    GitCommitInfo info;
    info.setRepository(&repo);

    GitCommitFileModel model;
    model.setCommitInfo(&info);

    info.setCommitSha(sha);
    waitForLoading(info);

    REQUIRE(model.rowCount() == 1);

    // These should not crash
    model.fetchLineStats(-1);
    model.fetchLineStats(1);
    model.fetchLineStats(100);
}

TEST_CASE("GitCommitFileModel handles invalid index in data()", "[GitCommitFileModel]")
{
    GitCommitFileModel model;

    CHECK(!model.data(model.index(0), GitCommitFileModel::FilePathRole).isValid());
    CHECK(!model.data(model.index(-1), GitCommitFileModel::FilePathRole).isValid());
    CHECK(!model.data(QModelIndex(), GitCommitFileModel::FilePathRole).isValid());
}

TEST_CASE("GitCommitFileModel setting commitInfo to null clears connection", "[GitCommitFileModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial");
    TestUtilities::createFileAndCommit(repo, "file1.txt", "modified", "Change");
    QString sha = TestUtilities::getHeadSha(repo.directory());

    GitCommitInfo info;
    info.setRepository(&repo);

    GitCommitFileModel model;
    model.setCommitInfo(&info);

    info.setCommitSha(sha);
    waitForLoading(info);

    REQUIRE(model.rowCount() == 1);

    // Setting commitInfo to null should not crash
    QSignalSpy commitInfoSpy(&model, &GitCommitFileModel::commitInfoChanged);
    model.setCommitInfo(nullptr);
    CHECK(commitInfoSpy.count() == 1);
    CHECK(model.loading() == false);
    CHECK(model.errorMessage().isEmpty());

    // Model still holds old data (no fileListReady to clear it)
    CHECK(model.rowCount() == 1);
}

TEST_CASE("GitCommitFileModel multi-file commit shows all files", "[GitCommitFileModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    TestUtilities::createFileAndCommit(repo, "a.txt", "aaa", "First");
    TestUtilities::createFileAndCommit(repo, "b.txt", "bbb", "Second");

    // Modify a.txt, add c.txt, delete b.txt in one commit
    QDir dir = repo.directory();
    {
        QFile f(dir.filePath("a.txt"));
        REQUIRE(f.open(QFile::WriteOnly | QFile::Truncate | QFile::Text));
        f.write("modified");
        f.close();
    }
    {
        QFile f(dir.filePath("c.txt"));
        REQUIRE(f.open(QFile::WriteOnly | QFile::Text));
        f.write("new");
        f.close();
    }
    QFile::remove(dir.filePath("b.txt"));

    repo.checkStatus();
    Account account;
    account.setName("Test Author");
    account.setEmail("test@example.com");
    repo.setAccount(&account);
    repo.commitAll("Multi-file change", QString());

    QString sha = TestUtilities::getHeadSha(repo.directory());

    GitCommitInfo info;
    info.setRepository(&repo);

    GitCommitFileModel model;
    model.setCommitInfo(&info);

    info.setCommitSha(sha);
    waitForLoading(info);

    CHECK(model.rowCount() == 3);

    // Collect all statuses
    QStringList statuses;
    for (int i = 0; i < model.rowCount(); i++)
    {
        statuses << model.data(model.index(i), GitCommitFileModel::StatusTextRole).toString();
    }
    CHECK(statuses.contains("Modified"));
    CHECK(statuses.contains("Added"));
    CHECK(statuses.contains("Deleted"));
}
