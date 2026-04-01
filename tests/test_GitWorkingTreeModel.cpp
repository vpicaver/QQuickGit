//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "GitWorkingTreeModel.h"
#include "GitRepository.h"
#include "Account.h"

//Async includes
#include "asyncfuture.h"

//Qt includes
#include <QTemporaryDir>
#include <QDir>
#include <QSignalSpy>
#include <QFile>
#include <QAbstractItemModel>
#include <QTest>

//libgit2
#include "git2.h"

using namespace QQuickGit;

namespace {

void createFileAndCommit(GitRepository& repo, const QString& filename,
                         const QString& content, const QString& message)
{
    QDir dir = repo.directory();
    QFile file(dir.filePath(filename));
    REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate | QFile::Text));
    file.write(content.toUtf8());
    file.close();

    repo.checkStatus();

    Account account;
    account.setName("Test");
    account.setEmail("test@test.com");
    repo.setAccount(&account);
    repo.commitAll(message, QString());
    repo.checkStatus();
}

void waitForLoading(GitWorkingTreeModel& model)
{
    if (!model.loading())
        return;
    QSignalSpy loadingSpy(&model, &GitWorkingTreeModel::loadingChanged);
    REQUIRE(loadingSpy.wait(5000));
}

void writeFile(const QDir& dir, const QString& filename, const QString& content)
{
    QFile file(dir.filePath(filename));
    REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate | QFile::Text));
    file.write(content.toUtf8());
    file.close();
}

} // anonymous namespace

TEST_CASE("GitWorkingTreeModel basic functionality", "[GitWorkingTreeModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    SECTION("Clean repo has zero rows")
    {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        GitWorkingTreeModel model;
        model.setRepository(&repo);
        waitForLoading(model);

        CHECK(model.rowCount() == 0);
        CHECK(model.errorMessage().isEmpty());
    }

    SECTION("Modified file produces one row with correct status")
    {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        writeFile(repo.directory(), "file1.txt", "hello world");
        repo.checkStatus();

        GitWorkingTreeModel model;
        model.setRepository(&repo);
        waitForLoading(model);

        REQUIRE(model.rowCount() == 1);

        QModelIndex idx = model.index(0, 0);
        CHECK(model.data(idx, GitWorkingTreeModel::FilePathRole).toString() == "file1.txt");
        CHECK(model.data(idx, GitWorkingTreeModel::StatusRole).toInt() == GIT_DELTA_MODIFIED);
        CHECK(model.data(idx, GitWorkingTreeModel::StatusTextRole).toString() == "Modified");
        CHECK(model.data(idx, GitWorkingTreeModel::LineStatsFetchedRole).toBool() == false);
        CHECK(model.data(idx, GitWorkingTreeModel::AddedLinesRole).toInt() == -1);
        CHECK(model.data(idx, GitWorkingTreeModel::DeletedLinesRole).toInt() == -1);
    }

    SECTION("Untracked file shows as Added")
    {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        writeFile(repo.directory(), "newfile.txt", "new content");
        repo.checkStatus();

        GitWorkingTreeModel model;
        model.setRepository(&repo);
        waitForLoading(model);

        REQUIRE(model.rowCount() == 1);

        QModelIndex idx = model.index(0, 0);
        CHECK(model.data(idx, GitWorkingTreeModel::FilePathRole).toString() == "newfile.txt");
        CHECK(model.data(idx, GitWorkingTreeModel::StatusRole).toInt() == GIT_DELTA_ADDED);
        CHECK(model.data(idx, GitWorkingTreeModel::StatusTextRole).toString() == "Added");
    }

    SECTION("Deleted file shows as Deleted")
    {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        QFile::remove(repo.directory().filePath("file1.txt"));
        repo.checkStatus();

        GitWorkingTreeModel model;
        model.setRepository(&repo);
        waitForLoading(model);

        REQUIRE(model.rowCount() == 1);

        QModelIndex idx = model.index(0, 0);
        CHECK(model.data(idx, GitWorkingTreeModel::FilePathRole).toString() == "file1.txt");
        CHECK(model.data(idx, GitWorkingTreeModel::StatusRole).toInt() == GIT_DELTA_DELETED);
        CHECK(model.data(idx, GitWorkingTreeModel::StatusTextRole).toString() == "Deleted");
    }

    SECTION("Multiple dirty files produce correct row count")
    {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        writeFile(repo.directory(), "file1.txt", "modified");
        writeFile(repo.directory(), "file2.txt", "new file");
        writeFile(repo.directory(), "file3.txt", "another new file");
        repo.checkStatus();

        GitWorkingTreeModel model;
        model.setRepository(&repo);
        waitForLoading(model);

        CHECK(model.rowCount() == 3);
    }

    SECTION("Refreshes when modifiedFileCountChanged fires")
    {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        GitWorkingTreeModel model;
        model.setRepository(&repo);
        waitForLoading(model);

        CHECK(model.rowCount() == 0);

        // Modify a file and trigger checkStatus
        writeFile(repo.directory(), "file1.txt", "modified");
        repo.checkStatus(); // Emits modifiedFileCountChanged, which triggers refresh

        waitForLoading(model);

        CHECK(model.rowCount() == 1);
    }

    SECTION("fetchLineStats populates line counts")
    {
        createFileAndCommit(repo, "file1.txt", "line1\nline2\nline3\n", "Initial commit");

        writeFile(repo.directory(), "file1.txt", "line1\nmodified\nline3\nnew line\n");
        repo.checkStatus();

        GitWorkingTreeModel model;
        model.setRepository(&repo);
        waitForLoading(model);

        REQUIRE(model.rowCount() == 1);

        QModelIndex idx = model.index(0, 0);
        CHECK(model.data(idx, GitWorkingTreeModel::LineStatsFetchedRole).toBool() == false);

        QSignalSpy dataChangedSpy(&model, &QAbstractItemModel::dataChanged);
        model.fetchLineStats(0);
        REQUIRE(dataChangedSpy.wait(5000));

        CHECK(model.data(idx, GitWorkingTreeModel::LineStatsFetchedRole).toBool() == true);
        CHECK(model.data(idx, GitWorkingTreeModel::AddedLinesRole).toInt() >= 0);
        CHECK(model.data(idx, GitWorkingTreeModel::DeletedLinesRole).toInt() >= 0);
    }

    SECTION("fetchLineStats for already-fetched row is a no-op")
    {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        writeFile(repo.directory(), "file1.txt", "modified");
        repo.checkStatus();

        GitWorkingTreeModel model;
        model.setRepository(&repo);
        waitForLoading(model);

        REQUIRE(model.rowCount() == 1);

        // Fetch once
        QSignalSpy dataChangedSpy(&model, &QAbstractItemModel::dataChanged);
        model.fetchLineStats(0);
        REQUIRE(dataChangedSpy.wait(5000));

        // Second call should be a no-op
        dataChangedSpy.clear();
        model.fetchLineStats(0);

        // Give it a moment - should NOT emit dataChanged again
        QTest::qWait(100);
        CHECK(dataChangedSpy.count() == 0);
    }

    SECTION("Refresh cancels outstanding line stats futures")
    {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        writeFile(repo.directory(), "file1.txt", "modified");
        repo.checkStatus();

        GitWorkingTreeModel model;
        model.setRepository(&repo);
        waitForLoading(model);

        REQUIRE(model.rowCount() == 1);

        // Start a line stats fetch
        model.fetchLineStats(0);

        // Immediately trigger a refresh (which should cancel line stats futures)
        writeFile(repo.directory(), "file2.txt", "new");
        repo.checkStatus();

        waitForLoading(model);

        // After refresh, the old line stats should be gone (new rows don't have them)
        CHECK(model.rowCount() == 2);
        QModelIndex idx = model.index(0, 0);
        CHECK(model.data(idx, GitWorkingTreeModel::LineStatsFetchedRole).toBool() == false);
    }

    SECTION("Role names are correct")
    {
        GitWorkingTreeModel model;
        auto roles = model.roleNames();

        CHECK(roles.contains(GitWorkingTreeModel::FilePathRole));
        CHECK(roles.contains(GitWorkingTreeModel::OldFilePathRole));
        CHECK(roles.contains(GitWorkingTreeModel::StatusRole));
        CHECK(roles.contains(GitWorkingTreeModel::StatusTextRole));
        CHECK(roles.contains(GitWorkingTreeModel::IsBinaryRole));
        CHECK(roles.contains(GitWorkingTreeModel::IsImageRole));
        CHECK(roles.contains(GitWorkingTreeModel::AddedLinesRole));
        CHECK(roles.contains(GitWorkingTreeModel::DeletedLinesRole));
        CHECK(roles.contains(GitWorkingTreeModel::LineStatsFetchedRole));

        CHECK(roles[GitWorkingTreeModel::FilePathRole] == "filePath");
        CHECK(roles[GitWorkingTreeModel::StatusTextRole] == "statusText");
        CHECK(roles[GitWorkingTreeModel::AddedLinesRole] == "addedLines");
    }

    SECTION("Invalid row indices return empty data")
    {
        GitWorkingTreeModel model;

        CHECK(!model.data(model.index(-1, 0), GitWorkingTreeModel::FilePathRole).isValid());
        CHECK(!model.data(model.index(0, 0), GitWorkingTreeModel::FilePathRole).isValid());
        CHECK(!model.data(model.index(100, 0), GitWorkingTreeModel::FilePathRole).isValid());
    }

    SECTION("Setting null repository clears model")
    {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        writeFile(repo.directory(), "file1.txt", "modified");
        repo.checkStatus();

        GitWorkingTreeModel model;
        model.setRepository(&repo);
        waitForLoading(model);

        REQUIRE(model.rowCount() == 1);

        model.setRepository(nullptr);
        CHECK(model.rowCount() == 0);
    }

    SECTION("Uses incremental insert/remove, not modelReset")
    {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        writeFile(repo.directory(), "file1.txt", "modified");
        repo.checkStatus();

        GitWorkingTreeModel model;

        QSignalSpy insertSpy(&model, &QAbstractItemModel::rowsInserted);
        QSignalSpy resetSpy(&model, &QAbstractItemModel::modelReset);

        model.setRepository(&repo);
        waitForLoading(model);

        CHECK(insertSpy.count() >= 1);
        CHECK(resetSpy.count() == 0);
    }
}
