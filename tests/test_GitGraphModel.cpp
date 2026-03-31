//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "GitGraphModel.h"
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

} // anonymous namespace

TEST_CASE("GitGraphModel basic functionality", "[GitGraphModel]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    SECTION("Empty repository has zero rows") {
        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 0);
    }

    SECTION("Single commit produces one row") {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 1);

        QModelIndex idx = model.index(0, 0);
        CHECK(!model.data(idx, GitGraphModel::ShaRole).toString().isEmpty());
        CHECK(model.data(idx, GitGraphModel::MessageRole).toString() == "Initial commit");
        CHECK(model.data(idx, GitGraphModel::AuthorRole).toString() == "Test");
        CHECK(model.data(idx, GitGraphModel::TimestampRole).toDateTime().isValid());

        auto lanes = model.data(idx, GitGraphModel::LanesRole).value<QList<int>>();
        CHECK(lanes.size() >= 1);

        CHECK(model.data(idx, GitGraphModel::ActiveLaneRole).toInt() == 0);
    }

    SECTION("Multiple commits produces correct rowCount") {
        createFileAndCommit(repo, "file1.txt", "hello", "Commit 1");
        createFileAndCommit(repo, "file2.txt", "world", "Commit 2");
        createFileAndCommit(repo, "file3.txt", "foo", "Commit 3");

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 3);

        QModelIndex idx = model.index(0, 0);
        CHECK(model.data(idx, GitGraphModel::MessageRole).toString() == "Commit 3");
    }

    SECTION("Uses beginInsertRows, not modelReset") {
        createFileAndCommit(repo, "file1.txt", "hello", "Commit 1");

        GitGraphModel model;

        QSignalSpy insertSpy(&model, &QAbstractItemModel::rowsInserted);
        QSignalSpy resetSpy(&model, &QAbstractItemModel::modelReset);

        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(insertSpy.count() >= 1);
        CHECK(resetSpy.count() == 0);
    }

    SECTION("Refresh after new commit adds new row") {
        createFileAndCommit(repo, "file1.txt", "hello", "Commit 1");

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 1);

        createFileAndCommit(repo, "file2.txt", "world", "Commit 2");
        model.refresh();

        loadingSpy.clear();
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 2);

        QModelIndex idx = model.index(0, 0);
        CHECK(model.data(idx, GitGraphModel::MessageRole).toString() == "Commit 2");
    }

    SECTION("Ref labels are populated") {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial");

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        REQUIRE(model.rowCount() == 1);

        QModelIndex idx = model.index(0, 0);
        auto refs = model.data(idx, GitGraphModel::RefsRole).toStringList();

        bool hasMainRef = false;
        for (const auto& ref : refs)
        {
            if (ref == "main" || ref == "master")
                hasMainRef = true;
        }
        CHECK(hasMainRef);
    }

    SECTION("Role names are correct") {
        GitGraphModel model;
        auto roles = model.roleNames();

        CHECK(roles.contains(GitGraphModel::ShaRole));
        CHECK(roles.contains(GitGraphModel::MessageRole));
        CHECK(roles.contains(GitGraphModel::AuthorRole));
        CHECK(roles.contains(GitGraphModel::TimestampRole));
        CHECK(roles.contains(GitGraphModel::LanesRole));
        CHECK(roles.contains(GitGraphModel::ActiveLaneRole));
        CHECK(roles.contains(GitGraphModel::RefsRole));

        CHECK(roles[GitGraphModel::ShaRole] == "sha");
        CHECK(roles[GitGraphModel::MessageRole] == "message");
        CHECK(roles[GitGraphModel::LanesRole] == "lanes");
    }

    SECTION("Symbolic refs like origin/HEAD are excluded from ref labels") {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial");

        // Create origin/main (direct ref) and origin/HEAD (symbolic ref) using libgit2
        git_repository* rawRepo = nullptr;
        REQUIRE(git_repository_open(&rawRepo, tempDir.path().toLocal8Bit().constData()) == GIT_OK);
        std::unique_ptr<git_repository, decltype(&git_repository_free)>
            repoHolder(rawRepo, &git_repository_free);

        git_reference* headRef = nullptr;
        REQUIRE(git_repository_head(&headRef, rawRepo) == GIT_OK);
        const git_oid* headOid = git_reference_target(headRef);
        REQUIRE(headOid != nullptr);

        git_reference* originMain = nullptr;
        git_reference_create(&originMain, rawRepo, "refs/remotes/origin/main", headOid, 1, nullptr);
        if (originMain) git_reference_free(originMain);

        git_reference* originHead = nullptr;
        git_reference_symbolic_create(&originHead, rawRepo, "refs/remotes/origin/HEAD",
                                      "refs/remotes/origin/main", 1, nullptr);
        if (originHead) git_reference_free(originHead);
        git_reference_free(headRef);

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        REQUIRE(model.rowCount() == 1);
        auto refs = model.data(model.index(0, 0), GitGraphModel::RefsRole).toStringList();

        CHECK(refs.contains("origin/main"));
        CHECK_FALSE(refs.contains("origin/HEAD"));
    }

    SECTION("Setting null repository clears model") {
        createFileAndCommit(repo, "file1.txt", "hello", "Commit 1");

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 1);

        model.setRepository(nullptr);
        CHECK(model.rowCount() == 0);
    }

    SECTION("Dirty repo shows synthetic Uncommitted Changes row at index 0") {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        // Create an uncommitted file to make the repo dirty
        QDir dir = repo.directory();
        QFile dirtyFile(dir.filePath("dirty.txt"));
        REQUIRE(dirtyFile.open(QFile::WriteOnly | QFile::Text));
        dirtyFile.write("uncommitted");
        dirtyFile.close();
        repo.checkStatus();
        REQUIRE(repo.modifiedFileCount() > 0);

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        // Should have synthetic row + 1 real commit
        CHECK(model.rowCount() == 2);
        CHECK(model.hasUncommittedChanges());

        // Synthetic row at index 0 has empty SHA
        auto idx0 = model.index(0);
        CHECK(model.data(idx0, GitGraphModel::ShaRole).toString().isEmpty());
        CHECK(model.data(idx0, GitGraphModel::MessageRole).toString() == "Uncommitted Changes");
        CHECK(model.data(idx0, GitGraphModel::AuthorRole).toString().isEmpty());
        CHECK(model.data(idx0, GitGraphModel::RefsRole).toStringList().isEmpty());

        // Real commit at index 1
        auto idx1 = model.index(1);
        CHECK(!model.data(idx1, GitGraphModel::ShaRole).toString().isEmpty());
        CHECK(model.data(idx1, GitGraphModel::MessageRole).toString() == "Initial commit");
        CHECK(model.data(idx1, GitGraphModel::AuthorRole).toString() == "Test");
    }

    SECTION("Clean repo has no synthetic row") {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        CHECK(repo.modifiedFileCount() == 0);

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 1);
        CHECK_FALSE(model.hasUncommittedChanges());

        // First row is the real commit, not synthetic
        auto idx0 = model.index(0);
        CHECK(!model.data(idx0, GitGraphModel::ShaRole).toString().isEmpty());
    }

    SECTION("Synthetic row appears and disappears with modifiedFileCount transitions") {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 1);
        CHECK_FALSE(model.hasUncommittedChanges());

        QSignalSpy rowsInsertedSpy(&model, &GitGraphModel::rowsInserted);
        QSignalSpy rowsRemovedSpy(&model, &GitGraphModel::rowsRemoved);
        QSignalSpy uncommittedSpy(&model, &GitGraphModel::hasUncommittedChangesChanged);

        // Dirty the repo — synthetic row should be inserted
        QDir dir = repo.directory();
        QFile dirtyFile(dir.filePath("dirty.txt"));
        REQUIRE(dirtyFile.open(QFile::WriteOnly | QFile::Text));
        dirtyFile.write("uncommitted");
        dirtyFile.close();
        repo.checkStatus();

        CHECK(model.rowCount() == 2);
        CHECK(model.hasUncommittedChanges());
        CHECK(rowsInsertedSpy.count() == 1);
        CHECK(uncommittedSpy.count() == 1);

        // Verify incremental insert at row 0
        auto insertArgs = rowsInsertedSpy.takeFirst();
        CHECK(insertArgs.at(1).toInt() == 0); // first
        CHECK(insertArgs.at(2).toInt() == 0); // last

        // Commit all changes — synthetic row should be removed
        Account account;
        account.setName("Test");
        account.setEmail("test@test.com");
        repo.setAccount(&account);
        repo.commitAll("Commit dirty file", QString());
        repo.checkStatus();

        // After refresh completes, wait for loading to finish
        loadingSpy.clear();
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK_FALSE(model.hasUncommittedChanges());
    }

    SECTION("Synthetic row mirrors HEAD commit lane data") {
        createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        // Dirty the repo
        QDir dir = repo.directory();
        QFile dirtyFile(dir.filePath("dirty.txt"));
        REQUIRE(dirtyFile.open(QFile::WriteOnly | QFile::Text));
        dirtyFile.write("uncommitted");
        dirtyFile.close();
        repo.checkStatus();

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        REQUIRE(model.rowCount() >= 2);

        // Synthetic row lanes should match HEAD commit lanes
        auto syntheticLanes = model.data(model.index(0), GitGraphModel::LanesRole).value<QList<int>>();
        auto headLanes = model.data(model.index(1), GitGraphModel::LanesRole).value<QList<int>>();
        CHECK(syntheticLanes == headLanes);

        auto syntheticActiveLane = model.data(model.index(0), GitGraphModel::ActiveLaneRole).toInt();
        auto headActiveLane = model.data(model.index(1), GitGraphModel::ActiveLaneRole).toInt();
        CHECK(syntheticActiveLane == headActiveLane);
    }
}
