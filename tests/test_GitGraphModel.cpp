//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "Account.h"
#include "TestUtilities.h"
#include "GitGraphModel.h"
#include "GitRepository.h"

//Async includes
#include "asyncfuture.h"

//Qt includes
#include <QTemporaryDir>
#include <QDir>
#include <QFile>
#include <QSignalSpy>
#include <QAbstractItemModel>

//libgit2
#include "git2.h"

using namespace QQuickGit;

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
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 1);

        QModelIndex idx = model.index(0, 0);
        CHECK(!model.data(idx, GitGraphModel::ShaRole).toString().isEmpty());
        CHECK(model.data(idx, GitGraphModel::MessageRole).toString() == "Initial commit");
        CHECK(model.data(idx, GitGraphModel::AuthorRole).toString() == "Test Author");
        CHECK(model.data(idx, GitGraphModel::TimestampRole).toDateTime().isValid());

        auto lanes = model.data(idx, GitGraphModel::LanesRole).value<QList<int>>();
        CHECK(lanes.size() >= 1);

        CHECK(model.data(idx, GitGraphModel::ActiveLaneRole).toInt() == 0);
        CHECK(model.data(idx, GitGraphModel::IsHeadRole).toBool() == true);
    }

    SECTION("Multiple commits produces correct rowCount") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Commit 1");
        TestUtilities::createFileAndCommit(repo, "file2.txt", "world", "Commit 2");
        TestUtilities::createFileAndCommit(repo, "file3.txt", "foo", "Commit 3");

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 3);

        QModelIndex idx = model.index(0, 0);
        CHECK(model.data(idx, GitGraphModel::MessageRole).toString() == "Commit 3");
        CHECK(model.data(idx, GitGraphModel::IsHeadRole).toBool() == true);
        CHECK(model.data(model.index(1, 0), GitGraphModel::IsHeadRole).toBool() == false);
        CHECK(model.data(model.index(2, 0), GitGraphModel::IsHeadRole).toBool() == false);
    }

    SECTION("Uses beginInsertRows, not modelReset") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Commit 1");

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
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Commit 1");

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 1);

        TestUtilities::createFileAndCommit(repo, "file2.txt", "world", "Commit 2");
        model.refresh();

        loadingSpy.clear();
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 2);

        QModelIndex idx = model.index(0, 0);
        CHECK(model.data(idx, GitGraphModel::MessageRole).toString() == "Commit 2");
    }

    SECTION("Ref labels are populated") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial");

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
        CHECK(roles.contains(GitGraphModel::IsHeadRole));
        CHECK(roles[GitGraphModel::IsHeadRole] == "isHead");
    }

    SECTION("Symbolic refs like origin/HEAD are excluded from ref labels") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial");

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
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Commit 1");

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
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

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
        CHECK(model.data(idx0, GitGraphModel::IsHeadRole).toBool() == false);

        // Real commit at index 1
        auto idx1 = model.index(1);
        CHECK(!model.data(idx1, GitGraphModel::ShaRole).toString().isEmpty());
        CHECK(model.data(idx1, GitGraphModel::MessageRole).toString() == "Initial commit");
        CHECK(model.data(idx1, GitGraphModel::AuthorRole).toString() == "Test Author");
    }

    SECTION("Clean repo has no synthetic row") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

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
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

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

    SECTION("Model auto-refreshes after commitAll") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 1);

        // Dirty the repo and commit via the repository
        QDir dir = repo.directory();
        {
            QFile file(dir.filePath("file2.txt"));
            REQUIRE(file.open(QFile::WriteOnly | QFile::Text));
            file.write("new content");
        }

        Account account;
        account.setName("Test");
        account.setEmail("test@test.com");
        repo.setAccount(&account);
        repo.commitAll("Second commit", QString());

        // The model should auto-refresh without an explicit refresh() call.
        // Wait for any async loading to complete.
        loadingSpy.clear();
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 2);
        CHECK(model.data(model.index(0), GitGraphModel::MessageRole).toString() == "Second commit");
    }

    SECTION("Model auto-refreshes after pull brings new commits") {
        // Set up a bare repo as a local remote
        QTemporaryDir bareDir;
        REQUIRE(bareDir.isValid());

        git_repository* bareRepo = nullptr;
        REQUIRE(git_repository_init(&bareRepo, bareDir.path().toLocal8Bit().constData(), true) == GIT_OK);
        git_repository_free(bareRepo);

        // Add the bare repo as origin and push the initial commit
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");
        repo.addRemote("origin", QUrl::fromLocalFile(bareDir.path()));

        auto pushFuture = repo.push();
        REQUIRE(AsyncFuture::waitForFinished(pushFuture, 10000));
        REQUIRE(!pushFuture.result().hasError());

        // Clone into a second working copy and add a new commit there
        QTemporaryDir clone2Dir;
        REQUIRE(clone2Dir.isValid());
        QDir clone2Path(clone2Dir.path() + "/repo2");

        GitRepository repo2;
        repo2.setDirectory(clone2Path);
        auto cloneFuture = repo2.clone(QUrl::fromLocalFile(bareDir.path()));
        REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 10000));
        REQUIRE(!cloneFuture.result().hasError());

        repo2.initRepository();
        TestUtilities::createFileAndCommit(repo2, "file2.txt", "from clone2", "Clone2 commit");

        auto push2Future = repo2.push();
        REQUIRE(AsyncFuture::waitForFinished(push2Future, 10000));
        REQUIRE(!push2Future.result().hasError());

        // Now set up the model on the original repo and verify initial state
        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 1);

        // Pull new commits from the bare remote
        auto pullFuture = repo.pull();
        REQUIRE(AsyncFuture::waitForFinished(pullFuture, 10000));
        REQUIRE(!pullFuture.result().hasError());

        // The model should auto-refresh without an explicit refresh() call.
        loadingSpy.clear();
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.rowCount() == 2);
    }

    SECTION("Synthetic row disappears after commitAll without explicit checkStatus") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        // Dirty the repo so the synthetic row appears
        QDir dir = repo.directory();
        {
            QFile file(dir.filePath("dirty.txt"));
            REQUIRE(file.open(QFile::WriteOnly | QFile::Text));
            file.write("uncommitted");
        }
        repo.checkStatus();
        REQUIRE(repo.modifiedFileCount() > 0);

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        // Synthetic row + 1 real commit
        CHECK(model.rowCount() == 2);
        CHECK(model.hasUncommittedChanges());

        // Commit all changes — refsChanged should trigger checkStatusAsync
        // automatically, removing the synthetic row without an explicit checkStatus call.
        Account account;
        account.setName("Test");
        account.setEmail("test@test.com");
        repo.setAccount(&account);
        repo.commitAll("Commit dirty", QString());

        // Wait for the async status check and model refresh to complete
        QSignalSpy modifiedSpy(&repo, &GitRepository::modifiedFileCountChanged);
        if (repo.modifiedFileCount() > 0)
            REQUIRE(modifiedSpy.wait(5000));

        loadingSpy.clear();
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK_FALSE(model.hasUncommittedChanges());
        CHECK(model.rowCount() == 2); // 2 real commits now, no synthetic row
    }

    SECTION("Synthetic row mirrors HEAD commit lane data") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

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
