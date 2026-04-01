//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "TestUtilities.h"
#include "GitGraphModel.h"
#include "GitRepository.h"

//Async includes
#include "asyncfuture.h"

//Qt includes
#include <QTemporaryDir>
#include <QDir>
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
}
