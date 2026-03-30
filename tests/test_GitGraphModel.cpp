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
}
