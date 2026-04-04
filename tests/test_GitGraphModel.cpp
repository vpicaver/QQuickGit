//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "Account.h"
#include "TestUtilities.h"
#include "GitGraphModel.h"
#include "GitRepository.h"
#include "GitLaneType.h"

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

namespace {

struct CommitResult {
    git_oid oid;
    QString sha;
};

QString oidStr(const git_oid* oid)
{
    char buf[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(buf, sizeof(buf), oid);
    return QString::fromLatin1(buf);
}

CommitResult createRawCommit(git_repository* repo,
                             const QString& message,
                             const QVector<git_oid>& parentOids,
                             const QString& branchRef = QStringLiteral("refs/heads/main"))
{
    git_oid blobOid;
    QByteArray content = message.toUtf8();
    REQUIRE(git_blob_create_from_buffer(&blobOid, repo, content.constData(), content.size()) == GIT_OK);

    git_treebuilder* tb = nullptr;
    REQUIRE(git_treebuilder_new(&tb, repo, nullptr) == GIT_OK);
    REQUIRE(git_treebuilder_insert(nullptr, tb, "file.txt", &blobOid, GIT_FILEMODE_BLOB) == GIT_OK);

    git_oid treeOid;
    REQUIRE(git_treebuilder_write(&treeOid, tb) == GIT_OK);
    git_treebuilder_free(tb);

    git_tree* tree = nullptr;
    REQUIRE(git_tree_lookup(&tree, repo, &treeOid) == GIT_OK);

    git_signature* sig = nullptr;
    REQUIRE(git_signature_now(&sig, "Test", "test@test.com") == GIT_OK);

    QVector<const git_commit*> constParents;
    QVector<git_commit*> parentPtrs;
    for (const auto& pid : parentOids)
    {
        git_commit* parent = nullptr;
        REQUIRE(git_commit_lookup(&parent, repo, &pid) == GIT_OK);
        parentPtrs.append(parent);
        constParents.append(parent);
    }

    git_oid commitOid;
    QByteArray refBytes = branchRef.toUtf8();
    const char* updateRef = branchRef.isEmpty() ? nullptr : refBytes.constData();
    REQUIRE(git_commit_create(
        &commitOid, repo, updateRef, sig, sig, nullptr,
        message.toUtf8().constData(), tree,
        static_cast<size_t>(constParents.size()),
        constParents.isEmpty() ? nullptr : constParents.data()) == GIT_OK);

    for (auto* p : parentPtrs)
        git_commit_free(p);
    git_tree_free(tree);
    git_signature_free(sig);

    return {commitOid, oidStr(&commitOid)};
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

    SECTION("Synthetic row appears for new file in subdirectory") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        // Add a new file in a subdirectory (like CaveWhere adding a trip)
        QDir dir = repo.directory();
        REQUIRE(dir.mkpath("caves/MyCave"));
        QFile newFile(dir.filePath("caves/MyCave/trip.pb"));
        REQUIRE(newFile.open(QFile::WriteOnly));
        newFile.write("new trip data");
        newFile.close();

        repo.checkStatus();
        INFO("modifiedFileCount after checkStatus: " << repo.modifiedFileCount());
        REQUIRE(repo.modifiedFileCount() > 0);

        GitGraphModel model;
        model.setRepository(&repo);

        QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
        if (model.loading())
            REQUIRE(loadingSpy.wait(5000));

        CHECK(model.hasUncommittedChanges());
        CHECK(model.rowCount() == 2); // synthetic + 1 real commit
    }

    SECTION("checkStatusAsync detects new file in subdirectory") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");

        QDir dir = repo.directory();
        REQUIRE(dir.mkpath("caves/MyCave"));
        QFile newFile(dir.filePath("caves/MyCave/trip.pb"));
        REQUIRE(newFile.open(QFile::WriteOnly));
        newFile.write("new trip data");
        newFile.close();

        auto future = repo.checkStatusAsync();
        QSignalSpy modifiedSpy(&repo, &GitRepository::modifiedFileCountChanged);
        if (repo.modifiedFileCount() == 0)
            REQUIRE(modifiedSpy.wait(5000));

        CHECK(repo.modifiedFileCount() > 0);
    }

    SECTION("Synthetic row uses simplified lane types") {
        using LT = GitLaneType::Type;

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

        // Synthetic row lanes use simplified types (Active/NotActive/Empty)
        // instead of copying HEAD's topology-specific types verbatim.
        auto syntheticLanes = model.data(model.index(0), GitGraphModel::LanesRole).value<QList<int>>();
        auto headLanes = model.data(model.index(1), GitGraphModel::LanesRole).value<QList<int>>();
        CHECK(syntheticLanes.size() == headLanes.size());

        // Active lane should be Active type
        auto syntheticActiveLane = model.data(model.index(0), GitGraphModel::ActiveLaneRole).toInt();
        auto headActiveLane = model.data(model.index(1), GitGraphModel::ActiveLaneRole).toInt();
        CHECK(syntheticActiveLane == headActiveLane);
        CHECK(syntheticLanes[syntheticActiveLane] == static_cast<int>(LT::Active));
    }
}

TEST_CASE("GitGraphModel discontinuity merge has no top line on active lane", "[GitGraphModel]")
{
    // Topology matching PhakeCave3000 bug:
    //   main:    C1 -> C2 -> C4
    //   feature: C1 -> C3 -> M1(C3, C2)
    //
    // The revwalk visits C4 first (tip of main), then M1 (tip of feature).
    // M1 starts a new lane. Its active lane must NOT have a top line since
    // nothing exists above it on that lane.
    // Bug: setMerge() overwrites Branch with MergeFork, adding a dangling top line.

    using LT = GitLaneType::Type;

    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* rawRepo = nullptr;
    REQUIRE(git_repository_init(&rawRepo, tempDir.path().toLocal8Bit().constData(), false) == GIT_OK);

    auto c1 = createRawCommit(rawRepo, "C1", {});
    auto c2 = createRawCommit(rawRepo, "C2", {c1.oid});
    auto c3 = createRawCommit(rawRepo, "C3", {c1.oid}, QStringLiteral("refs/heads/feature"));
    auto m1 = createRawCommit(rawRepo, "Merge", {c3.oid, c2.oid}, QStringLiteral("refs/heads/feature"));
    auto c4 = createRawCommit(rawRepo, "C4", {c2.oid});

    git_repository_free(rawRepo);

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));

    GitGraphModel model;
    model.setRepository(&repo);

    QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
    if (model.loading())
        REQUIRE(loadingSpy.wait(5000));

    REQUIRE(model.rowCount() == 5);

    // Find the merge commit row by SHA
    int mergeRowIdx = -1;
    for (int i = 0; i < model.rowCount(); ++i)
    {
        auto sha = model.data(model.index(i), GitGraphModel::ShaRole).toString();
        if (sha == m1.sha)
        {
            mergeRowIdx = i;
            break;
        }
    }
    REQUIRE(mergeRowIdx >= 0);

    auto lanes = model.data(model.index(mergeRowIdx), GitGraphModel::LanesRole).value<QList<int>>();
    int activeLane = model.data(model.index(mergeRowIdx), GitGraphModel::ActiveLaneRole).toInt();

    REQUIRE(activeLane >= 0);
    REQUIRE(activeLane < lanes.size());

    int activeLaneType = lanes[activeLane];

    // The active lane should NOT be a MergeFork type (which has a top line).
    // It should be a Head type (no top line) since nothing is above it.
    CHECK(activeLaneType != static_cast<int>(LT::MergeFork));
    CHECK(activeLaneType != static_cast<int>(LT::MergeForkLeft));
    CHECK(activeLaneType != static_cast<int>(LT::MergeForkRight));

    bool isHeadType = activeLaneType == static_cast<int>(LT::Head)
                   || activeLaneType == static_cast<int>(LT::HeadLeft)
                   || activeLaneType == static_cast<int>(LT::HeadRight);
    CHECK(isHeadType);
}

TEST_CASE("GitGraphModel synthetic row appears in repo with merge history", "[GitGraphModel]")
{
    // Reproduces Cavewhere/cavewhere#377:
    // When the Git history contains a merge commit, uncommitted changes
    // should still produce a synthetic "Uncommitted Changes" row.

    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* rawRepo = nullptr;
    REQUIRE(git_repository_init(&rawRepo, tempDir.path().toLocal8Bit().constData(), false) == GIT_OK);

    // Build a merge topology:
    //   main:    C1 -> C2 -> M(C2, C3)
    //   feature: C1 -> C3
    auto c1 = createRawCommit(rawRepo, "C1", {});
    auto c2 = createRawCommit(rawRepo, "C2", {c1.oid});
    auto c3 = createRawCommit(rawRepo, "C3", {c1.oid}, QStringLiteral("refs/heads/feature"));
    auto merge = createRawCommit(rawRepo, "Merge C2 and C3", {c2.oid, c3.oid});

    git_repository_free(rawRepo);

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    // Dirty the working tree
    QDir dir = repo.directory();
    QFile dirtyFile(dir.filePath("dirty.txt"));
    REQUIRE(dirtyFile.open(QFile::WriteOnly | QFile::Text));
    dirtyFile.write("uncommitted change");
    dirtyFile.close();
    repo.checkStatus();
    REQUIRE(repo.modifiedFileCount() > 0);

    GitGraphModel model;
    model.setRepository(&repo);

    QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
    if (model.loading())
        REQUIRE(loadingSpy.wait(5000));

    // Should have synthetic row + 4 real commits (M, C3, C2, C1)
    INFO("rowCount: " << model.rowCount());
    CHECK(model.hasUncommittedChanges());
    CHECK(model.rowCount() == 5); // 1 synthetic + 4 real

    // Synthetic row at index 0 has empty SHA
    auto idx0 = model.index(0);
    CHECK(model.data(idx0, GitGraphModel::ShaRole).toString().isEmpty());
    CHECK(model.data(idx0, GitGraphModel::MessageRole).toString() == "Uncommitted Changes");

    // Real merge commit at index 1
    auto idx1 = model.index(1);
    CHECK(!model.data(idx1, GitGraphModel::ShaRole).toString().isEmpty());
}

TEST_CASE("GitGraphModel synthetic row appears after checkStatusAsync in repo with merge history", "[GitGraphModel]")
{
    // Tests the scenario from Cavewhere/cavewhere#377:
    // Model is loaded with a clean repo that has merge history, then the
    // working tree becomes dirty and checkStatusAsync is used to detect it.
    // This mimics navigating to the history page after modifying a scrap.

    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* rawRepo = nullptr;
    REQUIRE(git_repository_init(&rawRepo, tempDir.path().toLocal8Bit().constData(), false) == GIT_OK);

    auto c1 = createRawCommit(rawRepo, "C1", {});
    auto c2 = createRawCommit(rawRepo, "C2", {c1.oid});
    auto c3 = createRawCommit(rawRepo, "C3", {c1.oid}, QStringLiteral("refs/heads/feature"));
    auto merge = createRawCommit(rawRepo, "Merge", {c2.oid, c3.oid});

    git_repository_free(rawRepo);

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    // Start with a clean repo
    repo.checkStatus();
    REQUIRE(repo.modifiedFileCount() == 0);

    GitGraphModel model;
    model.setRepository(&repo);

    QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
    if (model.loading())
        REQUIRE(loadingSpy.wait(5000));

    CHECK(model.rowCount() == 4);
    CHECK_FALSE(model.hasUncommittedChanges());

    // Now dirty the working tree (simulating a scrap modification)
    QDir dir = repo.directory();
    QFile dirtyFile(dir.filePath("dirty.txt"));
    REQUIRE(dirtyFile.open(QFile::WriteOnly | QFile::Text));
    dirtyFile.write("uncommitted change");
    dirtyFile.close();

    // Use checkStatusAsync (as the history page does on onVisibleChanged)
    auto future = repo.checkStatusAsync();
    QSignalSpy modifiedSpy(&repo, &GitRepository::modifiedFileCountChanged);
    if (repo.modifiedFileCount() == 0)
        REQUIRE(modifiedSpy.wait(5000));

    CHECK(repo.modifiedFileCount() > 0);
    CHECK(model.hasUncommittedChanges());
    CHECK(model.rowCount() == 5); // 1 synthetic + 4 real

    auto idx0 = model.index(0);
    CHECK(model.data(idx0, GitGraphModel::ShaRole).toString().isEmpty());
    CHECK(model.data(idx0, GitGraphModel::MessageRole).toString() == "Uncommitted Changes");

    // Verify that refresh() preserves the synthetic row (simulates the
    // GitGraphModel being refreshed while uncommitted changes exist).
    model.refresh();

    loadingSpy.clear();
    if (model.loading())
        REQUIRE(loadingSpy.wait(5000));

    CHECK(model.hasUncommittedChanges());
    CHECK(model.rowCount() == 5); // Still 1 synthetic + 4 real
}
