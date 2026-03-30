//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "GitLanes.h"
#include "GitLaneType.h"
#include "GitLane.h"

//Qt includes
#include <QString>
#include <QStringList>
#include <QVector>
#include <QTemporaryDir>

//libgit2
#include "git2.h"

using namespace QQuickGit;
using LT = GitLaneType::Type;

namespace {

/**
 * Helper: create a commit in a libgit2 repo.
 * Returns the OID of the new commit and its SHA hex string.
 */
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

CommitResult createCommit(git_repository* repo,
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

    QVector<git_commit*> parentPtrs;
    for (const auto& pid : parentOids)
    {
        git_commit* parent = nullptr;
        REQUIRE(git_commit_lookup(&parent, repo, &pid) == GIT_OK);
        parentPtrs.append(parent);
    }

    // Separate const array needed for git_commit_create's API
    QVector<const git_commit*> constParents;
    constParents.reserve(parentPtrs.size());
    for (auto* p : parentPtrs)
        constParents.append(p);

    git_oid commitOid;
    QByteArray refBytes = branchRef.toUtf8();
    const char* updateRef = branchRef.isEmpty() ? nullptr : refBytes.constData();
    int err = git_commit_create(
        &commitOid,
        repo,
        updateRef,
        sig, sig,
        nullptr,
        message.toUtf8().constData(),
        tree,
        static_cast<size_t>(constParents.size()),
        constParents.isEmpty() ? nullptr : constParents.data());

    REQUIRE(err == GIT_OK);

    for (auto* p : parentPtrs)
        git_commit_free(p);
    git_tree_free(tree);
    git_signature_free(sig);

    CommitResult result;
    result.oid = commitOid;
    result.sha = oidStr(&commitOid);
    return result;
}

/**
 * Walk the repo and run the lane algorithm.
 * Returns (shas, lanes, activeLanes) for each row.
 */
struct WalkRow {
    QString sha;
    QVector<GitLane> lanes;
    int activeLane;
};

QVector<WalkRow> walkAndComputeLanes(git_repository* repo)
{
    git_revwalk* walk = nullptr;
    REQUIRE(git_revwalk_new(&walk, repo) == GIT_OK);

    git_revwalk_sorting(walk, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);
    git_revwalk_push_glob(walk, "refs/heads/*");

    GitLanes lanes;
    git_oid oid;
    bool first = true;
    QVector<WalkRow> rows;

    while (git_revwalk_next(&oid, walk) == GIT_OK)
    {
        QString sha = oidStr(&oid);

        git_commit* commit = nullptr;
        REQUIRE(git_commit_lookup(&commit, repo, &oid) == GIT_OK);

        unsigned int parentCount = git_commit_parentcount(commit);
        QStringList parentShas;
        for (unsigned int i = 0; i < parentCount; i++)
            parentShas.append(oidStr(git_commit_parent_id(commit, i)));

        git_commit_free(commit);

        if (first)
        {
            lanes.init(sha);
            first = false;
        }

        bool isDisc = false;
        bool fork = lanes.isFork(sha, isDisc);

        if (isDisc)
            lanes.changeActiveLane(sha);

        if (fork)
            lanes.setFork(sha);

        if (parentCount > 1)
            lanes.setMerge(parentShas);

        if (parentCount == 0)
            lanes.setInitial();

        WalkRow row;
        row.sha = sha;
        row.lanes = lanes.getLanes();
        row.activeLane = lanes.activeLaneIndex();
        rows.append(row);

        QString nextSha = parentCount == 0 ? QString() : parentShas.first();
        lanes.nextParent(nextSha);

        if (parentCount > 1)
            lanes.afterMerge();
        if (fork)
            lanes.afterFork();
        if (lanes.isBranch())
            lanes.afterBranch();
    }

    git_revwalk_free(walk);
    return rows;
}

} // anonymous namespace

TEST_CASE("GitLane helper methods work correctly", "[GitLanes]")
{
    SECTION("isHead returns true for Head variants") {
        CHECK(GitLane(LT::Head).isHead());
        CHECK(GitLane(LT::HeadLeft).isHead());
        CHECK(GitLane(LT::HeadRight).isHead());
        CHECK_FALSE(GitLane(LT::Active).isHead());
        CHECK_FALSE(GitLane(LT::Join).isHead());
    }

    SECTION("isTail returns true for Tail variants") {
        CHECK(GitLane(LT::Tail).isTail());
        CHECK(GitLane(LT::TailLeft).isTail());
        CHECK(GitLane(LT::TailRight).isTail());
        CHECK_FALSE(GitLane(LT::Active).isTail());
    }

    SECTION("isJoin returns true for Join variants") {
        CHECK(GitLane(LT::Join).isJoin());
        CHECK(GitLane(LT::JoinLeft).isJoin());
        CHECK(GitLane(LT::JoinRight).isJoin());
        CHECK_FALSE(GitLane(LT::Active).isJoin());
    }

    SECTION("isMerge returns true for MergeFork variants") {
        CHECK(GitLane(LT::MergeFork).isMerge());
        CHECK(GitLane(LT::MergeForkLeft).isMerge());
        CHECK(GitLane(LT::MergeForkRight).isMerge());
        CHECK_FALSE(GitLane(LT::Active).isMerge());
    }

    SECTION("isActive returns true for Active, Initial, Branch, and MergeFork") {
        CHECK(GitLane(LT::Active).isActive());
        CHECK(GitLane(LT::Initial).isActive());
        CHECK(GitLane(LT::Branch).isActive());
        CHECK(GitLane(LT::MergeFork).isActive());
        CHECK_FALSE(GitLane(LT::Empty).isActive());
        CHECK_FALSE(GitLane(LT::NotActive).isActive());
    }

    SECTION("isFreeLane returns true for NotActive, Cross, and Join variants") {
        CHECK(GitLane(LT::NotActive).isFreeLane());
        CHECK(GitLane(LT::Cross).isFreeLane());
        CHECK(GitLane(LT::Join).isFreeLane());
        CHECK(GitLane(LT::JoinLeft).isFreeLane());
        CHECK_FALSE(GitLane(LT::Active).isFreeLane());
    }
}

TEST_CASE("GitLanes linear topology", "[GitLanes]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), false) == GIT_OK);

    // Create a linear chain: C1 <- C2 <- C3
    auto c1 = createCommit(repo, "C1", {});
    auto c2 = createCommit(repo, "C2", {c1.oid});
    auto c3 = createCommit(repo, "C3", {c2.oid});

    auto rows = walkAndComputeLanes(repo);

    REQUIRE(rows.size() == 3);

    for (const auto& row : rows)
    {
        CHECK(row.lanes.size() == 1);
        CHECK(row.activeLane == 0);
    }

    for (int i = 0; i < rows.size() - 1; i++)
    {
        CHECK(rows[i].lanes[0].isActive());
    }

    CHECK(rows.last().lanes[0].equals(LT::Initial));

    git_repository_free(repo);
}

TEST_CASE("GitLanes simple fork", "[GitLanes]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), false) == GIT_OK);

    // Create: C1 <- C2 (main)
    //              \- C3 (feature)
    auto c1 = createCommit(repo, "C1", {});
    auto c2 = createCommit(repo, "C2", {c1.oid});
    auto c3 = createCommit(repo, "C3", {c1.oid}, QStringLiteral("refs/heads/feature"));

    auto rows = walkAndComputeLanes(repo);

    REQUIRE(rows.size() == 3);

    bool foundForkRow = false;
    for (const auto& row : rows)
    {
        if (row.sha == c1.sha)
        {
            foundForkRow = true;
            bool hasForkType = false;
            for (const auto& lane : row.lanes)
            {
                if (lane.isMerge() || lane.isTail())
                    hasForkType = true;
            }
            CHECK(hasForkType);
        }
    }
    CHECK(foundForkRow);

    git_repository_free(repo);
}

TEST_CASE("GitLanes simple merge", "[GitLanes]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), false) == GIT_OK);

    // Create: C1 <- C2 (main line)
    //              \- C3 (branch)
    //         C2 + C3 -> M1 (merge)
    auto c1 = createCommit(repo, "C1", {});
    auto c2 = createCommit(repo, "C2", {c1.oid});
    auto c3 = createCommit(repo, "C3", {c1.oid}, QStringLiteral("refs/heads/feature"));

    auto m1 = createCommit(repo, "Merge", {c2.oid, c3.oid});

    auto rows = walkAndComputeLanes(repo);

    REQUIRE(rows.size() == 4);

    bool foundMerge = false;
    for (const auto& row : rows)
    {
        if (row.sha == m1.sha)
        {
            foundMerge = true;
            bool hasMergeType = false;
            for (const auto& lane : row.lanes)
            {
                if (lane.isMerge() || lane.isHead() || lane.isJoin())
                    hasMergeType = true;
            }
            CHECK(hasMergeType);
        }
    }
    CHECK(foundMerge);

    git_repository_free(repo);
}

TEST_CASE("GitLanes lane reuse after branch joins", "[GitLanes]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), false) == GIT_OK);

    // Create: C1 <- C2
    //              \- C3 (feature)
    // Merge: C2 + C3 -> M1
    // Then continue: M1 <- C4 <- C5
    auto c1 = createCommit(repo, "C1", {});
    auto c2 = createCommit(repo, "C2", {c1.oid});
    auto c3 = createCommit(repo, "C3", {c1.oid}, QStringLiteral("refs/heads/feature"));
    auto m1 = createCommit(repo, "Merge", {c2.oid, c3.oid});
    auto c4 = createCommit(repo, "C4", {m1.oid});
    auto c5 = createCommit(repo, "C5", {c4.oid});

    auto rows = walkAndComputeLanes(repo);

    REQUIRE(rows.size() == 6);

    CHECK(rows[0].lanes.size() == 1); // C5
    CHECK(rows[1].lanes.size() == 1); // C4

    git_repository_free(repo);
}

TEST_CASE("GitLanes torture test - many branches", "[GitLanes]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), false) == GIT_OK);

    auto base = createCommit(repo, "Base", {});

    const int numBranches = 20;
    QVector<git_oid> branchTips;
    for (int i = 0; i < numBranches; i++)
    {
        QString branchRef = QStringLiteral("refs/heads/branch-%1").arg(i);
        auto branchCommit = createCommit(
            repo,
            QStringLiteral("Branch %1 commit").arg(i),
            {base.oid},
            branchRef);
        branchTips.append(branchCommit.oid);
    }

    git_oid current = branchTips.first();
    for (int i = 1; i < numBranches; i++)
    {
        QString ref = (i == numBranches - 1)
            ? QStringLiteral("refs/heads/merge")
            : QString();
        auto merge = createCommit(
            repo,
            QStringLiteral("Merge branch-%1").arg(i),
            {current, branchTips[i]},
            ref);
        current = merge.oid;
    }

    auto rows = walkAndComputeLanes(repo);

    REQUIRE(rows.size() > 0);

    for (const auto& row : rows)
    {
        int activeCount = 0;
        for (const auto& lane : row.lanes)
        {
            if (lane.isActive())
                activeCount++;
        }
        CHECK(activeCount >= 1);
    }

    CHECK(rows[0].lanes.size() >= 1);

    bool foundBase = false;
    for (const auto& row : rows)
    {
        if (row.sha == oidStr(&base.oid))
        {
            foundBase = true;
            bool hasForkType = false;
            for (const auto& lane : row.lanes)
            {
                if (lane.isMerge() || lane.isTail())
                    hasForkType = true;
            }
            CHECK(hasForkType);
        }
    }
    CHECK(foundBase);

    git_repository_free(repo);
}
