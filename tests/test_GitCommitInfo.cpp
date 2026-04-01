//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "TestUtilities.h"
#include "GitCommitInfo.h"
#include "GitRepository.h"

//Qt includes
#include <QTemporaryDir>
#include <QDir>
#include <QSignalSpy>
#include <QFile>

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

TEST_CASE("GitCommitInfo basic functionality", "[GitCommitInfo]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    SECTION("Valid SHA loads metadata") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial commit");
        QString sha = TestUtilities::getHeadSha(repo.directory());
        REQUIRE(!sha.isEmpty());

        GitCommitInfo info;
        info.setRepository(&repo);
        info.setCommitSha(sha);

        waitForLoading(info);

        CHECK(info.author() == "Test Author");
        CHECK(info.authorEmail() == "test@example.com");
        CHECK(info.subject() == "Initial commit");
        CHECK(info.body().isEmpty());
        CHECK(info.timestamp().isValid());
        CHECK(info.errorMessage().isEmpty());
        CHECK(!info.isMergeCommit());
    }

    SECTION("Commit with body parses subject and body") {
        QDir dir = repo.directory();
        QFile file(dir.filePath("file1.txt"));
        REQUIRE(file.open(QFile::WriteOnly | QFile::Text));
        file.write("content");
        file.close();

        repo.checkStatus();

        git_repository* rawRepo = nullptr;
        REQUIRE(git_repository_open(&rawRepo, dir.absolutePath().toLocal8Bit().constData()) == GIT_OK);
        std::unique_ptr<git_repository, decltype(&git_repository_free)>
            repoHolder(rawRepo, &git_repository_free);

        git_index* idx = nullptr;
        REQUIRE(git_repository_index(&idx, rawRepo) == GIT_OK);
        std::unique_ptr<git_index, decltype(&git_index_free)>
            idxHolder(idx, &git_index_free);

        REQUIRE(git_index_add_bypath(idx, "file1.txt") == GIT_OK);
        REQUIRE(git_index_write(idx) == GIT_OK);

        git_oid treeOid;
        REQUIRE(git_index_write_tree(&treeOid, idx) == GIT_OK);

        git_tree* tree = nullptr;
        REQUIRE(git_tree_lookup(&tree, rawRepo, &treeOid) == GIT_OK);
        std::unique_ptr<git_tree, decltype(&git_tree_free)>
            treeHolder(tree, &git_tree_free);

        git_signature* sig = nullptr;
        REQUIRE(git_signature_now(&sig, "Test Author", "test@example.com") == GIT_OK);
        std::unique_ptr<git_signature, decltype(&git_signature_free)>
            sigHolder(sig, &git_signature_free);

        git_oid commitOid;
        REQUIRE(git_commit_create_v(&commitOid, rawRepo, "HEAD", sig, sig,
                                     nullptr, "Fix the bug\n\nThis fixes issue #42.\nMulti-line body.",
                                     tree, 0) == GIT_OK);

        char shaBuffer[GIT_OID_SHA1_HEXSIZE + 1];
        git_oid_tostr(shaBuffer, sizeof(shaBuffer), &commitOid);
        QString sha = QString::fromLatin1(shaBuffer);

        GitCommitInfo info;
        info.setRepository(&repo);
        info.setCommitSha(sha);

        waitForLoading(info);

        CHECK(info.subject() == "Fix the bug");
        CHECK(info.body().contains("This fixes issue #42."));
        CHECK(info.body().contains("Multi-line body."));
    }

    SECTION("Root commit has empty parentShas and all files Added") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Root commit");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitCommitInfo info;
        QSignalSpy fileSpy(&info, &GitCommitInfo::fileListReady);

        info.setRepository(&repo);
        info.setCommitSha(sha);

        waitForLoading(info);

        CHECK(info.parentShas().isEmpty());
        CHECK(!info.isMergeCommit());

        REQUIRE(fileSpy.count() >= 1);
        auto files = fileSpy.last().at(0).value<QVector<CommitLoadResult::FileEntry>>();
        REQUIRE(files.size() == 1);
        CHECK(files[0].filePath == "file1.txt");
        CHECK(files[0].statusText == "Added");
    }

    SECTION("Multi-file commit lists all changed files") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "First");
        TestUtilities::createFileAndCommit(repo, "file2.txt", "world", "Second");

        // Now modify file1 and add file3 in one commit
        QDir dir = repo.directory();
        {
            QFile f1(dir.filePath("file1.txt"));
            REQUIRE(f1.open(QFile::WriteOnly | QFile::Truncate | QFile::Text));
            f1.write("modified");
            f1.close();
        }
        {
            QFile f3(dir.filePath("file3.txt"));
            REQUIRE(f3.open(QFile::WriteOnly | QFile::Text));
            f3.write("new file");
            f3.close();
        }
        repo.checkStatus();
        Account account;
        account.setName("Test Author");
        account.setEmail("test@example.com");
        repo.setAccount(&account);
        repo.commitAll("Multi-file change", QString());

        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitCommitInfo info;
        QSignalSpy fileSpy(&info, &GitCommitInfo::fileListReady);
        info.setRepository(&repo);
        info.setCommitSha(sha);

        waitForLoading(info);

        REQUIRE(fileSpy.count() >= 1);
        auto files = fileSpy.last().at(0).value<QVector<CommitLoadResult::FileEntry>>();
        CHECK(files.size() == 2); // file1.txt modified + file3.txt added
    }

    SECTION("Invalid SHA sets errorMessage") {
        GitCommitInfo info;
        info.setRepository(&repo);
        info.setCommitSha("invalid_sha_string");

        waitForLoading(info);

        CHECK(!info.errorMessage().isEmpty());
    }

    SECTION("Empty SHA clears metadata") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "Initial");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitCommitInfo info;
        info.setRepository(&repo);
        info.setCommitSha(sha);

        waitForLoading(info);
        CHECK(!info.author().isEmpty());

        info.setCommitSha("");
        CHECK(info.author().isEmpty());
        CHECK(info.subject().isEmpty());
    }

    SECTION("Changing SHA reloads") {
        TestUtilities::createFileAndCommit(repo, "file1.txt", "hello", "First commit");
        QString sha1 = TestUtilities::getHeadSha(repo.directory());
        TestUtilities::createFileAndCommit(repo, "file2.txt", "world", "Second commit");
        QString sha2 = TestUtilities::getHeadSha(repo.directory());

        GitCommitInfo info;
        info.setRepository(&repo);
        info.setCommitSha(sha1);

        waitForLoading(info);
        CHECK(info.subject() == "First commit");

        info.setCommitSha(sha2);
        waitForLoading(info);
        CHECK(info.subject() == "Second commit");
    }
}
