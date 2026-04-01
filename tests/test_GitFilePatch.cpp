//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "TestUtilities.h"
#include "GitFilePatch.h"
#include "GitRepository.h"

//Qt includes
#include <QTemporaryDir>
#include <QDir>
#include <QFile>
#include <QSignalSpy>

using namespace QQuickGit;

namespace {

void waitForLoading(GitFilePatch& patch)
{
    if (!patch.loading()) {
        return;
    }
    QSignalSpy spy(&patch, &GitFilePatch::loadingChanged);
    REQUIRE(spy.wait(5000));
}

} // anonymous namespace

TEST_CASE("GitFilePatch committed diffs", "[GitFilePatch]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    GitRepository repo;
    repo.setDirectory(QDir(tempDir.path()));
    repo.initRepository();

    SECTION("Modified file produces correct origins") {
        TestUtilities::createFileAndCommit(repo, "file.txt", "line1\nline2\nline3\n", "Initial");
        TestUtilities::createFileAndCommit(repo, "file.txt", "line1\nmodified\nline3\n", "Modify line 2");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitFilePatch patch;
        patch.setRepository(&repo);
        patch.setCommitSha(sha);
        patch.setFilePath("file.txt");

        waitForLoading(patch);

        REQUIRE(patch.rowCount() > 0);
        CHECK_FALSE(patch.isBinary());
        CHECK_FALSE(patch.tooLarge());
        CHECK(patch.errorMessage().isEmpty());

        // Check that we have context, added, and deleted lines
        bool hasContext = false;
        bool hasAdded = false;
        bool hasDeleted = false;
        bool hasHunk = false;

        for (int i = 0; i < patch.rowCount(); i++) {
            QModelIndex idx = patch.index(i);
            QString origin = patch.data(idx, GitFilePatch::OriginRole).toString();
            if (origin == " ") {
                hasContext = true;
            }
            if (origin == "+") {
                hasAdded = true;
            }
            if (origin == "-") {
                hasDeleted = true;
            }
            if (origin == "H") {
                hasHunk = true;
            }
        }

        CHECK(hasContext);
        CHECK(hasAdded);
        CHECK(hasDeleted);
        CHECK(hasHunk);
    }

    SECTION("Added file shows all '+' lines") {
        TestUtilities::createFileAndCommit(repo, "new.txt", "line1\nline2\n", "Add new file");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitFilePatch patch;
        patch.setRepository(&repo);
        patch.setCommitSha(sha);
        patch.setFilePath("new.txt");

        waitForLoading(patch);

        REQUIRE(patch.rowCount() > 0);

        // All non-hunk lines should be additions
        for (int i = 0; i < patch.rowCount(); i++) {
            QModelIndex idx = patch.index(i);
            QString origin = patch.data(idx, GitFilePatch::OriginRole).toString();
            CHECK((origin == "+" || origin == "H"));
        }
    }

    SECTION("Deleted file shows all '-' lines") {
        TestUtilities::createFileAndCommit(repo, "doomed.txt", "line1\nline2\n", "Add file");
        TestUtilities::deleteFileAndCommit(repo, "doomed.txt", "Delete file");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitFilePatch patch;
        patch.setRepository(&repo);
        patch.setCommitSha(sha);
        patch.setFilePath("doomed.txt");

        waitForLoading(patch);

        REQUIRE(patch.rowCount() > 0);

        // All non-hunk lines should be deletions
        for (int i = 0; i < patch.rowCount(); i++) {
            QModelIndex idx = patch.index(i);
            QString origin = patch.data(idx, GitFilePatch::OriginRole).toString();
            CHECK((origin == "-" || origin == "H"));
        }
    }

    SECTION("Binary file sets isBinary") {
        // Write a binary file (PNG header bytes)
        QDir dir = repo.directory();
        QFile binFile(dir.filePath("image.png"));
        REQUIRE(binFile.open(QFile::WriteOnly));
        QByteArray pngHeader;
        pngHeader.append('\x89');
        pngHeader.append("PNG\r\n\x1a\n", 7);
        pngHeader.append(QByteArray(100, '\x00'));
        binFile.write(pngHeader);
        binFile.close();

        repo.checkStatus();
        Account account;
        account.setName("Test Author");
        account.setEmail("test@example.com");
        repo.setAccount(&account);
        repo.commitAll("Add binary", QString());
        repo.checkStatus();

        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitFilePatch patch;
        patch.setRepository(&repo);
        patch.setCommitSha(sha);
        patch.setFilePath("image.png");

        waitForLoading(patch);

        CHECK(patch.isBinary());
        CHECK(patch.rowCount() == 0);
    }

    SECTION("Large diff sets tooLarge with custom threshold") {
        // Create a file with many lines
        QString content;
        for (int i = 0; i < 100; i++) {
            content += QStringLiteral("line %1\n").arg(i);
        }
        TestUtilities::createFileAndCommit(repo, "big.txt", content, "Add big file");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitFilePatch patch;
        patch.setMaxDiffLines(10); // Very low threshold
        patch.setRepository(&repo);
        patch.setCommitSha(sha);
        patch.setFilePath("big.txt");

        waitForLoading(patch);

        CHECK(patch.tooLarge());
        CHECK(patch.rowCount() == 0);
    }

    SECTION("Custom threshold allows large diffs when high enough") {
        QString content;
        for (int i = 0; i < 100; i++) {
            content += QStringLiteral("line %1\n").arg(i);
        }
        TestUtilities::createFileAndCommit(repo, "big.txt", content, "Add big file");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitFilePatch patch;
        patch.setMaxDiffLines(10000);
        patch.setRepository(&repo);
        patch.setCommitSha(sha);
        patch.setFilePath("big.txt");

        waitForLoading(patch);

        CHECK_FALSE(patch.tooLarge());
        CHECK(patch.rowCount() > 0);
    }

    SECTION("Line numbers are correct") {
        TestUtilities::createFileAndCommit(repo, "file.txt", "aaa\nbbb\nccc\n", "Initial");
        TestUtilities::createFileAndCommit(repo, "file.txt", "aaa\nBBB\nccc\n", "Modify");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitFilePatch patch;
        patch.setRepository(&repo);
        patch.setCommitSha(sha);
        patch.setFilePath("file.txt");

        waitForLoading(patch);

        REQUIRE(patch.rowCount() > 0);

        // Find an added line and verify it has valid newLineNo
        for (int i = 0; i < patch.rowCount(); i++) {
            QModelIndex idx = patch.index(i);
            QString origin = patch.data(idx, GitFilePatch::OriginRole).toString();
            int oldLine = patch.data(idx, GitFilePatch::OldLineNoRole).toInt();
            int newLine = patch.data(idx, GitFilePatch::NewLineNoRole).toInt();

            if (origin == "+") {
                CHECK(newLine > 0);
                CHECK(oldLine == -1);
            } else if (origin == "-") {
                CHECK(oldLine > 0);
                CHECK(newLine == -1);
            } else if (origin == " ") {
                CHECK(oldLine > 0);
                CHECK(newLine > 0);
            }
        }
    }

    SECTION("EOFNL origins are mapped correctly") {
        // Create a file without trailing newline
        TestUtilities::createFileAndCommit(repo, "noeol.txt", "line1\nline2", "No trailing newline");
        // Add a trailing newline
        TestUtilities::createFileAndCommit(repo, "noeol.txt", "line1\nline2\n", "Add trailing newline");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitFilePatch patch;
        patch.setRepository(&repo);
        patch.setCommitSha(sha);
        patch.setFilePath("noeol.txt");

        waitForLoading(patch);

        REQUIRE(patch.rowCount() > 0);
        CHECK(patch.errorMessage().isEmpty());

        // All origins should be valid mapped values
        for (int i = 0; i < patch.rowCount(); i++) {
            QModelIndex idx = patch.index(i);
            QString origin = patch.data(idx, GitFilePatch::OriginRole).toString();
            CHECK((origin == " " || origin == "+" || origin == "-" || origin == "H"));
        }
    }

    SECTION("Invalid file path sets error") {
        TestUtilities::createFileAndCommit(repo, "file.txt", "hello", "Initial");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitFilePatch patch;
        patch.setRepository(&repo);
        patch.setCommitSha(sha);
        patch.setFilePath("nonexistent.txt");

        waitForLoading(patch);

        CHECK(!patch.errorMessage().isEmpty());
        CHECK(patch.rowCount() == 0);
    }

    SECTION("Cancel does not crash") {
        TestUtilities::createFileAndCommit(repo, "file.txt", "hello", "Initial");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        {
            GitFilePatch patch;
            patch.setRepository(&repo);
            patch.setCommitSha(sha);
            patch.setFilePath("file.txt");
            // Destroy immediately while loading might be in progress
        }
        // If we get here without crashing, the test passes
        CHECK(true);
    }

    SECTION("Role names are correct") {
        GitFilePatch patch;
        auto roles = patch.roleNames();

        CHECK(roles.contains(GitFilePatch::TextRole));
        CHECK(roles.contains(GitFilePatch::OriginRole));
        CHECK(roles.contains(GitFilePatch::OldLineNoRole));
        CHECK(roles.contains(GitFilePatch::NewLineNoRole));

        CHECK(roles[GitFilePatch::TextRole] == "text");
        CHECK(roles[GitFilePatch::OriginRole] == "origin");
        CHECK(roles[GitFilePatch::OldLineNoRole] == "oldLineNo");
        CHECK(roles[GitFilePatch::NewLineNoRole] == "newLineNo");
    }

    SECTION("Setting null repository clears model") {
        TestUtilities::createFileAndCommit(repo, "file.txt", "hello", "Initial");
        QString sha = TestUtilities::getHeadSha(repo.directory());

        GitFilePatch patch;
        patch.setRepository(&repo);
        patch.setCommitSha(sha);
        patch.setFilePath("file.txt");

        waitForLoading(patch);
        CHECK(patch.rowCount() > 0);

        patch.setRepository(nullptr);
        CHECK(patch.rowCount() == 0);
        CHECK_FALSE(patch.loading());
    }
}
