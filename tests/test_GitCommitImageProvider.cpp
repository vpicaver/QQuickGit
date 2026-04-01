//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "GitCommitImageProvider.h"
#include "GitRepository.h"
#include "LfsStore.h"
#include "Account.h"

//Qt includes
#include <QTemporaryDir>
#include <QDir>
#include <QFile>
#include <QImage>
#include <QBuffer>

using namespace QQuickGit;

namespace {

// 1x1 red PNG (68 bytes)
QByteArray createMinimalPng()
{
    // Generate a 1x1 red image and save to PNG
    QImage img(1, 1, QImage::Format_ARGB32);
    img.setPixelColor(0, 0, QColor(Qt::red));
    QByteArray data;
    QBuffer buf(&data);
    buf.open(QIODevice::WriteOnly);
    img.save(&buf, "PNG");
    return data;
}

void createFileAndCommit(GitRepository& repo, const QString& filename,
                         const QByteArray& content, const QString& message)
{
    QDir dir = repo.directory();
    QFile file(dir.filePath(filename));
    REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate));
    file.write(content);
    file.close();

    repo.checkStatus();

    Account account;
    account.setName("Test");
    account.setEmail("test@test.com");
    repo.setAccount(&account);
    repo.commitAll(message, QString());
    repo.checkStatus();
}

QString headSha(GitRepository& repo)
{
    auto result = GitRepository::headCommitOid(repo.directory().absolutePath());
    return result.hasError() ? QString() : result.value();
}

} // anonymous namespace

TEST_CASE("GitCommitImageProvider basic functionality", "[GitCommitImageProvider]")
{
    GitCommitImageProvider provider;

    SECTION("Register and unregister repository")
    {
        int id1 = provider.registerRepository("/tmp/repo1");
        int id2 = provider.registerRepository("/tmp/repo2");

        CHECK(id1 != id2);
        CHECK(id1 > 0);
        CHECK(id2 > 0);

        // Unregister should not crash
        provider.unregisterRepository(id1);
        provider.unregisterRepository(id2);

        // Unregistering non-existent ID should not crash
        provider.unregisterRepository(999);
    }

    SECTION("Valid image from committed file returns QImage")
    {
        QTemporaryDir tempDir;
        REQUIRE(tempDir.isValid());

        GitRepository repo;
        repo.setDirectory(QDir(tempDir.path()));
        repo.initRepository();

        QByteArray pngData = createMinimalPng();
        createFileAndCommit(repo, "image.png", pngData, "Add image");

        QString sha = headSha(repo);
        REQUIRE(!sha.isEmpty());

        int repoId = provider.registerRepository(tempDir.path());

        QSize size;
        QString url = QString("%1/%2/image.png").arg(repoId).arg(sha);
        QImage image = provider.requestImage(url, &size, QSize());

        CHECK(!image.isNull());
        CHECK(size.width() == 1);
        CHECK(size.height() == 1);

        provider.unregisterRepository(repoId);
    }

    SECTION("Non-existent file returns null QImage")
    {
        QTemporaryDir tempDir;
        REQUIRE(tempDir.isValid());

        GitRepository repo;
        repo.setDirectory(QDir(tempDir.path()));
        repo.initRepository();

        createFileAndCommit(repo, "file.txt", "hello", "Init");

        QString sha = headSha(repo);
        int repoId = provider.registerRepository(tempDir.path());

        QSize size;
        QString url = QString("%1/%2/nonexistent.png").arg(repoId).arg(sha);
        QImage image = provider.requestImage(url, &size, QSize());

        CHECK(image.isNull());

        provider.unregisterRepository(repoId);
    }

    SECTION("Unregistered repo ID returns null QImage")
    {
        QSize size;
        QImage image = provider.requestImage("999/abcdef0123456789abcdef0123456789abcdef01/file.png",
                                             &size, QSize());
        CHECK(image.isNull());
    }

    SECTION("Malformed URL returns null QImage")
    {
        QSize size;

        // No slashes
        CHECK(provider.requestImage("garbage", &size, QSize()).isNull());

        // Missing file path
        CHECK(provider.requestImage("1/abcdef0123456789abcdef0123456789abcdef01", &size, QSize()).isNull());

        // SHA too short
        CHECK(provider.requestImage("1/abc/file.png", &size, QSize()).isNull());

        // Non-integer repo ID
        CHECK(provider.requestImage("notanint/abcdef0123456789abcdef0123456789abcdef01/file.png",
                                    &size, QSize()).isNull());
    }

    SECTION("Non-image file returns null QImage")
    {
        QTemporaryDir tempDir;
        REQUIRE(tempDir.isValid());

        GitRepository repo;
        repo.setDirectory(QDir(tempDir.path()));
        repo.initRepository();

        createFileAndCommit(repo, "readme.txt", "just text", "Add text");

        QString sha = headSha(repo);
        int repoId = provider.registerRepository(tempDir.path());

        QSize size;
        QString url = QString("%1/%2/readme.txt").arg(repoId).arg(sha);
        QImage image = provider.requestImage(url, &size, QSize());

        CHECK(image.isNull());

        provider.unregisterRepository(repoId);
    }

    SECTION("File path with subdirectory works")
    {
        QTemporaryDir tempDir;
        REQUIRE(tempDir.isValid());

        GitRepository repo;
        repo.setDirectory(QDir(tempDir.path()));
        repo.initRepository();

        QDir(tempDir.path()).mkpath("sub/dir");
        QByteArray pngData = createMinimalPng();
        createFileAndCommit(repo, "sub/dir/deep.png", pngData, "Add deep image");

        QString sha = headSha(repo);
        int repoId = provider.registerRepository(tempDir.path());

        QSize size;
        QString url = QString("%1/%2/sub/dir/deep.png").arg(repoId).arg(sha);
        QImage image = provider.requestImage(url, &size, QSize());

        CHECK(!image.isNull());
        CHECK(size.width() == 1);
        CHECK(size.height() == 1);

        provider.unregisterRepository(repoId);
    }

    SECTION("LFS pointer is resolved from local store")
    {
        QTemporaryDir tempDir;
        REQUIRE(tempDir.isValid());

        GitRepository repo;
        repo.setDirectory(QDir(tempDir.path()));
        repo.initRepository();

        // Create a real PNG and store it in the LFS object store
        QByteArray pngData = createMinimalPng();
        QString gitDir = tempDir.path() + "/.git";
        LfsStore store(gitDir);
        auto storeResult = store.storeBytes(pngData);
        REQUIRE(!storeResult.hasError());
        LfsPointer pointer = storeResult.value();

        // Commit the LFS pointer text instead of the real content
        createFileAndCommit(repo, "image.png", pointer.toPointerText(), "Add LFS image");

        QString sha = headSha(repo);
        int repoId = provider.registerRepository(tempDir.path());

        QSize size;
        QString url = QString("%1/%2/image.png").arg(repoId).arg(sha);
        QImage image = provider.requestImage(url, &size, QSize());

        CHECK(!image.isNull());
        CHECK(size.width() == 1);
        CHECK(size.height() == 1);

        provider.unregisterRepository(repoId);
    }

    SECTION("Missing LFS object returns null QImage")
    {
        QTemporaryDir tempDir;
        REQUIRE(tempDir.isValid());

        GitRepository repo;
        repo.setDirectory(QDir(tempDir.path()));
        repo.initRepository();

        // Create a fake LFS pointer (object doesn't exist in store)
        QByteArray fakePointer =
            "version https://git-lfs.github.com/spec/v1\n"
            "oid sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"
            "size 12345\n";

        createFileAndCommit(repo, "image.png", fakePointer, "Add missing LFS");

        QString sha = headSha(repo);
        int repoId = provider.registerRepository(tempDir.path());

        QSize size;
        QString url = QString("%1/%2/image.png").arg(repoId).arg(sha);
        QImage image = provider.requestImage(url, &size, QSize());

        CHECK(image.isNull());

        provider.unregisterRepository(repoId);
    }
}
