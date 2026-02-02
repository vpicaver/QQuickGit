// Catch includes
#include <catch2/catch_test_macros.hpp>

// libgit2
#include "git2.h"
#include "git2/filter.h"

// Our includes
#include "GitRepository.h"
#include "Account.h"
#include "LfsStore.h"

// Qt includes
#include <QDir>
#include <QFile>
#include <QImage>
#include <QTemporaryDir>

using namespace QQuickGit;

namespace {

bool writeTextFile(const QString& path, const QByteArray& contents)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return false;
    }
    return file.write(contents) == contents.size();
}

QByteArray readFileBytes(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return QByteArray();
    }
    return file.readAll();
}

QByteArray readBlobFromHead(git_repository* repo, const char* path)
{
    git_reference* head = nullptr;
    if (git_repository_head(&head, repo) != GIT_OK) {
        return QByteArray();
    }

    const git_oid* headId = git_reference_target(head);
    if (!headId) {
        git_reference_free(head);
        return QByteArray();
    }

    git_commit* commit = nullptr;
    if (git_commit_lookup(&commit, repo, headId) != GIT_OK) {
        git_reference_free(head);
        return QByteArray();
    }

    git_tree* tree = nullptr;
    if (git_commit_tree(&tree, commit) != GIT_OK) {
        git_commit_free(commit);
        git_reference_free(head);
        return QByteArray();
    }

    git_tree_entry* entry = nullptr;
    if (git_tree_entry_bypath(&entry, tree, path) != GIT_OK) {
        git_tree_free(tree);
        git_commit_free(commit);
        git_reference_free(head);
        return QByteArray();
    }

    git_blob* blob = nullptr;
    if (git_blob_lookup(&blob, repo, git_tree_entry_id(entry)) != GIT_OK) {
        git_tree_entry_free(entry);
        git_tree_free(tree);
        git_commit_free(commit);
        git_reference_free(head);
        return QByteArray();
    }

    const auto* content = static_cast<const char*>(git_blob_rawcontent(blob));
    const size_t size = git_blob_rawsize(blob);
    QByteArray result(content, static_cast<int>(size));

    git_blob_free(blob);
    git_tree_entry_free(entry);
    git_tree_free(tree);
    git_commit_free(commit);
    git_reference_free(head);

    return result;
}

QString headOidString(git_repository* repo)
{
    git_reference* head = nullptr;
    if (git_repository_head(&head, repo) != GIT_OK) {
        return QString();
    }

    const git_oid* headId = git_reference_target(head);
    if (!headId) {
        git_reference_free(head);
        return QString();
    }

    const char* oidStr = git_oid_tostr_s(headId);
    const QString result = oidStr ? QString::fromLatin1(oidStr) : QString();
    git_reference_free(head);
    return result;
}

QByteArray createPngFile(const QString& path, const QColor& color)
{
    QImage image(10, 10, QImage::Format_ARGB32);
    image.fill(color);
    if (!image.save(path, "PNG")) {
        return QByteArray();
    }
    return readFileBytes(path);
}

}

TEST_CASE("LfsPointer round trip", "[LFS]") {
    LfsPointer pointer;
    pointer.oid = QStringLiteral("0123456789abcdef");
    pointer.size = 1234;

    const QByteArray pointerText = pointer.toPointerText();
    REQUIRE(!pointerText.isEmpty());

    LfsPointer parsed;
    REQUIRE(LfsPointer::parse(pointerText, &parsed));
    CHECK(parsed.oid == pointer.oid);
    CHECK(parsed.size == pointer.size);
}

TEST_CASE("LfsStore store/read bytes", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), 0) == GIT_OK);
    REQUIRE(repo != nullptr);

    QByteArray payload;
    payload.append("binary", 6);
    payload.append('\0');
    payload.append("data", 4);
    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();

    LfsStore store(gitDirPath);
    auto storeResult = store.storeBytes(payload);
    REQUIRE(!storeResult.hasError());
    const LfsPointer pointer = storeResult.value();
    CHECK(pointer.size == payload.size());
    CHECK(!pointer.oid.isEmpty());

    auto readResult = store.readObject(pointer.oid);
    REQUIRE(!readResult.hasError());
    CHECK(readResult.value() == payload);

    git_repository_free(repo);
}

TEST_CASE("Lfs filter clean/smudge round trip", "[LFS]") {
    QTemporaryDir tempDir;

    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), 0) == GIT_OK);
    REQUIRE(repo != nullptr);

    const QString repoPath = tempDir.path();
    const QString attributesPath = QDir(repoPath).filePath(QStringLiteral(".gitattributes"));
    REQUIRE(writeTextFile(attributesPath, QByteArray("*.png filter=lfs diff=lfs merge=lfs -text\n")));

    const QByteArray payload("lfs-binary-\x01\x02\x03", 14);

    git_filter_list* cleanFilters = nullptr;
    REQUIRE(git_filter_list_load(&cleanFilters, repo, nullptr, "test.png", GIT_FILTER_TO_ODB, GIT_FILTER_DEFAULT) == GIT_OK);
    REQUIRE(cleanFilters != nullptr);
    CHECK(git_filter_list_contains(cleanFilters, "lfs") == 1);

    git_buf cleanOut = GIT_BUF_INIT;
    REQUIRE(git_filter_list_apply_to_buffer(&cleanOut, cleanFilters, payload.constData(), static_cast<size_t>(payload.size())) == GIT_OK);
    REQUIRE(cleanOut.size > 0);

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(QByteArray(cleanOut.ptr, static_cast<int>(cleanOut.size)), &pointer));
    CHECK(pointer.size == payload.size());
    CHECK(!pointer.oid.isEmpty());

    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
    CHECK(QFile::exists(objectPath));

    git_filter_list* smudgeFilters = nullptr;
    REQUIRE(git_filter_list_load(&smudgeFilters, repo, nullptr, "test.png", GIT_FILTER_TO_WORKTREE, GIT_FILTER_DEFAULT) == GIT_OK);
    REQUIRE(smudgeFilters != nullptr);
    CHECK(git_filter_list_contains(smudgeFilters, "lfs") == 1);

    git_buf smudgeOut = GIT_BUF_INIT;
    REQUIRE(git_filter_list_apply_to_buffer(&smudgeOut,
                                            smudgeFilters,
                                            cleanOut.ptr,
                                            static_cast<size_t>(cleanOut.size)) == GIT_OK);
    REQUIRE(smudgeOut.size == static_cast<size_t>(payload.size()));
    CHECK(QByteArray(smudgeOut.ptr, static_cast<int>(smudgeOut.size)) == payload);

    git_buf_dispose(&cleanOut);
    git_buf_dispose(&smudgeOut);
    git_filter_list_free(cleanFilters);
    git_filter_list_free(smudgeFilters);
    git_repository_free(repo);
}

TEST_CASE("Lfs filter keeps working tree PNG and stores pointer in ODB", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    git_repository* repo = nullptr;
    REQUIRE(git_repository_init(&repo, tempDir.path().toLocal8Bit().constData(), 0) == GIT_OK);
    REQUIRE(repo != nullptr);

    const QString repoPath = tempDir.path();
    const QString attributesPath = QDir(repoPath).filePath(QStringLiteral(".gitattributes"));
    REQUIRE(writeTextFile(attributesPath, QByteArray("*.png filter=lfs diff=lfs merge=lfs -text\n")));

    const QString imageFileName = QStringLiteral("red.png");
    const QString imagePath = QDir(repoPath).filePath(imageFileName);

    QImage image(10, 10, QImage::Format_ARGB32);
    image.fill(Qt::red);
    REQUIRE(image.save(imagePath, "PNG"));

    const QByteArray workingTreeBytes = readFileBytes(imagePath);
    REQUIRE(!workingTreeBytes.isEmpty());
    REQUIRE(QFile::exists(imagePath));

    git_filter_list* cleanFilters = nullptr;
    REQUIRE(git_filter_list_load(&cleanFilters, repo, nullptr, "red.png", GIT_FILTER_TO_ODB, GIT_FILTER_DEFAULT) == GIT_OK);
    REQUIRE(cleanFilters != nullptr);
    CHECK(git_filter_list_contains(cleanFilters, "lfs") == 1);

    git_buf cleanOut = GIT_BUF_INIT;
    REQUIRE(git_filter_list_apply_to_file(&cleanOut, cleanFilters, repo, "red.png") == GIT_OK);
    REQUIRE(cleanOut.size > 0);

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(QByteArray(cleanOut.ptr, static_cast<int>(cleanOut.size)), &pointer));
    CHECK(pointer.size == workingTreeBytes.size());

    const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(repo))).absolutePath();
    const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
    CHECK(QFile::exists(objectPath));

    CHECK(QFile::exists(imagePath));
    const QByteArray workingTreeBytesAfter = readFileBytes(imagePath);
    CHECK(workingTreeBytesAfter == workingTreeBytes);

    git_filter_list* smudgeFilters = nullptr;
    REQUIRE(git_filter_list_load(&smudgeFilters, repo, nullptr, "red.png", GIT_FILTER_TO_WORKTREE, GIT_FILTER_DEFAULT) == GIT_OK);
    REQUIRE(smudgeFilters != nullptr);
    CHECK(git_filter_list_contains(smudgeFilters, "lfs") == 1);

    git_buf smudgeOut = GIT_BUF_INIT;
    REQUIRE(git_filter_list_apply_to_buffer(&smudgeOut,
                                            smudgeFilters,
                                            cleanOut.ptr,
                                            static_cast<size_t>(cleanOut.size)) == GIT_OK);
    REQUIRE(smudgeOut.size == static_cast<size_t>(workingTreeBytes.size()));
    CHECK(QByteArray(smudgeOut.ptr, static_cast<int>(smudgeOut.size)) == workingTreeBytes);

    git_buf_dispose(&cleanOut);
    git_buf_dispose(&smudgeOut);
    git_filter_list_free(cleanFilters);
    git_filter_list_free(smudgeFilters);
    git_repository_free(repo);
}

TEST_CASE("Lfs commit via GitRepository stores pointer and checkout restores PNG", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.initRepository();

    const QString attributesPath = repoDir.filePath(QStringLiteral(".gitattributes"));
    REQUIRE(QFile::exists(attributesPath));

    const QString imageFileName = QStringLiteral("red.png");
    const QString imagePath = repoDir.filePath(imageFileName);

    QImage image(10, 10, QImage::Format_ARGB32);
    image.fill(Qt::red);
    REQUIRE(image.save(imagePath, "PNG"));

    const QByteArray workingTreeBytes = readFileBytes(imagePath);
    REQUIRE(!workingTreeBytes.isEmpty());

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    repository.setAccount(&account);

    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add png"), QStringLiteral("LFS test")));

    CHECK(QFile::exists(imagePath));
    CHECK(readFileBytes(imagePath) == workingTreeBytes);

    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoDir.absolutePath().toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(repo != nullptr);

    const QByteArray blobData = readBlobFromHead(repo, "red.png");
    REQUIRE(!blobData.isEmpty());

    LfsPointer pointer;
    REQUIRE(LfsPointer::parse(blobData, &pointer));
    CHECK(pointer.size == workingTreeBytes.size());
    CHECK(!pointer.oid.isEmpty());

    QFile file(imagePath);
    REQUIRE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    file.write("corrupt");
    file.close();

    REQUIRE_NOTHROW(repository.resetHard(QStringLiteral("HEAD")));
    CHECK(readFileBytes(imagePath) == workingTreeBytes);
    repository.checkStatus();
    CHECK(repository.modifiedFileCount() == 0);

    git_repository_free(repo);
}

TEST_CASE("Lfs commits keep working tree PNG for multiple commits", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());
    tempDir.setAutoRemove(false);
    qDebug() << "Temp dir:" << tempDir.path();

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.initRepository();

    const QString attributesPath = repoDir.filePath(QStringLiteral(".gitattributes"));
    REQUIRE(QFile::exists(attributesPath));

    Account account;
    account.setName(QStringLiteral("LFS Tester"));
    account.setEmail(QStringLiteral("lfs@test.invalid"));
    repository.setAccount(&account);

    const QString imageFileName = QStringLiteral("color.png");
    const QString imagePath = repoDir.filePath(imageFileName);

    const QByteArray redBytes = createPngFile(imagePath, Qt::red);
    REQUIRE(!redBytes.isEmpty());
    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add red"), QStringLiteral("LFS red")));

    git_repository* repo = nullptr;
    REQUIRE(git_repository_open(&repo, repoDir.absolutePath().toLocal8Bit().constData()) == GIT_OK);
    REQUIRE(repo != nullptr);
    const QString redCommit = headOidString(repo);
    REQUIRE(!redCommit.isEmpty());

    const QByteArray greenBytes = createPngFile(imagePath, Qt::green);
    REQUIRE(!greenBytes.isEmpty());
    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add green"), QStringLiteral("LFS green")));
    const QString greenCommit = headOidString(repo);
    REQUIRE(!greenCommit.isEmpty());

    const QByteArray blueBytes = createPngFile(imagePath, Qt::blue);
    REQUIRE(!blueBytes.isEmpty());
    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Add blue"), QStringLiteral("LFS blue")));
    const QString blueCommit = headOidString(repo);
    REQUIRE(!blueCommit.isEmpty());

    repository.createBranch(QStringLiteral("check"), QStringLiteral("HEAD"), false);

    REQUIRE_NOTHROW(repository.resetHard(redCommit));
    CHECK(readFileBytes(imagePath) == redBytes);

    REQUIRE_NOTHROW(repository.resetHard(greenCommit));
    CHECK(readFileBytes(imagePath) == greenBytes);

    REQUIRE_NOTHROW(repository.resetHard(blueCommit));
    CHECK(readFileBytes(imagePath) == blueBytes);

    git_repository_free(repo);
}

TEST_CASE("Lfs policy updates managed .gitattributes section", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.initRepository();

    LfsPolicy emptyPolicy;
    emptyPolicy.setAttributesSectionTag(QStringLiteral("qquickgit-test"));
    emptyPolicy.setDefaultRule([](const QString&, const QByteArray*) { return false; });
    repository.setLfsPolicy(emptyPolicy);

    const QString attributesPath = repoDir.filePath(QStringLiteral(".gitattributes"));
    const QByteArray initialContents = readFileBytes(attributesPath);
    const QByteArray beginMarker = QByteArray("# qquickgit-test:begin-lfs");
    const QByteArray endMarker = QByteArray("# qquickgit-test:end-lfs");
    REQUIRE(initialContents.contains(beginMarker));
    REQUIRE(initialContents.contains(endMarker));

    LfsPolicy updatedPolicy = emptyPolicy;
    updatedPolicy.setRule(QStringLiteral("png"), [](const QString&, const QByteArray*) { return true; });
    updatedPolicy.setRule(QStringLiteral("pdf"), [](const QString&, const QByteArray*) { return true; });
    repository.setLfsPolicy(updatedPolicy);

    const QByteArray updatedContents = readFileBytes(attributesPath);
    REQUIRE(updatedContents.contains(beginMarker));
    REQUIRE(updatedContents.contains(endMarker));
    CHECK(updatedContents.contains(QByteArray("*.png filter=lfs diff=lfs merge=lfs -text")));
    CHECK(updatedContents.contains(QByteArray("*.pdf filter=lfs diff=lfs merge=lfs -text")));
}

TEST_CASE("GitRepository resetHard discards local changes", "[GitRepository]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    const QDir repoDir(tempDir.path());
    GitRepository repository;
    repository.setDirectory(repoDir);
    repository.initRepository();

    Account account;
    account.setName(QStringLiteral("Reset Tester"));
    account.setEmail(QStringLiteral("reset@test.invalid"));
    repository.setAccount(&account);

    const QString filePath = repoDir.filePath(QStringLiteral("note.txt"));
    REQUIRE(writeTextFile(filePath, QByteArray("original\n")));
    REQUIRE_NOTHROW(repository.commitAll(QStringLiteral("Initial"), QStringLiteral("add note")));

    REQUIRE(writeTextFile(filePath, QByteArray("modified\n")));
    CHECK(readFileBytes(filePath) == QByteArray("modified\n"));

    REQUIRE_NOTHROW(repository.resetHard(QStringLiteral("HEAD")));
    CHECK(readFileBytes(filePath) == QByteArray("original\n"));

    repository.checkStatus();
    CHECK(repository.modifiedFileCount() == 0);
}

TEST_CASE("LfsStoreRegistry keeps store when other repository is alive", "[LFS]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    std::shared_ptr<LfsStore> storeA;
    {
        const QDir repoDir(tempDir.path());
        GitRepository repoA;
        repoA.setDirectory(repoDir);
        repoA.initRepository();
        storeA = repoA.lfsStore();
        REQUIRE(storeA);

        {
            GitRepository repoB;
            repoB.setDirectory(repoDir);
            repoB.initRepository();
            auto storeB = repoB.lfsStore();
            REQUIRE(storeB);
            REQUIRE(storeB == LfsStoreRegistry::storeFor(storeB->gitDirPath()));
        }

        REQUIRE(LfsStoreRegistry::storeFor(storeA->gitDirPath()) == storeA);
    }
}
