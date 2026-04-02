//Our includes
#include "TestUtilities.h"
#include "GitRepository.h"
#include "Account.h"

//Qt includes
#include <QUuid>
#include <QJsonDocument>
#include <QDirIterator>
#include <QFile>

//libgit2
#include "git2.h"

//Catch includes
#include <catch2/catch_test_macros.hpp>

TestUtilities::TestUtilities()
{

}

QDir TestUtilities::createUniqueTempDir()
{
    QDir tempDir = QDir::temp();
    auto tempDirId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    REQUIRE(tempDir.mkdir(tempDirId)); //If this fails the folder already exist, remove it, try again
    tempDir.cd(tempDirId);
    return tempDir;
}

QDir TestUtilities::moveToNewTempDirectory(const QDir &oldDirectory)
{
    auto newTemp = TestUtilities::createUniqueTempDir();

    QDir dir;
    REQUIRE(dir.rmdir(newTemp.absolutePath()));

    CHECK(oldDirectory.exists());
    CHECK(!newTemp.exists());
    INFO("Old direcotry:" << oldDirectory.absolutePath().toStdString());
    INFO("New directory:" << newTemp.absolutePath().toStdString());
    CHECK(dir.rename(oldDirectory.absolutePath(), newTemp.absolutePath()));
    CHECK(newTemp.exists());

    return newTemp;
}

std::ostream& operator<<(std::ostream& os, const QVariantMap& map)
{
    QJsonDocument doc = QJsonDocument::fromVariant(map);
    os << "\"" << doc.toJson(QJsonDocument::Compact).toStdString() << "\"";
    return os;
}

std::ostream& operator<<(std::ostream& os, const QModelIndex& index)
{
    os << "model:" << index.model() << " (" << index.row() << "," << index.column() << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, const QStringList& list) {
    for (int i = 0; i < list.size(); ++i) {
        os << list.at(i).toStdString();
        if (i != list.size() - 1)
            os << ", ";
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const QHash<int, QByteArray>& hash)
{
    os << "{ ";
    for(auto it = hash.begin(); it != hash.end(); ++it) {
        if(it != hash.begin()) {
            os << ", ";
        }
        os << it.key() << " : " << it.value().toStdString();
    }
    os << " }";
    return os;
}

void TestUtilities::createFileAndCommit(QQuickGit::GitRepository& repo, const QString& filename,
                                        const QString& content, const QString& message)
{
    QDir dir = repo.directory();
    QFile file(dir.filePath(filename));
    REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate | QFile::Text));
    file.write(content.toUtf8());
    file.close();

    repo.checkStatus();

    QQuickGit::Account account;
    account.setName("Test Author");
    account.setEmail("test@example.com");
    repo.setAccount(&account);
    repo.commitAll(message, QString());
    repo.checkStatus();
}

void TestUtilities::createBinaryFileAndCommit(QQuickGit::GitRepository& repo, const QString& filename,
                                              const QByteArray& content, const QString& message)
{
    QDir dir = repo.directory();
    QFile file(dir.filePath(filename));
    REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate));
    file.write(content);
    file.close();

    repo.checkStatus();

    QQuickGit::Account account;
    account.setName("Test Author");
    account.setEmail("test@example.com");
    repo.setAccount(&account);
    repo.commitAll(message, QString());
    repo.checkStatus();
}

void TestUtilities::deleteFileAndCommit(QQuickGit::GitRepository& repo, const QString& filename,
                                        const QString& message)
{
    QDir dir = repo.directory();
    QFile::remove(dir.filePath(filename));

    repo.checkStatus();

    QQuickGit::Account account;
    account.setName("Test Author");
    account.setEmail("test@example.com");
    repo.setAccount(&account);
    repo.commitAll(message, QString());
    repo.checkStatus();
}

QString TestUtilities::getHeadSha(const QDir& dir)
{
    git_repository* repo = nullptr;
    if (git_repository_open(&repo, dir.absolutePath().toLocal8Bit().constData()) != GIT_OK)
    {
        return {};
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)>
        repoHolder(repo, &git_repository_free);

    git_reference* headRef = nullptr;
    if (git_repository_head(&headRef, repo) != GIT_OK)
    {
        return {};
    }
    std::unique_ptr<git_reference, decltype(&git_reference_free)>
        refHolder(headRef, &git_reference_free);

    const git_oid* oid = git_reference_target(headRef);
    if (!oid)
    {
        return {};
    }

    char buffer[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(buffer, sizeof(buffer), oid);
    return QString::fromLatin1(buffer);
}
