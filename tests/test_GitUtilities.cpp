//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "GitUtilities.h"

//Qt includes
#include <QClipboard>
#include <QGuiApplication>
#include <QList>
#include <QString>
#include <QTemporaryDir>
#include <QUrl>

using namespace QQuickGit;

TEST_CASE("GitUtilities should fix up ssh url correctly", "[GitUtilities]") {

    GitUtilities utils;

    QList<std::pair<QString, QUrl>> tests {
        {"ssh://git@github.com/Cavewhere/cavewhere.git", QUrl("ssh://git@github.com/Cavewhere/cavewhere.git")},
        {"git@gitlab.com:caves.org/btcp/gis.git", QUrl("ssh://git@gitlab.com/caves.org/btcp/gis.git")},
        {"https://gitlab.com/caves.org/btcp/gis.git", QUrl("https://gitlab.com/caves.org/btcp/gis.git")},
        {QString(), QUrl()}
    };

    for(const auto& test : tests) {
        auto url = GitUtilities::fixGitUrl(test.first);
        CHECK(url.toString().toStdString() == test.second.toString().toStdString());

        QUrl url2;
        QMetaObject::invokeMethod(&utils, "fixGitUrl",
                                  Q_RETURN_ARG(QUrl, url2),
                                  Q_ARG(QString, test.first));

        CHECK(url2.toString().toStdString() == test.second.toString().toStdString());
    }
}

TEST_CASE("GitUtilities derives LFS endpoint from remote url", "[GitUtilities]")
{
    const QList<std::pair<QString, QString>> tests{
        {QStringLiteral("git@github.com:Cavewhere/PhakeCave3000.git"),
         QStringLiteral("https://github.com/Cavewhere/PhakeCave3000.git/info/lfs")},
        {QStringLiteral("ssh://git@github.com/Cavewhere/PhakeCave3000.git"),
         QStringLiteral("https://github.com/Cavewhere/PhakeCave3000.git/info/lfs")},
        {QStringLiteral("https://github.com/Cavewhere/PhakeCave3000.git"),
         QStringLiteral("https://github.com/Cavewhere/PhakeCave3000.git/info/lfs")},
        {QStringLiteral("http://example.com/repo.git/"),
         QStringLiteral("http://example.com/repo.git/info/lfs")}
    };

    for (const auto& test : tests) {
        const QUrl endpoint = GitUtilities::lfsEndpointFromRemoteUrl(test.first);
        CHECK(endpoint.toString().toStdString() == test.second.toStdString());
    }
}

TEST_CASE("GitUtilities rejects unsupported LFS endpoint remote urls", "[GitUtilities]")
{
    CHECK(GitUtilities::lfsEndpointFromRemoteUrl(QString()).isEmpty());
    CHECK(GitUtilities::lfsEndpointFromRemoteUrl(QStringLiteral("file:///tmp/repo.git")).isEmpty());
}

TEST_CASE("GitUtilities copyToClipboard sets clipboard text", "[GitUtilities]")
{
    auto* clipboard = QGuiApplication::clipboard();
    REQUIRE(clipboard != nullptr);

    clipboard->clear();
    GitUtilities::copyToClipboard(QStringLiteral("/some/absolute/path.txt"));
    CHECK(clipboard->text().toStdString() == "/some/absolute/path.txt");

    GitUtilities::copyToClipboard(QStringLiteral(""));
    CHECK(clipboard->text().toStdString() == "");
}

TEST_CASE("GitUtilities revealInFileManager does not crash on valid path", "[GitUtilities]")
{
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    // Should not crash when given a valid directory
    GitUtilities::revealInFileManager(tempDir.path());

    // Should not crash when given a valid file
    QFile file(QDir(tempDir.path()).filePath("test.txt"));
    REQUIRE(file.open(QFile::WriteOnly));
    file.write("test");
    file.close();
    GitUtilities::revealInFileManager(file.fileName());
}

TEST_CASE("GitUtilities revealInFileManager does not crash on nonexistent path", "[GitUtilities]")
{
    // Should not crash when given a nonexistent path
    GitUtilities::revealInFileManager(QStringLiteral("/nonexistent/path/to/file.txt"));
}
