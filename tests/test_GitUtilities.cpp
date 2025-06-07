//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "GitUtilities.h"

//Qt includes
#include <QList>
#include <QString>
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
