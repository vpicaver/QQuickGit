//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "GitRemotesModel.h"

//Qt includes
#include <QSignalSpy>

using namespace QQuickGit;

TEST_CASE("GitRemotesModel should set and get correctly", "[GitRemotesModel]") {
    GitRemotesModel model;

    QSignalSpy resetSpy(&model, &GitRemotesModel::modelReset);
    QSignalSpy remotesChangedSpy(&model, &GitRemotesModel::remotesChanged);
    QSignalSpy countSpy(&model, &GitRemotesModel::countChanged);

    QVector<GitRemoteInfo> remotes = {
        {"test", QUrl("http://google.com")},
        {"origin", QUrl("ssh://google.com")}
    };

    model.setRemotes(remotes);
    CHECK(model.remotes() == remotes);

    CHECK(resetSpy.count() == 1);
    CHECK(remotesChangedSpy.count() == 1);
    CHECK(countSpy.count() == 1);
    CHECK(model.rowCount() == 2);
    CHECK(model.count() == 2);

    for(int i = 0; i < remotes.size(); i++) {
        auto index = model.index(i);
        auto remote = remotes.at(i);
        CHECK(index.data(GitRemotesModel::NameRole).toString().toStdString() == remote.name().toStdString());
        CHECK(index.data(GitRemotesModel::UrlRole).toUrl().toString().toStdString() == remote.url().toString().toStdString());
    }

    CHECK(model.roleNames() == QHash<int, QByteArray>({
                                                          {GitRemotesModel::NameRole, QByteArrayLiteral("nameRole")},
                                                          {GitRemotesModel::UrlRole, QByteArrayLiteral("urlRole")}
                                                      }));

}
