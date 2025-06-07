//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our inculdes
#include "GitTestConnection.h"

//Qt includes
#include <QEventLoop>
#include <QTimer>

//Std includes
#include <iostream>

using namespace QQuickGit;

TEST_CASE("GitTestConnection should async test a git connection", "[GitTestConnection]") {
    auto testConnection = [](const QUrl& url, const QString& message) {
        INFO("Url:" << url.toString().toStdString());

        GitTestConnection connection;
        CHECK(connection.state() == GitTestConnection::Ready);
        CHECK(connection.url().isEmpty());
        CHECK(connection.errorMessage().isEmpty());

        connection.setUrl(url);
        CHECK(connection.url() == url);

        bool canceled = false;

        QEventLoop loop;

        QObject::connect(&connection, &GitTestConnection::stateChanged, &loop, [&connection, &loop]() {
            if(connection.state() == GitTestConnection::Ready) {
                loop.quit();
            }
        });

        connection.test();
        CHECK(connection.state() == GitTestConnection::Testing);
        CHECK(connection.errorMessage().isEmpty());

        loop.exec();

        CHECK(canceled == false);
        CHECK(connection.state() == GitTestConnection::Ready);
        CHECK(connection.errorMessage().toStdString() == message.toStdString());
    };

    testConnection(QUrl("ssh://git@github.com/vpicaver/surfacewhere-testData.git"), QString());

    //Bad Urls
    testConnection(QUrl("ssh://git@github.com/vpicaver/surfacewher.git"), QString("ERROR: Repository not found."));

    std::cout << "Testing connect to a bad host, this will take a while (~20 secs)" << std::endl;
    testConnection(QUrl("ssh://192.168.1.2/test.git"), QString("failed to connect to 192.168.1.2: Operation timed out"));
    std::cout << "Done" << std::endl;

}

TEST_CASE("GitTestConnection should handle being deleted while running", "[GitTestConnection]") {

    {
        GitTestConnection connection;
        connection.setUrl(QUrl("xyz :D"));
        connection.test();
    }

    QEventLoop loop;
    QTimer::singleShot(1000, &loop, [&loop]() {
        loop.quit();
    });
    loop.exec();

    CHECK(true);
}
