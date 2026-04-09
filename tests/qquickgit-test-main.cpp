#define CATCH_CONFIG_RUNNER
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

//Qt includes
#include <QGuiApplication>
#include <QThread>
#include <QSettings>

//OpenSSL applink — must be in the .exe, not a DLL, so OpenSSL's
//shared library can find OPENSSL_Applink during cleanup at exit.
#ifdef Q_OS_WINDOWS
#include <openssl/applink.c>
#endif

//Our inculdes
#include "GitRepository.h"

using namespace QQuickGit;

int main( int argc, char* argv[] )
{
    QGuiApplication app(argc, argv);

    QGuiApplication::setOrganizationName("Vadose Solutions");
    QGuiApplication::setOrganizationDomain("cavewhere.com");
    QGuiApplication::setApplicationName("qquickgit-test");
    QGuiApplication::setApplicationVersion("1.0");

    GitRepository::initGitEngine();

    {
        QSettings settings;
        settings.clear();
    }

    app.thread()->setObjectName("Main QThread");

    int result = 0;
    QMetaObject::invokeMethod(&app, [&result, argc, argv]() {
        result = Catch::Session().run( argc, argv );
        QCoreApplication::quit();
    }, Qt::QueuedConnection);

    app.exec();

    GitRepository::shutdownGitEngine();

    return result;
}

