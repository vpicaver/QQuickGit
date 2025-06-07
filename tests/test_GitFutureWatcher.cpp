//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "GitFutureWatcher.h"
#include "GitRepository.h"
#include <SignalSpyChecker.h>
using namespace SignalSpyChecker;

//Async includes
#include "asyncfuture.h"

//Qt includes
#include <QDir>

const int timeout = 30000;

using namespace QQuickGit;

//This test case is flakey
TEST_CASE("GitFutureWatcher should watch git repository futures correctly", "[GitFutureWatcher]") {

    QDir cloneDir("clone-test");

    INFO("Dir:" << QDir::toNativeSeparators(cloneDir.absolutePath()).toStdString());
    CHECK(cloneDir.removeRecursively());

    GitRepository repository;
    repository.setDirectory(cloneDir);

    //Need a bigger repo
    auto future = repository.clone(QUrl("ssh://git@github.com/cavewhere/cavewhere.git"));

    //If this fails, the clone could have happened before getting here
    CHECK(!future.isFinished());

    GitFutureWatcher watcher;
    auto checker = Constant::makeChecker(&watcher);
    watcher.setFuture(future);

    auto progressSpy = checker.findSpy(&GitFutureWatcher::progressChanged);
    checker.remove(progressSpy);
    auto progressTextSpy = checker.findSpy(&GitFutureWatcher::progressTextChanged);
    checker.remove(progressTextSpy);

    checker[checker.findSpy(&GitFutureWatcher::stateChanged)]++;
    checker[checker.findSpy(&GitFutureWatcher::futureChanged)]++;
    checker.checkSpies();

    //If this timeout is too short, it might cause a crash
    REQUIRE(AsyncFuture::waitForFinished(future, timeout));

    checker[checker.findSpy(&GitFutureWatcher::stateChanged)]++;
    checker.checkSpies();

    CHECK(progressSpy->count() > 0);
    CHECK(progressTextSpy->count() > 0);

    CHECK(watcher.progress() == 1.0);
    CHECK(watcher.state() == GitFutureWatcher::Ready);
    INFO("Error message:" << watcher.errorMessage().toStdString());
    CHECK(watcher.errorMessage().isEmpty());
}

TEST_CASE("GitFutureWatcher Test bad url handling", "[GitFutureWatcher]") {

    QDir cloneDir("clone-test");

    INFO("Dir:" << QDir::toNativeSeparators(cloneDir.absolutePath()).toStdString());
    CHECK(cloneDir.removeRecursively());

    GitRepository repository;
    repository.setDirectory(cloneDir);

    auto future = repository.clone(QUrl("ssh://git@github.com/vpicaver/bad-url-aoeu.git"));

    GitFutureWatcher watcher;
    auto checker = Constant::makeChecker(&watcher);
    watcher.setFuture(future);

    REQUIRE(AsyncFuture::waitForFinished(future, timeout));

    CHECK(!watcher.errorMessage().isEmpty());
    CHECK(watcher.errorMessage().toStdString() == "ERROR: Repository not found.");
}
