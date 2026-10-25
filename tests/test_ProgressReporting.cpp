//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "ProgressReporting.h"
#include "ProgressState.h"

//Qt includes
#include <QFutureInterface>

using namespace QQuickGit;

namespace {

struct ObservedProgress {
    int value = 0;
    int maximum = 0;
    ProgressState state;
};

ObservedProgress report(QFutureInterface<int>* progressInterface, const ProgressState& state)
{
    setFutureProgress(progressInterface, state);
    return {progressInterface->progressValue(),
            progressInterface->progressMaximum(),
            ProgressState::fromJson(progressInterface->progressText())};
}

}

TEST_CASE("setFutureProgress tracks the callback's current value", "[ProgressReporting]") {
    QFutureInterface<int> progressInterface;
    progressInterface.reportStarted();

    const auto first = report(&progressInterface, ProgressState(QStringLiteral("Fetching ... 1 MB"), 10, 1000));
    CHECK(first.maximum == 1000);
    CHECK(first.value == 10);
    CHECK(first.state.text() == QStringLiteral("Fetching ... 1 MB"));
    CHECK(first.state.current() == 10);
    CHECK(first.state.total() == 1000);

    const auto second = report(&progressInterface, ProgressState(QStringLiteral("Fetching ... 2 MB"), 250, 1000));
    CHECK(second.maximum == 1000);
    CHECK(second.value == 250);
    CHECK(second.state.text() == QStringLiteral("Fetching ... 2 MB"));
    CHECK(second.state.current() == 250);

    const auto third = report(&progressInterface, ProgressState(QStringLiteral("Fetching ... 9 MB"), 900, 1000));
    CHECK(third.maximum == 1000);
    CHECK(third.value == 900);
    CHECK(third.state.text() == QStringLiteral("Fetching ... 9 MB"));
    CHECK(third.state.current() == 900);

    progressInterface.reportFinished();
}

TEST_CASE("setFutureProgress publishes a new text when current does not advance", "[ProgressReporting]") {
    QFutureInterface<int> progressInterface;
    progressInterface.reportStarted();

    const auto first = report(&progressInterface, ProgressState(QStringLiteral("Fetching ... 1 MB"), 10, 1000));
    CHECK(first.value == 10);

    const auto repeated = report(&progressInterface, ProgressState(QStringLiteral("Fetching ... 2 MB"), 10, 1000));
    CHECK(repeated.value == 11);
    CHECK(repeated.state.text() == QStringLiteral("Fetching ... 2 MB"));
    CHECK(repeated.state.current() == 10);

    progressInterface.reportFinished();
}

TEST_CASE("setFutureProgress resets the value when the total changes", "[ProgressReporting]") {
    QFutureInterface<int> progressInterface;
    progressInterface.reportStarted();

    const auto fetching = report(&progressInterface, ProgressState(QStringLiteral("Fetching"), 900, 1000));
    CHECK(fetching.value == 900);
    CHECK(fetching.maximum == 1000);

    const auto downloading = report(&progressInterface, ProgressState(QStringLiteral("Downloading files"), 3, 41));
    CHECK(downloading.maximum == 41);
    CHECK(downloading.value == 3);
    CHECK(downloading.state.text() == QStringLiteral("Downloading files"));

    const auto merging = report(&progressInterface, ProgressState(QStringLiteral("Merging"), 0, 1));
    CHECK(merging.maximum == 1);
    CHECK(merging.value == 1);
    CHECK(merging.state.text() == QStringLiteral("Merging"));

    progressInterface.reportFinished();
}

TEST_CASE("setFutureProgress publishes a new text when the value is already at the total", "[ProgressReporting]") {
    QFutureInterface<int> progressInterface;
    progressInterface.reportStarted();

    const auto merging = report(&progressInterface, ProgressState(QStringLiteral("Merging"), 0, 1));
    CHECK(merging.value == 1);
    CHECK(merging.state.text() == QStringLiteral("Merging"));

    const auto downloading = report(&progressInterface, ProgressState(QStringLiteral("Downloading files"), 0, 1));
    CHECK(downloading.maximum == 1);
    CHECK(downloading.value == 1);
    CHECK(downloading.state.text() == QStringLiteral("Downloading files"));
    CHECK(downloading.state.current() == 0);

    const auto downloaded = report(&progressInterface, ProgressState(QStringLiteral("Downloading files"), 1, 1));
    CHECK(downloaded.value == 1);
    CHECK(downloaded.state.text() == QStringLiteral("Downloading files"));
    CHECK(downloaded.state.current() == 1);

    progressInterface.reportFinished();
}
