//Our includes
#include "ProgressReporting.h"

//Std includes
#include <algorithm>

namespace QQuickGit {

void setFutureProgress(QFutureInterfaceBase* progressInterface, const QString& text)
{
    if (!text.isEmpty()) {
        //We have to increment the progress by one to signal that the text changes
        progressInterface->setProgressValueAndText(progressInterface->progressValue() + 1, text);
    }
}

void setFutureProgress(QFutureInterfaceBase* progressInterface, const ProgressState& state)
{
    const int total = static_cast<int>(state.total());
    const int current = static_cast<int>(state.current());
    const bool hasRange = total > 0;

    const auto nextValue = [&](int previousValue) {
        const int value = std::max(current, previousValue + 1);
        return hasRange ? std::min(value, total) : value;
    };

    if (total != progressInterface->progressMaximum()) {
        progressInterface->setProgressRange(0, total);
    }

    int value = nextValue(progressInterface->progressValue());
    if (value <= progressInterface->progressValue()) {
        //Already at the total: restart the range so Qt accepts the new text
        progressInterface->setProgressRange(0, total);
        value = nextValue(progressInterface->progressValue());
    }

    const QString text = state.toJsonString();
    if (!text.isEmpty()) {
        progressInterface->setProgressValueAndText(value, text);
    }
}

}
