#include "AbstractGitFutureWatcher.h"

AbstractGitFutureWatcher::AbstractGitFutureWatcher(QObject *parent) : AbstractResultFutureWatcher(parent)
{

}

double AbstractGitFutureWatcher::progress() const {
    return mProgressState.progress();
}

QString AbstractGitFutureWatcher::progressText() const {
    return mProgressState.text();
}

void AbstractGitFutureWatcher::setInitialProgressText(QString initialProgressText) {
    if(mInitialProgressText != initialProgressText) {
        mInitialProgressText = initialProgressText;
        emit initialProgressTextChanged();
    }
}

void AbstractGitFutureWatcher::setProgress(const ProgressState &newState) {
    if(!newState.text().isEmpty()) {
        mProgressState = newState;
        emit progressChanged();
        emit progressTextChanged();
    }
}
