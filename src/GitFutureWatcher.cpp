//Our includes
#include "GitFutureWatcher.h"

GitFutureWatcher::GitFutureWatcher(QObject *parent) : AbstractGitFutureWatcher(parent)
{

}

void GitFutureWatcher::setFuture(const GitRepository::GitFuture& future) {
    mFuture = future;
    watchProgress(mFuture);
    emit futureChanged();
}

