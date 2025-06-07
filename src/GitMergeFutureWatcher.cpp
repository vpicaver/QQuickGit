#include "GitMergeFutureWatcher.h"

using namespace QQuickGit;

GitMergeFutureWatcher::GitMergeFutureWatcher(QObject *parent) : AbstractGitFutureWatcher(parent)
{

}

void GitMergeFutureWatcher::setFuture(const GitRepository::MergeFuture& mergeFuture) {
    mMergeFuture = mergeFuture;
    watchProgress(mergeFuture,
                  [this, mergeFuture]()
    {
        watchFuture(mergeFuture, [mergeFuture, this](const Monad::Result<GitRepository::MergeResult> result) {
            auto stateToString = [](GitRepository::MergeResult::State state) {
                switch(state) {
                case GitRepository::MergeResult::UnknownState:
                    return QStringLiteral("Unknown merge state");
                case GitRepository::MergeResult::AlreadyUpToDate:
                    return QStringLiteral("Already up to date");
                case GitRepository::MergeResult::FastForward:
                    return QStringLiteral("Success!");
                case GitRepository::MergeResult::MergeCommitCreated:
                    return QStringLiteral("Success!");
                case GitRepository::MergeResult::MergeConflicts:
                    return QStringLiteral("Merge Conflicts");
                }
            };
            setProgress(ProgressState(stateToString(result.value().state()), 1, 1));
        });
    });
    emit futureChanged();
}
