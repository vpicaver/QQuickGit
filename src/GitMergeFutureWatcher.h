#ifndef GITMERGEFUTUREWATCHER_H
#define GITMERGEFUTUREWATCHER_H

//Our includes
#include "QQuickGitExport.h"
#include "GitFutureWatcher.h"

//Qt includes
#include <QObject>
namespace QQuickGit {
class QQUICKGIT_EXPORT GitMergeFutureWatcher : public AbstractGitFutureWatcher
{
    Q_OBJECT

    Q_PROPERTY(GitRepository::MergeFuture future READ future WRITE setFuture NOTIFY futureChanged)

public:
    explicit GitMergeFutureWatcher(QObject *parent = nullptr);

    GitRepository::MergeFuture future() const;
    void setFuture(const GitRepository::MergeFuture &future);

signals:
    void futureChanged();

private:
    GitRepository::MergeFuture mMergeFuture; //!<
};

inline GitRepository::MergeFuture GitMergeFutureWatcher::future() const {
    return mMergeFuture;
}
}

#endif // GITMERGEFUTUREWATCHER_H
