#ifndef GITFUTUREWATCHER_H
#define GITFUTUREWATCHER_H

//Our inculdes
#include "Monad/Result.h"
#include "GitRepository.h"
#include "AbstractGitFutureWatcher.h"

//Qt includes
#include <QObject>
#include <QQmlEngine>

namespace QQuickGit {

class GitFutureWatcher : public AbstractGitFutureWatcher
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(GitRepository::GitFuture future READ future WRITE setFuture NOTIFY futureChanged)
public:
    explicit GitFutureWatcher(QObject *parent = nullptr);

    GitRepository::GitFuture future() const;
    void setFuture(const GitRepository::GitFuture &future);

signals:
    void futureChanged();

private:
    GitRepository::GitFuture mFuture; //!<
};

inline GitRepository::GitFuture GitFutureWatcher::future() const {
    return mFuture;
}
}

#endif // GITFUTUREWATCHER_H
