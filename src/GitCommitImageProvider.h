#ifndef GITCOMMITIMAGEPROVIDER_H
#define GITCOMMITIMAGEPROVIDER_H

//Our includes
#include "QQuickGitExport.h"

//Qt includes
#include <QQuickImageProvider>
#include <QReadWriteLock>
#include <QHash>

namespace QQuickGit {

class QQUICKGIT_EXPORT GitCommitImageProvider : public QQuickImageProvider
{
public:
    GitCommitImageProvider();

    QImage requestImage(const QString& id, QSize* size, const QSize& requestedSize) override;

    int registerRepository(const QString& repoPath);
    void unregisterRepository(int id);

    static GitCommitImageProvider* registerOn(QQmlEngine* engine);
    static GitCommitImageProvider* instance();

private:
    static GitCommitImageProvider* sInstance;
    QReadWriteLock mLock;
    QHash<int, QString> mRepos;
    int mNextId = 1;
};

} // namespace QQuickGit

#endif // GITCOMMITIMAGEPROVIDER_H
