//Our includes
#include "GitCommitImageProvider.h"
#include "GitRepository.h"
#include "LfsStore.h"

//Qt includes
#include <QImage>
#include <QQmlEngine>

using namespace QQuickGit;

GitCommitImageProvider* GitCommitImageProvider::sInstance = nullptr;

GitCommitImageProvider::GitCommitImageProvider()
    : QQuickImageProvider(QQuickImageProvider::Image)
{
    sInstance = this;
}

GitCommitImageProvider::~GitCommitImageProvider()
{
    if (sInstance == this) {
        sInstance = nullptr;
    }
}

/**
 * URL format: "<repo-id>/<40-char-sha>/<file-path>"
 *
 * The repo-id is an integer assigned by registerRepository().
 * The SHA is exactly 40 hex characters.
 * The file path is everything after the second '/' and may contain '/'.
 */
QImage GitCommitImageProvider::requestImage(const QString& id, QSize* size, const QSize& requestedSize)
{
    const int firstSlash = id.indexOf(QLatin1Char('/'));
    if (firstSlash < 1) {
        return {};
    }

    bool ok = false;
    const int repoId = id.left(firstSlash).toInt(&ok);
    if (!ok) {
        return {};
    }

    const int shaStart = firstSlash + 1;
    if (id.size() < shaStart + 41) {
        return {};
    }
    const QString sha = id.mid(shaStart, 40);

    const int pathStart = shaStart + 41;
    if (pathStart >= id.size()) {
        return {};
    }
    const QString filePath = id.mid(pathStart);

    QString repoPath;
    {
        QReadLocker locker(&mLock);
        auto it = mRepos.constFind(repoId);
        if (it == mRepos.constEnd()) {
            return {};
        }
        repoPath = it.value();
    }

    auto result = GitRepository::fileContentAtCommit(repoPath, sha, filePath);
    if (result.hasError() || result.value().isEmpty()) {
        return {};
    }

    QByteArray content = result.value();

    LfsPointer pointer;
    if (LfsPointer::parse(content, &pointer)) {
        const QString gitDir = repoPath + QStringLiteral("/.git");
        LfsStore store(gitDir);
        auto lfsResult = store.readObject(pointer.oid);
        if (lfsResult.hasError()) {
            qWarning("GitCommitImageProvider: LFS object not found for %s (oid=%s)",
                     qPrintable(filePath), qPrintable(pointer.oid));
            return {};
        }
        content = lfsResult.value();
    }

    QImage image;
    image.loadFromData(content);

    if (!image.isNull() && requestedSize.isValid()
        && (image.width() > requestedSize.width() || image.height() > requestedSize.height())) {
        image = image.scaled(requestedSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);
    }

    if (size) {
        *size = image.size();
    }

    return image;
}

int GitCommitImageProvider::registerRepository(const QString& repoPath)
{
    QWriteLocker locker(&mLock);
    const int id = mNextId++;
    mRepos.insert(id, repoPath);
    return id;
}

void GitCommitImageProvider::unregisterRepository(int id)
{
    QWriteLocker locker(&mLock);
    mRepos.remove(id);
}

GitCommitImageProvider* GitCommitImageProvider::registerOn(QQmlEngine* engine)
{
    auto* provider = new GitCommitImageProvider;
    engine->addImageProvider(QStringLiteral("gitcommit"), provider);
    return provider;
}

GitCommitImageProvider* GitCommitImageProvider::instance()
{
    return sInstance;
}
