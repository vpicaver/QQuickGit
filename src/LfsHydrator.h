#ifndef LFSHYDRATOR_H
#define LFSHYDRATOR_H

//QQuickGit
#include "GitRepository.h"
#include "ProgressState.h"
#include "LfsFilter.h"
#include "LfsStore.h"
#include "LfsBatchClient.h"
#include "Monad/Result.h"

//libgit2
#include "git2.h"

//Qt
#include <QByteArray>
#include <QDir>
#include <QFuture>
#include <QString>
#include <QVector>

//std
#include <algorithm>
#include <functional>

namespace QQuickGit {
namespace LfsHydrator {

// One worktree pointer file staged for hydration: its path, the object-store path its
// content lives at, and the parsed pointer.
struct PointerWorkItem {
    QString relativePath;
    QString objectPath;
    LfsPointer pointer;
};

// The plan for hydrating a repository: every pointer file found, plus the subset whose
// object content is not yet present locally and must be downloaded.
struct LfsHydrationPlan {
    QString workDir;
    QString gitDirPath;
    QVector<PointerWorkItem> pointerFiles;
    QVector<LfsPointer> missingPointers;
};

// Progress sink shared by the LFS upload (push) and download (clone/fetch/pull) paths:
// human-readable text, completed objects, total objects.
using LfsTransferProgress = std::function<void(const QString& text, int current, int total)>;

Monad::Result<LfsHydrationPlan> buildLfsHydrationPlan(git_repository* repo);

QFuture<Monad::Result<LfsHydrationPlan>> prepareLfsHydrationPlan(const QDir& repositoryDir);

GitRepository::GitFuture runLfsHydrationPipeline(const LfsHydrationPlan& plan,
                                                 QObject* context,
                                                 const LfsTransferProgress& progress = {});

GitRepository::GitFuture runLfsHydrationForDirectory(const QDir& repositoryDir,
                                                     QObject* context,
                                                     const LfsTransferProgress& progress = {});

GitRepository::GitFuture runLfsPrePushUpload(const QByteArray& repoPath,
                                             const QString& refSpec,
                                             const QString& remoteName,
                                             QObject* context,
                                             const QString& httpsToken = QString(),
                                             const LfsTransferProgress& progress = {});

GitRepository::MergeFuture runMergeHydrationForDirectory(const Monad::Result<GitRepository::MergeResult>& mergeResult,
                                                         const QDir& repositoryDir,
                                                         QObject* context,
                                                         const LfsTransferProgress& progress = {});

//Builds the LFS-hydration progress callback shared by clone/fetch/pull/pullRebaseOrMerge.
//The QFutureInterface is copied into the returned callback so it outlives the caller frame.
template<typename ProgressInterface>
LfsTransferProgress makeLfsTransferProgress(ProgressInterface progressInterface) {
    return [progressInterface](const QString& text, int current, int total) mutable {
        const int safeTotal = std::max(1, total);
        const int safeCurrent = std::clamp(current, 0, safeTotal);
        setProgress(&progressInterface,
                    ProgressState(text,
                                  static_cast<size_t>(safeCurrent),
                                  static_cast<size_t>(safeTotal)));
    };
}

} // namespace LfsHydrator
} // namespace QQuickGit

#endif // LFSHYDRATOR_H
