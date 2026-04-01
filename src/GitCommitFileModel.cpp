//Our includes
#include "GitCommitFileModel.h"
#include "CommitDiffContext.h"
#include "GitConcurrent.h"
#include "GitRepository.h"

//Async includes
#include "asyncfuture.h"

//Qt includes
#include <QDir>

//std includes
#include <utility>

//libgit2
#include "git2.h"

using namespace QQuickGit;

GitCommitFileModel::GitCommitFileModel(QObject* parent)
    : QAbstractListModel(parent)
{
}

GitCommitFileModel::~GitCommitFileModel()
{
    cancelAllLineStatFutures();
}

void GitCommitFileModel::setCommitInfo(GitCommitInfo* info)
{
    if (mCommitInfo == info) {
        return;
    }

    if (mCommitInfo) {
        disconnect(mCommitInfo, nullptr, this, nullptr);
    }

    mCommitInfo = info;

    if (mCommitInfo)
    {
        connect(mCommitInfo, &GitCommitInfo::fileListReady,
                this, &GitCommitFileModel::onFileListReady);
        connect(mCommitInfo, &GitCommitInfo::loadingChanged,
                this, &GitCommitFileModel::loadingChanged);
        connect(mCommitInfo, &GitCommitInfo::errorMessageChanged,
                this, &GitCommitFileModel::errorMessageChanged);
    }

    emit commitInfoChanged();
}

bool GitCommitFileModel::loading() const
{
    return mCommitInfo ? mCommitInfo->loading() : false;
}

QString GitCommitFileModel::errorMessage() const
{
    return mCommitInfo ? mCommitInfo->errorMessage() : QString();
}

int GitCommitFileModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return mFiles.size();
}

QVariant GitCommitFileModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= mFiles.size()) {
        return QVariant();
    }

    const auto& entry = mFiles.at(index.row());

    switch (role)
    {
    case FilePathRole:
        return entry.filePath;
    case OldFilePathRole:
        return entry.oldFilePath;
    case StatusRole:
        return entry.status;
    case StatusTextRole:
        return entry.statusText;
    case IsBinaryRole:
        return entry.isBinary;
    case IsImageRole:
        return entry.isImage;
    case AddedLinesRole: {
        auto it = mLineStatsCache.constFind(index.row());
        return it != mLineStatsCache.constEnd() ? it->added : -1;
    }
    case DeletedLinesRole: {
        auto it = mLineStatsCache.constFind(index.row());
        return it != mLineStatsCache.constEnd() ? it->deleted : -1;
    }
    case LineStatsFetchedRole:
        return mLineStatsCache.contains(index.row());
    }

    return QVariant();
}

QHash<int, QByteArray> GitCommitFileModel::roleNames() const
{
    static const QHash<int, QByteArray> roles {
        {FilePathRole, "filePath"},
        {OldFilePathRole, "oldFilePath"},
        {StatusRole, "status"},
        {StatusTextRole, "statusText"},
        {IsBinaryRole, "isBinary"},
        {IsImageRole, "isImage"},
        {AddedLinesRole, "addedLines"},
        {DeletedLinesRole, "deletedLines"},
        {LineStatsFetchedRole, "lineStatsFetched"}
    };
    return roles;
}

void GitCommitFileModel::fetchLineStats(int row)
{
    if (row < 0 || row >= mFiles.size()) {
        return;
    }

    if (mLineStatsCache.contains(row)) {
        return;
    }

    if (mLineStatFutures.contains(row)) {
        return;
    }

    if (!mCommitInfo || !mCommitInfo->repository()) {
        return;
    }

    QDir dir = mCommitInfo->repository()->directory();
    if (!dir.exists()) {
        return;
    }

    QString repoPath = dir.absolutePath();
    QString commitSha = mCommitInfo->commitSha();
    int parentIndex = mCommitInfo->parentIndex();
    QString filePath = mFiles.at(row).filePath;

    auto future = GitConcurrent::run([repoPath, commitSha, parentIndex, filePath]() -> LineStats {
        LineStats stats;

        QString errorMessage;
        auto ctx = CommitDiffContext::open(repoPath, commitSha, parentIndex, errorMessage);
        if (!ctx) {
            return stats;
        }

        git_diff* diff = nullptr;
        git_diff_options diffOptions = GIT_DIFF_OPTIONS_INIT;
        QByteArray pathBytes = filePath.toUtf8();
        const char* pathspec = pathBytes.constData();
        diffOptions.pathspec.strings = const_cast<char**>(&pathspec);
        diffOptions.pathspec.count = 1;

        if (git_diff_tree_to_tree(&diff, ctx->repo.get(), ctx->parentTree.get(),
                                  ctx->commitTree.get(), &diffOptions) != GIT_OK || !diff) {
            return stats;
        }
        std::unique_ptr<git_diff, decltype(&git_diff_free)> diffHolder(diff, &git_diff_free);

        size_t deltaCount = git_diff_num_deltas(diff);
        if (deltaCount == 0) {
            return stats;
        }

        git_patch* patch = nullptr;
        if (git_patch_from_diff(&patch, diff, 0) != GIT_OK || !patch) {
            return stats;
        }
        std::unique_ptr<git_patch, decltype(&git_patch_free)> patchHolder(patch, &git_patch_free);

        size_t totalContext = 0, totalAdded = 0, totalDeleted = 0;
        if (git_patch_line_stats(&totalContext, &totalAdded, &totalDeleted, patch) == GIT_OK)
        {
            stats.added = static_cast<int>(totalAdded);
            stats.deleted = static_cast<int>(totalDeleted);
        }

        return stats;
    });

    mLineStatFutures.insert(row, future);

    AsyncFuture::observe(future).context(this, [this, row, future]() {
        mLineStatFutures.remove(row);

        if (future.isCanceled()) {
            return;
        }

        LineStats stats = future.result();
        mLineStatsCache.insert(row, stats);

        QModelIndex idx = index(row);
        emit dataChanged(idx, idx, {AddedLinesRole, DeletedLinesRole, LineStatsFetchedRole});
    });
}

void GitCommitFileModel::onFileListReady(const QVector<CommitLoadResult::FileEntry>& files)
{
    cancelAllLineStatFutures();

    beginResetModel();
    mFiles = files;
    mLineStatsCache.clear();
    endResetModel();
}

void GitCommitFileModel::cancelAllLineStatFutures()
{
    // Move futures out first — cancel can deliver queued signals via the event
    // loop, which could re-enter this function through onFileListReady.
    auto futures = std::exchange(mLineStatFutures, {});

    for (auto& future : futures) {
        future.cancel();
    }
}
