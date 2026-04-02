//Our includes
#include "GitWorkingTreeModel.h"
#include "GitRepository.h"
#include "GitConcurrent.h"
#include "GitOidUtils.h"
#include "LfsStore.h"

//Async Future includes
#include "asyncfuture.h"

//LibGit2 includes
#include "git2.h"

//Qt includes
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QImageReader>
#include <QCryptographicHash>

using namespace QQuickGit;

namespace {

QByteArray blobBytesForIndexEntry(git_repository* repo, const QString& relativePath)
{
    if (repo == nullptr || relativePath.isEmpty())
        return {};

    git_index* index = nullptr;
    if (git_repository_index(&index, repo) != GIT_OK || index == nullptr)
        return {};
    std::unique_ptr<git_index, decltype(&git_index_free)> guard(index, &git_index_free);

    const QByteArray pathUtf8 = relativePath.toUtf8();
    const git_index_entry* ie = git_index_get_bypath(index, pathUtf8.constData(), 0);
    if (ie == nullptr || git_oid_is_zero(&ie->id))
        return {};

    return blobContent(repo, &ie->id);
}

QString statusEntryPath(const git_status_entry* entry)
{
    if (entry == nullptr)
        return {};

    if (entry->index_to_workdir && entry->index_to_workdir->new_file.path)
        return QString::fromUtf8(entry->index_to_workdir->new_file.path);
    if (entry->head_to_index && entry->head_to_index->new_file.path)
        return QString::fromUtf8(entry->head_to_index->new_file.path);
    return {};
}

QString statusEntryOldPath(const git_status_entry* entry)
{
    if (entry == nullptr)
        return {};

    if (entry->index_to_workdir && entry->index_to_workdir->old_file.path)
        return QString::fromUtf8(entry->index_to_workdir->old_file.path);
    if (entry->head_to_index && entry->head_to_index->old_file.path)
        return QString::fromUtf8(entry->head_to_index->old_file.path);
    return {};
}

bool isHydratedLfsFalsePositive(git_repository* repo,
                                const QString& workTreeRoot,
                                const git_status_entry* entry)
{
    if (repo == nullptr || entry == nullptr)
        return false;

    if (entry->status != GIT_STATUS_WT_MODIFIED)
        return false;

    const QString relativePath = statusEntryPath(entry);
    if (relativePath.isEmpty())
        return false;

    const QByteArray blobData = blobBytesForIndexEntry(repo, relativePath);
    if (blobData.isEmpty())
        return false;

    LfsPointer pointer;
    if (!LfsPointer::parse(blobData, &pointer) || !pointer.isValid())
        return false;

    const QString absolutePath = QDir(workTreeRoot).filePath(relativePath);
    const QFileInfo fileInfo(absolutePath);
    if (!fileInfo.exists() || !fileInfo.isFile() || fileInfo.size() != pointer.size)
        return false;

    QFile workingFile(absolutePath);
    if (!workingFile.open(QIODevice::ReadOnly))
        return false;

    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!workingFile.atEnd())
    {
        const QByteArray chunk = workingFile.read(256 * 1024);
        if (chunk.isEmpty() && workingFile.error() != QFile::NoError)
            return false;
        if (!chunk.isEmpty())
            hash.addData(chunk);
    }

    return QString::fromLatin1(hash.result().toHex()) == pointer.oid;
}

int mapStatusToGitDelta(unsigned int statusFlags)
{
    if (statusFlags & (GIT_STATUS_INDEX_NEW | GIT_STATUS_WT_NEW))
        return GIT_DELTA_ADDED;
    if (statusFlags & (GIT_STATUS_INDEX_DELETED | GIT_STATUS_WT_DELETED))
        return GIT_DELTA_DELETED;
    if (statusFlags & (GIT_STATUS_INDEX_RENAMED | GIT_STATUS_WT_RENAMED))
        return GIT_DELTA_RENAMED;
    if (statusFlags & (GIT_STATUS_INDEX_MODIFIED | GIT_STATUS_WT_MODIFIED))
        return GIT_DELTA_MODIFIED;
    if (statusFlags & (GIT_STATUS_INDEX_TYPECHANGE | GIT_STATUS_WT_TYPECHANGE))
        return GIT_DELTA_TYPECHANGE;
    return GIT_DELTA_UNMODIFIED;
}

QString statusToText(int delta)
{
    switch (delta)
    {
    case GIT_DELTA_ADDED:      return QStringLiteral("Added");
    case GIT_DELTA_DELETED:    return QStringLiteral("Deleted");
    case GIT_DELTA_MODIFIED:   return QStringLiteral("Modified");
    case GIT_DELTA_RENAMED:    return QStringLiteral("Renamed");
    case GIT_DELTA_TYPECHANGE: return QStringLiteral("Type Change");
    default:                   return QStringLiteral("Unknown");
    }
}

bool isBinaryFile(const git_status_entry* entry)
{
    if (entry == nullptr)
        return false;

    const git_diff_delta* delta = entry->index_to_workdir
                                      ? entry->index_to_workdir
                                      : entry->head_to_index;
    if (delta == nullptr)
        return false;

    if (delta->flags & GIT_DIFF_FLAG_BINARY)
        return true;

    return false;
}

bool isImageFile(const QString& filePath)
{
    static const QSet<QByteArray> supportedFormats = [] {
        const auto formats = QImageReader::supportedImageFormats();
        return QSet<QByteArray>(formats.begin(), formats.end());
    }();

    const QByteArray suffix = QFileInfo(filePath).suffix().toLower().toUtf8();
    return supportedFormats.contains(suffix);
}

WorkingTreeResult runStatusPass(const QString& repoPath)
{
    WorkingTreeResult result;

    git_repository* repo = nullptr;
    if (git_repository_open(&repo, repoPath.toUtf8().constData()) != GIT_OK)
    {
        const git_error* err = git_error_last();
        result.errorMessage = err ? QString::fromUtf8(err->message)
                                  : QStringLiteral("Failed to open repository");
        return result;
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoGuard(repo, &git_repository_free);

    git_status_list* list = nullptr;
    git_status_options opts = GIT_STATUS_OPTIONS_INIT;
    opts.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
    opts.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS;

    if (git_status_list_new(&list, repo, &opts) != GIT_OK)
    {
        const git_error* err = git_error_last();
        result.errorMessage = err ? QString::fromUtf8(err->message)
                                  : QStringLiteral("Failed to get status list");
        return result;
    }
    std::unique_ptr<git_status_list, decltype(&git_status_list_free)> listGuard(list, &git_status_list_free);

    const QString workTreeRoot = QDir(repoPath).absolutePath();
    const size_t entryCount = git_status_list_entrycount(list);

    for (size_t i = 0; i < entryCount; ++i)
    {
        const git_status_entry* entry = git_status_byindex(list, i);
        if (entry == nullptr || entry->status == GIT_STATUS_CURRENT)
            continue;

        if (isHydratedLfsFalsePositive(repo, workTreeRoot, entry))
            continue;

        const QString filePath = statusEntryPath(entry);
        const QString oldFilePath = statusEntryOldPath(entry);
        const int delta = mapStatusToGitDelta(entry->status);
        const bool binary = isBinaryFile(entry);
        const bool image = isImageFile(filePath);

        result.files.append({filePath, oldFilePath, delta, binary, image});
    }

    return result;
}

LineStatsResult runLineStats(const QString& repoPath, const QString& filePath)
{
    LineStatsResult result;

    git_repository* repo = nullptr;
    if (git_repository_open(&repo, repoPath.toUtf8().constData()) != GIT_OK)
    {
        const git_error* err = git_error_last();
        result.errorMessage = err ? QString::fromUtf8(err->message)
                                  : QStringLiteral("Failed to open repository");
        return result;
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoGuard(repo, &git_repository_free);

    git_reference* headRef = nullptr;
    git_object* headObj = nullptr;
    git_tree* headTree = nullptr;

    bool hasHead = false;
    if (git_repository_head(&headRef, repo) == GIT_OK)
    {
        std::unique_ptr<git_reference, decltype(&git_reference_free)> refGuard(headRef, &git_reference_free);
        if (git_reference_peel(&headObj, headRef, GIT_OBJECT_COMMIT) == GIT_OK)
        {
            std::unique_ptr<git_object, decltype(&git_object_free)> objGuard(headObj, &git_object_free);
            if (git_commit_tree(&headTree, reinterpret_cast<git_commit*>(headObj)) == GIT_OK)
            {
                hasHead = true;
            }
        }
    }
    std::unique_ptr<git_tree, decltype(&git_tree_free)> treeGuard(headTree, &git_tree_free);

    git_diff* diff = nullptr;
    git_diff_options diffOpts = GIT_DIFF_OPTIONS_INIT;
    const QByteArray pathUtf8 = filePath.toUtf8();
    const char* pathSpec = pathUtf8.constData();
    diffOpts.pathspec.strings = const_cast<char**>(&pathSpec);
    diffOpts.pathspec.count = 1;

    int rc = git_diff_tree_to_workdir_with_index(&diff, repo, hasHead ? headTree : nullptr, &diffOpts);
    if (rc != GIT_OK)
    {
        const git_error* err = git_error_last();
        result.errorMessage = err ? QString::fromUtf8(err->message)
                                  : QStringLiteral("Failed to create diff");
        return result;
    }
    std::unique_ptr<git_diff, decltype(&git_diff_free)> diffGuard(diff, &git_diff_free);

    const size_t numDeltas = git_diff_num_deltas(diff);
    for (size_t i = 0; i < numDeltas; ++i)
    {
        git_patch* patch = nullptr;
        if (git_patch_from_diff(&patch, diff, i) != GIT_OK || patch == nullptr)
            continue;
        std::unique_ptr<git_patch, decltype(&git_patch_free)> patchGuard(patch, &git_patch_free);

        size_t context = 0, additions = 0, deletions = 0;
        if (git_patch_line_stats(&context, &additions, &deletions, patch) == GIT_OK)
        {
            result.addedLines = static_cast<int>(additions);
            result.deletedLines = static_cast<int>(deletions);
        }
        break; // pathspec filtered to one file
    }

    if (result.addedLines == -1 && result.deletedLines == -1)
    {
        result.addedLines = 0;
        result.deletedLines = 0;
    }

    return result;
}

} // anonymous namespace

GitWorkingTreeModel::GitWorkingTreeModel(QObject* parent)
    : QAbstractListModel(parent)
    , mRestarter(this)
{
    mRestarter.onFutureChanged([this]() {
        auto future = mRestarter.future();
        AsyncFuture::observe(future).context(this, [this, future]() {
            if (future.isCanceled())
                return;

            auto result = future.result();
            const int oldCount = mRows.size();

            if (!mRows.isEmpty())
            {
                beginRemoveRows(QModelIndex(), 0, mRows.size() - 1);
                mRows.clear();
                endRemoveRows();
            }

            if (mErrorMessage != result.errorMessage)
            {
                mErrorMessage = result.errorMessage;
                emit errorMessageChanged();
            }

            if (!result.files.isEmpty())
            {
                beginInsertRows(QModelIndex(), 0, result.files.size() - 1);
                mRows.reserve(result.files.size());
                for (auto& fileEntry : result.files)
                {
                    mRows.append({std::move(fileEntry), -1, -1, false});
                }
                endInsertRows();
            }

            if (mRows.size() != oldCount)
                emit countChanged();

            if (mLoading)
            {
                mLoading = false;
                emit loadingChanged();
            }
        });
    });
}

GitWorkingTreeModel::~GitWorkingTreeModel()
{
    cancelLineStatsFutures();
    mRestarter.future().cancel();
}

void GitWorkingTreeModel::setRepository(GitRepository* repository)
{
    if (mRepository == repository)
        return;

    if (mRepository)
        disconnect(mRepository, nullptr, this, nullptr);

    mRepository = repository;

    if (mRepository)
    {
        connect(mRepository, &GitRepository::modifiedFileCountChanged,
                this, &GitWorkingTreeModel::refresh);
        connect(mRepository, &GitRepository::directoryChanged,
                this, &GitWorkingTreeModel::refresh);
    }

    emit repositoryChanged();

    if (!mRepository)
    {
        cancelLineStatsFutures();
        if (!mRows.isEmpty())
        {
            beginRemoveRows(QModelIndex(), 0, mRows.size() - 1);
            mRows.clear();
            endRemoveRows();
            emit countChanged();
        }
        return;
    }

    refresh();
}

int GitWorkingTreeModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid())
        return 0;
    return mRows.size();
}

QVariant GitWorkingTreeModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= mRows.size())
        return {};

    const RowData& row = mRows.at(index.row());

    switch (role)
    {
    case FilePathRole:         return row.entry.filePath;
    case OldFilePathRole:      return row.entry.oldFilePath;
    case StatusRole:           return row.entry.status;
    case StatusTextRole:       return statusToText(row.entry.status);
    case IsBinaryRole:         return row.entry.isBinary;
    case IsImageRole:          return row.entry.isImage;
    case AddedLinesRole:       return row.addedLines;
    case DeletedLinesRole:     return row.deletedLines;
    case LineStatsFetchedRole: return row.lineStatsFetched;
    }

    return {};
}

QHash<int, QByteArray> GitWorkingTreeModel::roleNames() const
{
    static const QHash<int, QByteArray> roles = {
        {FilePathRole,         "filePath"},
        {OldFilePathRole,      "oldFilePath"},
        {StatusRole,           "status"},
        {StatusTextRole,       "statusText"},
        {IsBinaryRole,         "isBinary"},
        {IsImageRole,          "isImage"},
        {AddedLinesRole,       "addedLines"},
        {DeletedLinesRole,     "deletedLines"},
        {LineStatsFetchedRole, "lineStatsFetched"}
    };
    return roles;
}

void GitWorkingTreeModel::fetchLineStats(int row)
{
    if (row < 0 || row >= mRows.size())
        return;

    if (mRows.at(row).lineStatsFetched)
        return;

    if (!mRepository)
        return;

    const QString repoPath = mRepository->directory().absolutePath();
    const QString filePath = mRows.at(row).entry.filePath;

    auto future = GitConcurrent::run([repoPath, filePath]() -> LineStatsResult {
        return runLineStats(repoPath, filePath);
    });

    if (mLineStatsFutures.size() <= row)
        mLineStatsFutures.resize(row + 1);
    mLineStatsFutures[row] = future;

    AsyncFuture::observe(future).context(this, [this, row, filePath, future]() {
        if (future.isCanceled())
            return;

        if (row >= mRows.size())
            return;

        // Verify the row still holds the same file after potential refresh
        RowData& rowData = mRows[row];
        if (rowData.entry.filePath != filePath)
            return;

        const auto result = future.result();
        rowData.addedLines = result.addedLines;
        rowData.deletedLines = result.deletedLines;
        rowData.lineStatsFetched = true;

        const QModelIndex idx = index(row, 0);
        emit dataChanged(idx, idx, {AddedLinesRole, DeletedLinesRole, LineStatsFetchedRole});
    });
}

void GitWorkingTreeModel::refresh()
{
    if (!mRepository)
        return;

    const QDir dir = mRepository->directory();
    if (!dir.exists())
        return;

    cancelLineStatsFutures();

    const QString repoPath = dir.absolutePath();

    if (!mLoading)
    {
        mLoading = true;
        emit loadingChanged();
    }

    mRestarter.restart([repoPath]() -> QFuture<WorkingTreeResult> {
        return GitConcurrent::run([repoPath]() -> WorkingTreeResult {
            return runStatusPass(repoPath);
        });
    });
}

void GitWorkingTreeModel::cancelLineStatsFutures()
{
    for (auto& future : mLineStatsFutures)
    {
        if (future.isRunning())
            future.cancel();
    }
    mLineStatsFutures.clear();
}
