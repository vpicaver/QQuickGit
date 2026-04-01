//Our includes
#include "GitFilePatch.h"
#include "CommitDiffContext.h"
#include "GitConcurrent.h"
#include "GitOidUtils.h"
#include "LfsStore.h"

//Async includes
#include "asyncfuture.h"

//Qt includes
#include <QDir>

//libgit2
#include "git2.h"

using namespace QQuickGit;

namespace {

char mapOrigin(char origin)
{
    switch (origin)
    {
    case GIT_DIFF_LINE_CONTEXT:      return ' ';
    case GIT_DIFF_LINE_ADDITION:     return '+';
    case GIT_DIFF_LINE_DELETION:     return '-';
    case GIT_DIFF_LINE_HUNK_HDR:     return 'H';
    case GIT_DIFF_LINE_CONTEXT_EOFNL: return ' ';
    case GIT_DIFF_LINE_ADD_EOFNL:    return '+';
    case GIT_DIFF_LINE_DEL_EOFNL:    return '-';
    default:                         return ' ';
    }
}

bool shouldFilterLine(char origin)
{
    return origin == GIT_DIFF_LINE_FILE_HDR
        || origin == GIT_DIFF_LINE_BINARY;
}

void setPathspec(git_diff_options& opts, const char** pathspec)
{
    opts.pathspec.strings = const_cast<char**>(pathspec);
    opts.pathspec.count = 1;
}

bool isBlobLfsPointer(git_repository* repo, const git_oid* oid)
{
    // LFS pointers are ~130 bytes; skip large blobs
    QByteArray content = blobContent(repo, oid, 200);
    if (content.isEmpty()) {
        return false;
    }
    LfsPointer pointer;
    return LfsPointer::parse(content, &pointer);
}

FilePatchResult generatePatchLines(git_diff* diff, const QString& filePath, int maxDiffLines)
{
    FilePatchResult result;

    size_t deltaCount = git_diff_num_deltas(diff);
    if (deltaCount == 0) {
        result.errorMessage = QStringLiteral("File not found in diff: %1").arg(filePath);
        return result;
    }

    git_patch* patch = nullptr;
    if (git_patch_from_diff(&patch, diff, 0) != GIT_OK || !patch) {
        result.errorMessage = QStringLiteral("Failed to create patch");
        return result;
    }
    std::unique_ptr<git_patch, decltype(&git_patch_free)> patchHolder(patch, &git_patch_free);

    const git_diff_delta* delta = git_patch_get_delta(patch);
    if (delta && (delta->flags & GIT_DIFF_FLAG_BINARY)) {
        result.isBinary = true;
        return result;
    }

    // Check if either side is an LFS pointer stored in the ODB
    if (delta) {
        git_repository* repo = git_patch_owner(patch);
        if (isBlobLfsPointer(repo, &delta->new_file.id)
            || isBlobLfsPointer(repo, &delta->old_file.id)) {
            result.isLfsPointer = true;
            return result;
        }
    }

    size_t totalContext = 0, totalAdded = 0, totalDeleted = 0;
    if (git_patch_line_stats(&totalContext, &totalAdded, &totalDeleted, patch) == GIT_OK) {
        if (static_cast<int>(totalAdded + totalDeleted) > maxDiffLines) {
            result.tooLarge = true;
            return result;
        }
    }

    size_t hunkCount = git_patch_num_hunks(patch);
    result.lines.reserve(static_cast<int>(totalContext + totalAdded + totalDeleted + hunkCount));
    for (size_t h = 0; h < hunkCount; h++) {
        const git_diff_hunk* hunk = nullptr;
        size_t lineCount = 0;
        if (git_patch_get_hunk(&hunk, &lineCount, patch, h) != GIT_OK) {
            continue;
        }

        if (hunk) {
            FilePatchResult::DiffLine hunkLine;
            hunkLine.text = QString::fromUtf8(hunk->header, static_cast<int>(hunk->header_len)).trimmed();
            hunkLine.origin = 'H';
            hunkLine.oldLineNo = -1;
            hunkLine.newLineNo = -1;
            result.lines.append(std::move(hunkLine));
        }

        for (size_t l = 0; l < lineCount; l++) {
            const git_diff_line* line = nullptr;
            if (git_patch_get_line_in_hunk(&line, patch, h, l) != GIT_OK || !line) {
                continue;
            }

            if (shouldFilterLine(line->origin)) {
                continue;
            }

            FilePatchResult::DiffLine diffLine;
            diffLine.text = QString::fromUtf8(line->content, static_cast<int>(line->content_len));
            if (diffLine.text.endsWith(QLatin1Char('\n'))) {
                diffLine.text.chop(1);
            }
            diffLine.origin = mapOrigin(line->origin);
            diffLine.oldLineNo = line->old_lineno;
            diffLine.newLineNo = line->new_lineno;
            result.lines.append(std::move(diffLine));
        }
    }

    return result;
}

FilePatchResult loadPatch(const QString& repoPath, const QString& commitSha,
                          int parentIndex, const QString& filePath, int maxDiffLines)
{
    FilePatchResult result;

    if (commitSha.isEmpty() || filePath.isEmpty()) {
        return result;
    }

    auto ctx = CommitDiffContext::open(repoPath, commitSha, parentIndex, result.errorMessage);
    if (!ctx) {
        return result;
    }

    git_diff* diff = nullptr;
    git_diff_options diffOptions = GIT_DIFF_OPTIONS_INIT;
    QByteArray pathBytes = filePath.toUtf8();
    const char* pathspec = pathBytes.constData();
    setPathspec(diffOptions, &pathspec);

    if (git_diff_tree_to_tree(&diff, ctx->repo.get(), ctx->parentTree.get(),
                              ctx->commitTree.get(), &diffOptions) != GIT_OK || !diff) {
        result.errorMessage = QStringLiteral("Failed to generate diff");
        return result;
    }
    std::unique_ptr<git_diff, decltype(&git_diff_free)> diffHolder(diff, &git_diff_free);

    return generatePatchLines(diff, filePath, maxDiffLines);
}

FilePatchResult loadWorkingTreePatch(const QString& repoPath, const QString& filePath, int maxDiffLines)
{
    FilePatchResult result;

    if (filePath.isEmpty()) {
        return result;
    }

    git_repository* rawRepo = nullptr;
    if (git_repository_open(&rawRepo, repoPath.toLocal8Bit().constData()) != GIT_OK || !rawRepo) {
        result.errorMessage = QStringLiteral("Failed to open repository");
        return result;
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repo(rawRepo, &git_repository_free);

    git_reference* headRef = nullptr;
    if (git_repository_head(&headRef, rawRepo) != GIT_OK || !headRef) {
        result.errorMessage = QStringLiteral("Failed to resolve HEAD");
        return result;
    }
    std::unique_ptr<git_reference, decltype(&git_reference_free)> headHolder(headRef, &git_reference_free);

    git_object* headObj = nullptr;
    if (git_reference_peel(&headObj, headRef, GIT_OBJECT_COMMIT) != GIT_OK || !headObj) {
        result.errorMessage = QStringLiteral("Failed to peel HEAD to commit");
        return result;
    }
    std::unique_ptr<git_object, decltype(&git_object_free)> objHolder(headObj, &git_object_free);

    git_tree* headTree = nullptr;
    if (git_commit_tree(&headTree, reinterpret_cast<git_commit*>(headObj)) != GIT_OK || !headTree) {
        result.errorMessage = QStringLiteral("Failed to get HEAD tree");
        return result;
    }
    std::unique_ptr<git_tree, decltype(&git_tree_free)> treeHolder(headTree, &git_tree_free);

    git_diff* diff = nullptr;
    git_diff_options diffOptions = GIT_DIFF_OPTIONS_INIT;
    QByteArray pathBytes = filePath.toUtf8();
    const char* pathspec = pathBytes.constData();
    setPathspec(diffOptions, &pathspec);
    diffOptions.flags |= GIT_DIFF_INCLUDE_UNTRACKED | GIT_DIFF_SHOW_UNTRACKED_CONTENT;

    if (git_diff_tree_to_workdir_with_index(&diff, rawRepo, headTree, &diffOptions) != GIT_OK || !diff) {
        result.errorMessage = QStringLiteral("Failed to generate working tree diff");
        return result;
    }
    std::unique_ptr<git_diff, decltype(&git_diff_free)> diffHolder(diff, &git_diff_free);

    return generatePatchLines(diff, filePath, maxDiffLines);
}

} // anonymous namespace

GitFilePatch::GitFilePatch(QObject* parent)
    : QAbstractListModel(parent)
    , mRestarter(this)
{
    mRestarter.onFutureChanged([this]() {
        auto future = mRestarter.future();
        AsyncFuture::observe(future).context(this, [this, future]() {
            if (future.isCanceled()) {
                return;
            }
            applyResult(future.result());
        });
    });
}

GitFilePatch::~GitFilePatch()
{
    mRestarter.future().cancel();
    AsyncFuture::waitForFinished(mRestarter.future());
}

int GitFilePatch::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return mLines.size();
}

QVariant GitFilePatch::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= mLines.size()) {
        return QVariant();
    }

    const auto& line = mLines.at(index.row());

    switch (role)
    {
    case TextRole:
        return line.text;
    case OriginRole: {
        static const QString context = QStringLiteral(" ");
        static const QString added = QStringLiteral("+");
        static const QString deleted = QStringLiteral("-");
        static const QString hunk = QStringLiteral("H");
        switch (line.origin) {
        case '+': return added;
        case '-': return deleted;
        case 'H': return hunk;
        default:  return context;
        }
    }
    case OldLineNoRole:
        return line.oldLineNo;
    case NewLineNoRole:
        return line.newLineNo;
    }

    return QVariant();
}

QHash<int, QByteArray> GitFilePatch::roleNames() const
{
    static const QHash<int, QByteArray> roles {
        {TextRole, "text"},
        {OriginRole, "origin"},
        {OldLineNoRole, "oldLineNo"},
        {NewLineNoRole, "newLineNo"}
    };
    return roles;
}

void GitFilePatch::setRepository(GitRepository* repository)
{
    if (mRepository == repository) {
        return;
    }

    mRepository = repository;
    emit repositoryChanged();
    load();
}

void GitFilePatch::setCommitSha(const QString& sha)
{
    if (mCommitSha == sha) {
        return;
    }

    mCommitSha = sha;
    emit commitShaChanged();
    load();
}

void GitFilePatch::setParentIndex(int index)
{
    if (mParentIndex == index) {
        return;
    }

    mParentIndex = index;
    emit parentIndexChanged();
    load();
}

void GitFilePatch::setFilePath(const QString& path)
{
    if (mFilePath == path) {
        return;
    }

    mFilePath = path;
    emit filePathChanged();
    load();
}

void GitFilePatch::setMaxDiffLines(int max)
{
    if (mMaxDiffLines == max) {
        return;
    }

    mMaxDiffLines = max;
    emit maxDiffLinesChanged();
    load();
}

void GitFilePatch::setWorkingTree(bool workingTree)
{
    if (mWorkingTree == workingTree) {
        return;
    }

    mWorkingTree = workingTree;
    emit workingTreeChanged();
    load();
}

void GitFilePatch::load()
{
    if (!mRepository || mFilePath.isEmpty()) {
        clear();
        return;
    }

    if (!mWorkingTree && mCommitSha.isEmpty()) {
        clear();
        return;
    }

    QString repoPath = mRepository->directory().absolutePath();
    QString path = mFilePath;
    int maxLines = mMaxDiffLines;

    if (!mLoading) {
        mLoading = true;
        emit loadingChanged();
    }

    if (mWorkingTree) {
        mRestarter.restart([repoPath, path, maxLines]() {
            return GitConcurrent::run([repoPath, path, maxLines]() {
                return loadWorkingTreePatch(repoPath, path, maxLines);
            });
        });
    } else {
        QString sha = mCommitSha;
        int parentIdx = mParentIndex;
        mRestarter.restart([repoPath, sha, parentIdx, path, maxLines]() {
            return GitConcurrent::run([repoPath, sha, parentIdx, path, maxLines]() {
                return loadPatch(repoPath, sha, parentIdx, path, maxLines);
            });
        });
    }
}

void GitFilePatch::applyResult(const FilePatchResult& result)
{
    beginResetModel();
    mLines = result.lines;
    endResetModel();

    bool tooLargeChanged = (mTooLarge != result.tooLarge);
    bool isBinaryChanged = (mIsBinary != result.isBinary);
    bool lfsChanged = (mIsLfsPointer != result.isLfsPointer);
    bool errorChanged = (mErrorMessage != result.errorMessage);

    mTooLarge = result.tooLarge;
    mIsBinary = result.isBinary;
    mIsLfsPointer = result.isLfsPointer;
    mErrorMessage = result.errorMessage;
    mLoading = false;

    emit loadingChanged();

    if (tooLargeChanged) {
        emit this->tooLargeChanged();
    }
    if (isBinaryChanged) {
        emit this->isBinaryChanged();
    }
    if (lfsChanged) {
        emit isLfsPointerChanged();
    }
    if (errorChanged) {
        emit errorMessageChanged();
    }
}

void GitFilePatch::clear()
{
    bool wasLoading = mLoading;
    bool wasTooLarge = mTooLarge;
    bool wasBinary = mIsBinary;
    bool wasLfs = mIsLfsPointer;
    bool hadError = !mErrorMessage.isEmpty();

    if (!mLines.isEmpty()) {
        beginResetModel();
        mLines.clear();
        endResetModel();
    }

    mTooLarge = false;
    mIsBinary = false;
    mIsLfsPointer = false;
    mErrorMessage.clear();
    mLoading = false;

    if (wasLoading) {
        emit loadingChanged();
    }
    if (wasTooLarge) {
        emit tooLargeChanged();
    }
    if (wasBinary) {
        emit isBinaryChanged();
    }
    if (wasLfs) {
        emit isLfsPointerChanged();
    }
    if (hadError) {
        emit errorMessageChanged();
    }
}
