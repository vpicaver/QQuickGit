//Our includes
#include "GitCommitInfo.h"
#include "CommitDiffContext.h"
#include "GitConcurrent.h"
#include "GitOidUtils.h"
#include "GitRepository.h"

//Qt includes
#include <QDir>
#include <QFileInfo>
#include <QImageReader>
#include <QBuffer>

//libgit2
#include "git2.h"

using namespace QQuickGit;

namespace {

QString deltaStatusText(git_delta_t status)
{
    switch (status)
    {
    case GIT_DELTA_ADDED:     return QStringLiteral("Added");
    case GIT_DELTA_DELETED:   return QStringLiteral("Deleted");
    case GIT_DELTA_MODIFIED:  return QStringLiteral("Modified");
    case GIT_DELTA_RENAMED:   return QStringLiteral("Renamed");
    case GIT_DELTA_COPIED:    return QStringLiteral("Copied");
    case GIT_DELTA_TYPECHANGE: return QStringLiteral("Type changed");
    default:                  return QStringLiteral("Unknown");
    }
}

bool isImageByExtension(const QString& filePath)
{
    static const auto formats = QImageReader::supportedImageFormats();
    auto suffix = QFileInfo(filePath).suffix().toLower().toUtf8();
    return formats.contains(suffix);
}

bool isImageByHeader(const QByteArray& blobContent)
{
    QBuffer buffer(const_cast<QByteArray*>(&blobContent));
    buffer.open(QIODevice::ReadOnly);
    return !QImageReader::imageFormat(&buffer).isEmpty();
}

bool checkBinaryIsImage(git_repository* repo, const git_diff_delta* delta)
{
    // First check extension
    const char* path = delta->new_file.path ? delta->new_file.path : delta->old_file.path;
    if (path && isImageByExtension(QString::fromUtf8(path)))
    {
        return true;
    }

    // For binary files without recognized extension, check blob header
    if (git_oid_is_zero(&delta->new_file.id)) {
        return false;
    }

    git_blob* blob = nullptr;
    if (git_blob_lookup(&blob, repo, &delta->new_file.id) != GIT_OK || !blob) {
        return false;
    }

    std::unique_ptr<git_blob, decltype(&git_blob_free)> blobHolder(blob, &git_blob_free);

    auto content = QByteArray::fromRawData(
        static_cast<const char*>(git_blob_rawcontent(blob)),
        static_cast<int>(git_blob_rawsize(blob)));

    return isImageByHeader(content);
}

QString fetchParentSubject(git_repository* repo, const git_oid* parentOid)
{
    git_commit* parent = nullptr;
    if (git_commit_lookup(&parent, repo, parentOid) != GIT_OK || !parent) {
        return QString();
    }

    std::unique_ptr<git_commit, decltype(&git_commit_free)>
        parentHolder(parent, &git_commit_free);

    const char* msg = git_commit_message(parent);
    if (!msg) {
        return QString();
    }

    QString fullMessage = QString::fromUtf8(msg);
    int newline = fullMessage.indexOf(QLatin1Char('\n'));
    return newline >= 0 ? fullMessage.left(newline) : fullMessage;
}

CommitLoadResult loadCommit(const QString& repoPath, const QString& commitSha, int parentIndex)
{
    CommitLoadResult result;

    if (commitSha.isEmpty()) {
        return result;
    }

    auto ctx = CommitDiffContext::open(repoPath, commitSha, parentIndex, result.errorMessage);
    if (!ctx) {
        return result;
    }

    git_commit* commit = ctx->commit.get();
    git_repository* repo = ctx->repo.get();

    const git_signature* authorSig = git_commit_author(commit);
    if (authorSig)
    {
        if (authorSig->name) {
            result.author = QString::fromUtf8(authorSig->name);
        }
        if (authorSig->email) {
            result.authorEmail = QString::fromUtf8(authorSig->email);
        }
    }

    git_time_t time = git_commit_time(commit);
    int offset = git_commit_time_offset(commit);
    result.timestamp = QDateTime::fromSecsSinceEpoch(time, QTimeZone::fromSecondsAheadOfUtc(offset * 60));

    const char* msg = git_commit_message(commit);
    if (msg)
    {
        QString fullMessage = QString::fromUtf8(msg);
        int newline = fullMessage.indexOf(QLatin1Char('\n'));
        if (newline >= 0)
        {
            result.subject = fullMessage.left(newline);
            int bodyStart = newline + 1;
            while (bodyStart < fullMessage.size() && fullMessage[bodyStart] == QLatin1Char('\n')) {
                bodyStart++;
            }
            if (bodyStart < fullMessage.size()) {
                result.body = fullMessage.mid(bodyStart).trimmed();
            }
        }
        else
        {
            result.subject = fullMessage;
        }
    }

    unsigned int parentCount = git_commit_parentcount(commit);
    unsigned int displayParents = qMin(parentCount, 8u);
    for (unsigned int i = 0; i < displayParents; i++)
    {
        const git_oid* parentOid = git_commit_parent_id(commit, i);
        result.parentShas.append(oidToString(parentOid));
        result.parentSubjects.append(fetchParentSubject(repo, parentOid));
    }

    git_diff* diff = nullptr;
    git_diff_options diffOptions = GIT_DIFF_OPTIONS_INIT;
    if (git_diff_tree_to_tree(&diff, repo, ctx->parentTree.get(),
                              ctx->commitTree.get(), &diffOptions) != GIT_OK || !diff)
    {
        result.errorMessage = QStringLiteral("Failed to generate diff");
        return result;
    }
    std::unique_ptr<git_diff, decltype(&git_diff_free)> diffHolder(diff, &git_diff_free);

    git_diff_find_options findOptions = GIT_DIFF_FIND_OPTIONS_INIT;
    findOptions.flags = GIT_DIFF_FIND_RENAMES;
    git_diff_find_similar(diff, &findOptions);

    const size_t deltaCount = git_diff_num_deltas(diff);
    result.files.reserve(static_cast<int>(deltaCount));

    for (size_t i = 0; i < deltaCount; i++)
    {
        const git_diff_delta* delta = git_diff_get_delta(diff, i);
        if (!delta) {
            continue;
        }

        CommitLoadResult::FileEntry entry;
        entry.filePath = delta->new_file.path
                             ? QString::fromUtf8(delta->new_file.path)
                             : QString();
        entry.oldFilePath = delta->old_file.path
                                ? QString::fromUtf8(delta->old_file.path)
                                : QString();
        entry.status = static_cast<int>(delta->status);
        entry.statusText = deltaStatusText(delta->status);
        entry.isBinary = (delta->flags & GIT_DIFF_FLAG_BINARY) != 0;

        if (entry.isBinary) {
            entry.isImage = checkBinaryIsImage(repo, delta);
        } else {
            entry.isImage = isImageByExtension(entry.filePath);
        }

        result.files.append(std::move(entry));
    }

    return result;
}

} // anonymous namespace

GitCommitInfo::GitCommitInfo(QObject* parent)
    : QObject(parent)
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

GitCommitInfo::~GitCommitInfo()
{
    mRestarter.future().cancel();
    AsyncFuture::waitForFinished(mRestarter.future());
}

void GitCommitInfo::setRepository(GitRepository* repository)
{
    if (mRepository == repository) {
        return;
    }

    mRepository = repository;
    emit repositoryChanged();
    load();
}

void GitCommitInfo::setCommitSha(const QString& sha)
{
    if (mCommitSha == sha) {
        return;
    }

    mCommitSha = sha;
    emit commitShaChanged();
    load();
}

void GitCommitInfo::setParentIndex(int index)
{
    if (mParentIndex == index) {
        return;
    }

    mParentIndex = index;
    emit parentIndexChanged();
    load();
}

void GitCommitInfo::load()
{
    if (!mRepository || mCommitSha.isEmpty())
    {
        clearMetadata();
        return;
    }

    QDir dir = mRepository->directory();
    if (!dir.exists())
    {
        clearMetadata();
        return;
    }

    QString repoPath = dir.absolutePath();
    QString sha = mCommitSha;
    int parentIdx = mParentIndex;

    mLoading = true;
    emit loadingChanged();

    mRestarter.restart([repoPath, sha, parentIdx]() {
        return GitConcurrent::run([repoPath, sha, parentIdx]() {
            return loadCommit(repoPath, sha, parentIdx);
        });
    });
}

void GitCommitInfo::applyResult(const CommitLoadResult& result)
{
    mAuthor = result.author;
    mAuthorEmail = result.authorEmail;
    mTimestamp = result.timestamp;
    mSubject = result.subject;
    mBody = result.body;
    mParentShas = result.parentShas;
    mParentSubjects = result.parentSubjects;

    if (mErrorMessage != result.errorMessage)
    {
        mErrorMessage = result.errorMessage;
        emit errorMessageChanged();
    }

    mLoading = false;
    emit loadingChanged();
    emit metadataChanged();
    emit fileListReady(result.files);
}

void GitCommitInfo::clearMetadata()
{
    bool wasLoading = mLoading;
    bool hadError = !mErrorMessage.isEmpty();

    mAuthor.clear();
    mAuthorEmail.clear();
    mTimestamp = QDateTime();
    mSubject.clear();
    mBody.clear();
    mParentShas.clear();
    mParentSubjects.clear();
    mErrorMessage.clear();
    mLoading = false;

    emit metadataChanged();
    emit fileListReady({});

    if (wasLoading) {
        emit loadingChanged();
    }
    if (hadError) {
        emit errorMessageChanged();
    }
}
