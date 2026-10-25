//Std includes
#include <stdexcept>
#include <array>
#include <algorithm>

//Our includes
#include "GitRepository.h"
#include "GitCommitImageProvider.h"
#include "GitOidUtils.h"
#include "GitRefSpecUtil.h"
#include "RSAKeyGenerator.h"
#include "Account.h"
#include "LfsFilter.h"
#include "LfsPolicy.h"
#include "LfsBatchClient.h"
#include "LfsStore.h"
#include "LfsHydrator.h"
#include "Monad/Result.h"
#include "ProgressState.h"
#include "ProgressReporting.h"
#include "Monad/Monad.h"

//LibGit2 includes
#include "git2.h"
#include <git2/index.h>
#include <git2/sys/errors.h>
#include <libssh2.h>

//Qt includes
#include <QDebug>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QMutex>
#include <QMutexLocker>
#include <QPointer>
#include <QSet>
#include <QtConcurrent>
#include <QUuid>
#include <QHash>
#include <QRegularExpression>

//Async includes
#include "asyncfuture.h"

using namespace Monad;
using namespace QQuickGit;

namespace {
QString gitErrorMessageWithPrefix(const QString& prefix)
{
    const git_error* lastError = git_error_last();
    if (lastError && lastError->message) {
        return QStringLiteral("%1: %2").arg(prefix, QString::fromUtf8(lastError->message).trimmed());
    }
    return prefix;
}

void ensureStandardLfsFilterConfig(git_repository* repo)
{
    if (!repo) {
        return;
    }

    git_config* config = nullptr;
    if (git_repository_config(&config, repo) != GIT_OK || config == nullptr) {
        return;
    }

    auto configGuard = qScopeGuard([&config]() {
        if (config) {
            git_config_free(config);
        }
    });

    git_config_set_string(config, "filter.lfs.clean", "git-lfs clean -- %f");
    git_config_set_string(config, "filter.lfs.smudge", "git-lfs smudge -- %f");
    git_config_set_string(config, "filter.lfs.process", "git-lfs filter-process");
    git_config_set_bool(config, "filter.lfs.required", 1);
}

#ifdef Q_OS_WIN
// Enable long path support to avoid MAX_PATH (260 char) failures
// in git_status_list_new and other libgit2 operations.
void enableLongPaths(git_repository* repo)
{
    if (!repo) {
        return;
    }

    git_config* cfg = nullptr;
    if (git_repository_config(&cfg, repo) != GIT_OK || cfg == nullptr) {
        return;
    }

    auto guard = qScopeGuard([&cfg]() { git_config_free(cfg); });
    git_config_set_bool(cfg, "core.longpaths", 1);
}
#endif

int parseHttpStatusFromMessage(const QString& message)
{
    static const QRegularExpression expression(QStringLiteral("httpStatus=(\\d{3})"));
    const QRegularExpressionMatch match = expression.match(message);
    if (!match.hasMatch()) {
        return 0;
    }
    return match.captured(1).toInt();
}

QStringList uniqueSortedPaths(const QStringList& paths)
{
    QSet<QString> seen;
    QStringList result;
    result.reserve(paths.size());
    for (const QString& path : paths) {
        const QString normalized = QDir::fromNativeSeparators(path);
        if (normalized.isEmpty() || seen.contains(normalized)) {
            continue;
        }

        seen.insert(normalized);
        result.append(normalized);
    }

    std::sort(result.begin(), result.end());
    return result;
}

QString entryPath(const git_status_entry* entry)
{
    if (entry == nullptr) {
        return QString();
    }

    if (entry->index_to_workdir != nullptr && entry->index_to_workdir->new_file.path != nullptr) {
        return QString::fromUtf8(entry->index_to_workdir->new_file.path);
    }
    if (entry->head_to_index != nullptr && entry->head_to_index->new_file.path != nullptr) {
        return QString::fromUtf8(entry->head_to_index->new_file.path);
    }
    return QString();
}

QByteArray blobBytesForIndexPath(git_repository* repo, const QString& relativePath)
{
    if (repo == nullptr || relativePath.isEmpty()) {
        return QByteArray();
    }

    git_index* index = nullptr;
    if (git_repository_index(&index, repo) != GIT_OK || index == nullptr) {
        return QByteArray();
    }
    std::unique_ptr<git_index, decltype(&git_index_free)> indexHolder(index, &git_index_free);

    const QByteArray pathUtf8 = relativePath.toUtf8();
    const git_index_entry* indexEntry = git_index_get_bypath(index, pathUtf8.constData(), 0);
    if (indexEntry == nullptr || git_oid_is_zero(&indexEntry->id)) {
        return QByteArray();
    }

    return blobContent(repo, &indexEntry->id);
}

bool hydratedLfsFileMatchesIndexPointer(git_repository* repo,
                                        const QString& workTreeRoot,
                                        const git_status_entry* entry)
{
    if (repo == nullptr || entry == nullptr) {
        return false;
    }

    const unsigned int benignStatus = GIT_STATUS_WT_MODIFIED;
    if (entry->status != benignStatus) {
        return false;
    }

    const QString relativePath = entryPath(entry);
    if (relativePath.isEmpty()) {
        return false;
    }

    const QByteArray blobData = blobBytesForIndexPath(repo, relativePath);
    if (blobData.isEmpty()) {
        return false;
    }

    LfsPointer pointer;
    if (!LfsPointer::parse(blobData, &pointer) || !pointer.isValid()) {
        return false;
    }

    const QString absolutePath = QDir(workTreeRoot).filePath(relativePath);
    const QFileInfo fileInfo(absolutePath);
    if (!fileInfo.exists() || !fileInfo.isFile() || fileInfo.size() != pointer.size) {
        return false;
    }

    QFile workingFile(absolutePath);
    if (!workingFile.open(QIODevice::ReadOnly)) {
        return false;
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!workingFile.atEnd()) {
        const QByteArray chunk = workingFile.read(256 * 1024);
        if (chunk.isEmpty() && workingFile.error() != QFile::NoError) {
            return false;
        }
        if (!chunk.isEmpty()) {
            hash.addData(chunk);
        }
    }

    return QString::fromLatin1(hash.result().toHex()) == pointer.oid;
}

int filteredStatusEntryCount(git_repository* repo,
                             const QString& workTreeRoot,
                             git_status_list* list)
{
    if (list == nullptr) {
        return 0;
    }

    int count = 0;
    const size_t entryCount = git_status_list_entrycount(list);
    for (size_t i = 0; i < entryCount; ++i) {
        const git_status_entry* entry = git_status_byindex(list, i);
        if (hydratedLfsFileMatchesIndexPointer(repo, workTreeRoot, entry)) {
            continue;
        }
        ++count;
    }
    return count;
}

int computeModifiedFileCount(git_repository* repo, const QString& workTreeRoot)
{
    ensureStandardLfsFilterConfig(repo);

    git_status_options opt = GIT_STATUS_OPTIONS_INIT;
    opt.show  = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
    opt.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS;

    git_status_list* list = nullptr;
    if (git_status_list_new(&list, repo, &opt) != GIT_OK) {
        return 0;
    }
    auto listGuard = qScopeGuard([list]() { git_status_list_free(list); });
    return filteredStatusEntryCount(repo, workTreeRoot, list);
}

const char* statusEntryOldPath(const git_status_entry* entry)
{
    if (entry == nullptr) {
        return nullptr;
    }
    if (entry->index_to_workdir != nullptr && entry->index_to_workdir->old_file.path != nullptr) {
        return entry->index_to_workdir->old_file.path;
    }
    if (entry->head_to_index != nullptr && entry->head_to_index->old_file.path != nullptr) {
        return entry->head_to_index->old_file.path;
    }
    return nullptr;
}

const char* statusEntryNewPath(const git_status_entry* entry)
{
    if (entry == nullptr) {
        return nullptr;
    }
    if (entry->index_to_workdir != nullptr && entry->index_to_workdir->new_file.path != nullptr) {
        return entry->index_to_workdir->new_file.path;
    }
    if (entry->head_to_index != nullptr && entry->head_to_index->new_file.path != nullptr) {
        return entry->head_to_index->new_file.path;
    }
    return nullptr;
}

bool isStatusEntryDeletion(unsigned int status)
{
    return !(status & (GIT_STATUS_INDEX_RENAMED | GIT_STATUS_WT_RENAMED))
        && (status & (GIT_STATUS_INDEX_DELETED | GIT_STATUS_WT_DELETED));
}

// A worktree file the commit's LFS pointer pass converts: present, a regular file, and LFS-eligible.
bool isLfsPointerPassCandidate(const LfsStore& store, const QString& absolutePath)
{
    const QFileInfo info(absolutePath);
    return info.exists() && !info.isDir() && store.isLfsEligible(absolutePath);
}

struct CommitEntryCounts {
    int pending = 0;
    int lfsPointerPass = 0;
};

// Counts in one pass over `list` the entries stageFilteredStatusEntries() will stage and, when
// `store` is set, those of them the LFS pointer pass in commitAll() then visits, so commit
// progress can announce its total up front without hashing hydrated LFS files again.
CommitEntryCounts commitEntryCounts(git_repository* repo,
                                    const QString& workTreeRoot,
                                    git_status_list* list,
                                    const LfsStore* store)
{
    CommitEntryCounts counts;
    if (list == nullptr) {
        return counts;
    }

    const QDir workDir(workTreeRoot);
    const size_t entryCount = git_status_list_entrycount(list);
    for (size_t i = 0; i < entryCount; ++i) {
        const git_status_entry* entry = git_status_byindex(list, i);
        if (hydratedLfsFileMatchesIndexPointer(repo, workTreeRoot, entry)) {
            continue;
        }
        ++counts.pending;

        if (store == nullptr || entry == nullptr) {
            continue;
        }
        if (entry->status == GIT_STATUS_CURRENT || isStatusEntryDeletion(entry->status)) {
            continue;
        }
        const char* rawNewPath = statusEntryNewPath(entry);
        if (rawNewPath == nullptr || *rawNewPath == '\0') {
            continue;
        }
        if (isLfsPointerPassCandidate(*store, workDir.filePath(QString::fromUtf8(rawNewPath)))) {
            ++counts.lfsPointerPass;
        }
    }
    return counts;
}

int stageFilteredStatusEntries(git_repository* repo,
                               const QString& workTreeRoot,
                               git_index* index,
                               git_status_list* list,
                               QSet<QString>* stagedPaths,
                               const std::function<void()>& entryStaged = {})
{
    if (repo == nullptr || index == nullptr || list == nullptr) {
        return 0;
    }

    auto addPath = [index](const char* rawPath) {
        if (rawPath == nullptr || *rawPath == '\0') {
            return;
        }
        // Skip directory entries — git_index_add_bypath only accepts file paths
        const size_t len = std::strlen(rawPath);
        if (len > 0 && rawPath[len - 1] == '/') {
            return;
        }
        const int err = git_index_add_bypath(index, rawPath);
        if (err != GIT_OK) {
            throw std::runtime_error(gitErrorMessageWithPrefix(QStringLiteral("Failed to add path to index")).toStdString());
        }
    };

    auto removePath = [index](const char* rawPath) {
        if (rawPath == nullptr || *rawPath == '\0') {
            return;
        }

        const int err = git_index_remove_bypath(index, rawPath);
        if (err != 0 && err != GIT_ENOTFOUND) {
            throw std::runtime_error(gitErrorMessageWithPrefix(QStringLiteral("Failed to remove path from index")).toStdString());
        }
    };

    int stagedCount = 0;
    auto markStaged = [&stagedCount, &entryStaged]() {
        ++stagedCount;
        if (entryStaged) {
            entryStaged();
        }
    };

    const size_t entryCount = git_status_list_entrycount(list);
    for (size_t i = 0; i < entryCount; ++i) {
        const git_status_entry* entry = git_status_byindex(list, i);
        if (hydratedLfsFileMatchesIndexPointer(repo, workTreeRoot, entry)) {
            continue;
        }

        const unsigned int status = entry != nullptr ? entry->status : 0;
        if (status == GIT_STATUS_CURRENT) {
            continue;
        }

        if (isStatusEntryDeletion(status)) {
            removePath(statusEntryOldPath(entry));
            markStaged();
            continue;
        }

        if (status & (GIT_STATUS_INDEX_RENAMED | GIT_STATUS_WT_RENAMED)) {
            removePath(statusEntryOldPath(entry));
        }

        const char* rawNewPath = statusEntryNewPath(entry);
        addPath(rawNewPath);
        if (stagedPaths != nullptr && rawNewPath != nullptr) {
            stagedPaths->insert(QString::fromUtf8(rawNewPath));
        }
        markStaged();
    }

    return stagedCount;
}

bool onlyBenignHydratedLfsStatusEntries(git_repository* repo,
                                        const QString& workTreeRoot)
{
    if (repo == nullptr) {
        return false;
    }

    git_status_list* list = nullptr;
    git_status_options options = GIT_STATUS_OPTIONS_INIT;
    options.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
    options.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS;

    if (git_status_list_new(&list, repo, &options) != GIT_OK || list == nullptr) {
        return false;
    }
    std::unique_ptr<git_status_list, decltype(&git_status_list_free)> listHolder(list, &git_status_list_free);

    const size_t entryCount = git_status_list_entrycount(list);
    if (entryCount == 0) {
        return false;
    }

    for (size_t i = 0; i < entryCount; ++i) {
        const git_status_entry* entry = git_status_byindex(list, i);
        if (!hydratedLfsFileMatchesIndexPointer(repo, workTreeRoot, entry)) {
            return false;
        }
    }

    return true;
}

struct SshCallbackPayload {
    std::function<void(const ProgressState&)> reportProgress;
    int agentMaxAttempts = 1;
    int agentAttempts = 0;
    bool allowAgent = true;
    QString httpsToken;
};

std::function<void(const ProgressState&)> progressFromPayload(void* payload)
{
    auto typed = reinterpret_cast<SshCallbackPayload*>(payload);
    if(!typed) {
        return {};
    }
    return typed->reportProgress;
}

bool pushRejectedByRemoteAdvanceMessage(const QString& errorMessage)
{
    const QString normalizedMessage = errorMessage.toLower();
    return normalizedMessage.contains(QStringLiteral("non-fast-forward"))
           || normalizedMessage.contains(QStringLiteral("failed to push some refs"))
           || normalizedMessage.contains(QStringLiteral("updates were rejected"))
           || normalizedMessage.contains(QStringLiteral("fetch first"))
           || normalizedMessage.contains(QStringLiteral("tip of your current branch is behind"))
           || normalizedMessage.contains(QStringLiteral("cannot lock ref"))
           || normalizedMessage.contains(QStringLiteral("contains commits that are not present locally"))
           || normalizedMessage.contains(QStringLiteral("cannot push because a reference that you are trying to update on the remote"));
}

bool isHttpAuthFailure(int libgitError, const QString& errorMessage)
{
    if (libgitError == GIT_OK) {
        return false;
    }
    const git_error* err = git_error_last();
    return err
        && err->klass == GIT_ERROR_HTTP
        && (errorMessage.contains(QLatin1String("401"))
            || errorMessage.contains(QLatin1String("authentication")));
}

int classifyPushErrorCode(int libgitError, const QString& errorMessage)
{
    if (isHttpAuthFailure(libgitError, errorMessage)) {
        return static_cast<int>(GitRepository::GitErrorCode::HttpAuthFailed);
    }
    if (libgitError == GIT_ENONFASTFORWARD || pushRejectedByRemoteAdvanceMessage(errorMessage)) {
        return static_cast<int>(GitRepository::GitErrorCode::PushRejectedByRemoteAdvance);
    }
    return static_cast<int>(GitRepository::GitErrorCode::PushFailed);
}

bool isRebaseConflictError(int error)
{
    return error == GIT_ECONFLICT || error == GIT_EUNMERGED;
}

Monad::Result<GitRepository::MergeResult::State> runRebaseOntoRemoteBranch(git_repository* repo,
                                                                           const QString& remoteBranch,
                                                                           Account* account)
{
    if (repo == nullptr) {
        return Monad::Result<GitRepository::MergeResult::State>(QStringLiteral("Failed to open repository for rebase."));
    }

    auto resolveAnnotatedCommit = [repo](const QString& refSpec) -> git_annotated_commit* {
        git_reference* ref = nullptr;
        if (git_reference_dwim(&ref, repo, refSpec.toLocal8Bit().constData()) == GIT_OK && ref != nullptr) {
            git_annotated_commit* commit = nullptr;
            const int fromRefResult = git_annotated_commit_from_ref(&commit, repo, ref);
            git_reference_free(ref);
            if (fromRefResult == GIT_OK) {
                return commit;
            }
            return nullptr;
        }

        git_object* object = nullptr;
        if (git_revparse_single(&object, repo, refSpec.toLocal8Bit().constData()) != GIT_OK || object == nullptr) {
            return nullptr;
        }

        git_annotated_commit* commit = nullptr;
        const int lookupResult = git_annotated_commit_lookup(&commit, repo, git_object_id(object));
        git_object_free(object);
        if (lookupResult != GIT_OK) {
            return nullptr;
        }
        return commit;
    };

    git_annotated_commit* upstreamCommit = resolveAnnotatedCommit(remoteBranch);
    if (upstreamCommit == nullptr) {
        return Monad::Result<GitRepository::MergeResult::State>(QStringLiteral("Failed to resolve upstream for rebase."));
    }
    auto upstreamCommitGuard = qScopeGuard([&upstreamCommit]() {
        if (upstreamCommit != nullptr) {
            git_annotated_commit_free(upstreamCommit);
        }
    });

    git_rebase_options options = GIT_REBASE_OPTIONS_INIT;
    git_rebase* rebase = nullptr;
    const int initResult = git_rebase_init(&rebase,
                                           repo,
                                           nullptr,
                                           upstreamCommit,
                                           nullptr,
                                           &options);
    if (initResult != GIT_OK || rebase == nullptr) {
        return Monad::Result<GitRepository::MergeResult::State>(
            gitErrorMessageWithPrefix(QStringLiteral("Failed to initialize rebase")),
            initResult);
    }

    auto abortRebase = [rebase]() {
        if (rebase != nullptr) {
            git_rebase_abort(rebase);
        }
    };
    auto rebaseGuard = qScopeGuard([&rebase]() {
        if (rebase != nullptr) {
            git_rebase_free(rebase);
        }
    });

    auto createCommitterSignature = [repo, account](git_signature** outSignature) -> int {
        if (outSignature == nullptr) {
            return GIT_ERROR;
        }

        if (account != nullptr && account->isValid()) {
            return git_signature_now(outSignature,
                                     account->name().toLocal8Bit().constData(),
                                     account->email().toLocal8Bit().constData());
        }

        return git_signature_default(outSignature, repo);
    };

    int rebaseNextResult = GIT_OK;
    while (true) {
        git_rebase_operation* operation = nullptr;
        rebaseNextResult = git_rebase_next(&operation, rebase);
        Q_UNUSED(operation);
        if (rebaseNextResult != GIT_OK) {
            break;
        }

        git_index* index = nullptr;
        const int indexResult = git_repository_index(&index, repo);
        if (indexResult != GIT_OK || index == nullptr) {
            abortRebase();
            return Monad::Result<GitRepository::MergeResult::State>(
                gitErrorMessageWithPrefix(QStringLiteral("Failed to open index during rebase")),
                indexResult);
        }

        const bool hasConflicts = git_index_has_conflicts(index);
        git_index_free(index);
        if (hasConflicts) {
            abortRebase();
            return Monad::Result<GitRepository::MergeResult::State>(GitRepository::MergeResult::MergeConflicts);
        }

        git_signature* committerSignature = nullptr;
        const int signatureResult = createCommitterSignature(&committerSignature);
        if (signatureResult != GIT_OK || committerSignature == nullptr) {
            abortRebase();
            return Monad::Result<GitRepository::MergeResult::State>(
                gitErrorMessageWithPrefix(QStringLiteral("Failed to create rebase committer signature")),
                signatureResult);
        }

        git_oid commitOid = {};
        const int commitResult = git_rebase_commit(&commitOid,
                                                   rebase,
                                                   nullptr,
                                                   committerSignature,
                                                   nullptr,
                                                   nullptr);
        git_signature_free(committerSignature);

        if (commitResult == GIT_EAPPLIED) {
            continue;
        }

        if (commitResult != GIT_OK) {
            abortRebase();
            if (isRebaseConflictError(commitResult)) {
                return Monad::Result<GitRepository::MergeResult::State>(GitRepository::MergeResult::MergeConflicts);
            }
            return Monad::Result<GitRepository::MergeResult::State>(
                gitErrorMessageWithPrefix(QStringLiteral("Failed to apply rebase commit")),
                commitResult);
        }
    }

    if (rebaseNextResult != GIT_ITEROVER) {
        abortRebase();
        if (isRebaseConflictError(rebaseNextResult)) {
            return Monad::Result<GitRepository::MergeResult::State>(GitRepository::MergeResult::MergeConflicts);
        }
        return Monad::Result<GitRepository::MergeResult::State>(
            gitErrorMessageWithPrefix(QStringLiteral("Failed to advance rebase")),
            rebaseNextResult);
    }

    git_signature* finishSignature = nullptr;
    const int finishSignatureResult = createCommitterSignature(&finishSignature);
    if (finishSignatureResult != GIT_OK || finishSignature == nullptr) {
        abortRebase();
        return Monad::Result<GitRepository::MergeResult::State>(
            gitErrorMessageWithPrefix(QStringLiteral("Failed to create rebase finish signature")),
            finishSignatureResult);
    }

    const int finishResult = git_rebase_finish(rebase, finishSignature);
    git_signature_free(finishSignature);
    if (finishResult != GIT_OK) {
        abortRebase();
        return Monad::Result<GitRepository::MergeResult::State>(
            gitErrorMessageWithPrefix(QStringLiteral("Failed to finalize rebase")),
            finishResult);
    }

    return Monad::Result<GitRepository::MergeResult::State>(GitRepository::MergeResult::Rebased);
}

}


class GitRepositoryData {
public:
    QDir mDirectory;
    git_repository *repo = nullptr;
    int mModifiedFilesCount = 0;
    int mImageProviderId = -1;
    QPointer<Account> mAccount; //!<
    LfsPolicy mLfsPolicy;
    std::shared_ptr<LfsStore> mLfsStore;
    GitCredentials m_credentials;

    // Serializes git operations on this repository across threads so the
    // background status worker (checkStatusAsync) can never run concurrently
    // with a main-thread operation that touches the same index/working tree,
    // config, or shared LFS store. Held by a shared_ptr so an in-flight worker
    // keeps it alive even if the GitRepository is destroyed mid-run (issue #546).
    std::shared_ptr<QMutex> mRepoMutex = std::make_shared<QMutex>();

    // Acquire the per-repo serialization lock for an apply phase. Hold it only
    // for the local mutation (index/worktree/refs/config/LFS smudge), never
    // across network transfer — see plans/GIT_REPO_SERIAL_EXECUTOR_PLAN.md.
    // For worker lambdas, capture `auto repoMutex = d->mRepoMutex;` by value and
    // lock inside the apply phase so the mutex outlives the GitRepository.
    [[nodiscard]] QMutexLocker<QMutex> lockRepo() const { return QMutexLocker(mRepoMutex.get()); }

    // Tracks the in-flight background status worker. Touched only on the main
    // thread (checkStatusAsync and its continuation), so it needs no locking.
    QFuture<int> mStatusFuture;
    QFuture<bool> mStatusBoolFuture;
    bool mStatusRefreshPending = false;

    ~GitRepositoryData() {
        unregisterImageProvider();
        if(repo) {
            git_repository_free(repo);
        }
    }

    // Reopen the repo handle so the refdb picks up refs written
    // by a separate handle (e.g. fetchRefsForDirectory).
    void reopenRepository() {
        auto path = mDirectory.absolutePath().toLocal8Bit();
        git_repository_free(repo);
        repo = nullptr;
        check(git_repository_open(&repo, path));
    }

    void unregisterImageProvider() {
        if (mImageProviderId >= 0) {
            if (auto* provider = GitCommitImageProvider::instance()) {
                provider->unregisterRepository(mImageProviderId);
            }
            mImageProviderId = -1;
        }
    }

    static int fileBasedCredential(git_credential **out,
                                   const char *url,
                                   const char *username_from_url)
    {
        const char *userName = (username_from_url && *username_from_url) ? username_from_url : "git";

        RSAKeyGenerator key;
        auto host = extractHostFromUrl(url);
        bool usedSshConfig = key.loadFromSshConfigHost(host);
        if(!usedSshConfig) {
            key.loadOrGenerate();
        }

        auto publicKeyPath = key.publicKeyPath().toLocal8Bit();
        auto privateKeyPath = key.privateKeyPath().toLocal8Bit();

        const char* publicKey = publicKeyPath.isEmpty() ? nullptr : publicKeyPath.constData();
        const char* privateKey = privateKeyPath.isEmpty() ? nullptr : privateKeyPath.constData();

        return git_credential_ssh_key_new(out, userName, publicKey, privateKey, "");
    }

    static int credentailCallBack(git_credential **out,
                                  const char *url,
                                  const char *username_from_url,
                                  unsigned int allowed_types,
                                  void *payload)
    {
        const char *userName = (username_from_url && *username_from_url) ? username_from_url : "git";

        if (allowed_types & GIT_CREDENTIAL_USERPASS_PLAINTEXT) {
            auto callbackPayload = reinterpret_cast<SshCallbackPayload*>(payload);
            if (callbackPayload && !callbackPayload->httpsToken.isEmpty()) {
                return git_credential_userpass_plaintext_new(
                    out,
                    "x-access-token",
                    callbackPayload->httpsToken.toUtf8().constData());
            }
            // No token — signal HTTP 401 so isHttpAuthFailure() can detect it
            // cleanly instead of letting libgit2 retry and produce a misleading
            // SSL or network error.
            git_error_set_str(GIT_ERROR_HTTP, "401 Unauthorized: no access token");
            return GIT_EAUTH;
        }

        if(allowed_types & GIT_CREDENTIAL_SSH_KEY) {
            auto callbackPayload = reinterpret_cast<SshCallbackPayload*>(payload);
            const bool allowAgent = callbackPayload ? callbackPayload->allowAgent : true;
            const int maxAttempts = callbackPayload ? callbackPayload->agentMaxAttempts : 1;
            int* attempts = callbackPayload ? &callbackPayload->agentAttempts : nullptr;

            if(allowAgent && attempts && *attempts < maxAttempts) {
                int agentResult = git_credential_ssh_key_from_agent(out, userName);
                if(agentResult == GIT_OK) {
                    if(attempts) {
                        (*attempts)++;
                    }
                    return GIT_OK;
                }
            }
        }

        return fileBasedCredential(out, url, username_from_url);
    }

    static QString bytesToString(size_t bytes) {
        const double next = 1024;
        const double kb = next;
        const double mb = kb * next;
        const double gb = mb * next;

        auto mbind = [](QString current, auto f) {
            if(current.isEmpty()) {
                return f();
            }
            return current;
        };

        auto toString = [next, gb](size_t byteRecieved, double unit, QString unitStr) {
            return [=]() {
                if(byteRecieved / (unit * next) <= 1.0 || unit == gb) {
                    double decimal = byteRecieved / unit;
                    return QString::number(decimal, 'f', 2)
                           + QStringLiteral(" ")
                           + unitStr;
                }
                return QString();
            };
        };

        auto unit = [=](size_t byteRecieved) {
            return mbind(mbind(mbind(QString(),
                                     toString(byteRecieved, kb, "KiB")),
                               toString(byteRecieved, mb, "MiB")),
                         toString(byteRecieved, gb, "GiB"));
        };

        return unit(bytes);
    }

    static int certificateCheckCallback(git_cert* cert, int /*valid*/, const char* /*host*/, void* /*payload*/)
    {
        // Accept SSH host keys unconditionally (same tradeoff as the rest of the app).
        // For X.509 (HTTPS), return 0 so libgit2 uses its own validation result — this
        // avoids the macOS/OpenSSL CA store mismatch that produces GIT_ECERTIFICATE when
        // the system cert bundle is not on OpenSSL's default search path.
        if (cert->cert_type == GIT_CERT_HOSTKEY_LIBSSH2) {
            return GIT_OK;
        }
        return 0;
    }

    static int transferProgress(	unsigned int current,
                                unsigned int total,
                                size_t bytes,
                                void* payload)
    {

        auto reportProgress = progressFromPayload(payload);
        if(reportProgress) {
            auto progress = ProgressState(QStringLiteral("Transfering ... ") + bytesToString(bytes),
                                          current,
                                          total);
            reportProgress(progress);
        }
        return GIT_OK;
    }



    static int fetchProgress(const git_transfer_progress *stats,
                             void *payload)
    {
        if(payload) {
            auto total = [stats]() {
                return stats->total_objects * 2;
            };

            auto current = [stats]() {
                return stats->indexed_objects + stats->received_objects;
            };

            auto recieved = [stats]()->QString {
                return bytesToString(stats->received_bytes);
            };

            auto reportProgress = progressFromPayload(payload);
            if(reportProgress) {
                auto progress = ProgressState(QStringLiteral("Fetching ... ") + recieved(),
                                              current(),
                                              total());
                reportProgress(progress);
            }
        }

        //        qDebug() << "Clone fetch progress:"
        //                    << "Index deltas" << stats->indexed_deltas
        //                    << "Index Objects" << stats->indexed_objects //This as progress
        //                    << "local Objects" << stats->local_objects
        //                    << "received bytes" << stats->received_bytes
        //                    << "received objects" << stats->received_objects //This as progress
        //                    << "total deltas" << stats->total_deltas
        //                    << "total objects" << stats->total_objects;

        return GIT_OK;

    }

    static void cloneCheckoutProgress(
        const char *path,
        size_t current,
        size_t total,
        void *payload)
    {
        //        qDebug() << "Clone checkout:"
        //        << path
        //        << current
        //        << total
        //                 << payload;

        if(payload) {
            auto reportProgress = progressFromPayload(payload);
            if(reportProgress) {
                auto progress = ProgressState(QStringLiteral("Checkout ... ") + path,
                                              current,
                                              total);
                reportProgress(progress);
            }
        }
    }

    static void check(int error) {
        if(error != GIT_OK) {
            const git_error *err = git_error_last();
            throw(std::runtime_error(std::string(err->message)));
        }
    }

    void checkout(const git_oid* id, QString branchName) {
        git_object* object;
        check(git_object_lookup(&object, repo, id, GIT_OBJECT_COMMIT));

        git_checkout_options options = GIT_CHECKOUT_OPTIONS_INIT;
        options.checkout_strategy = GIT_CHECKOUT_SAFE;
        check(git_checkout_tree(repo, object, &options));
        check(git_repository_set_head(repo, branchName.toLocal8Bit()));

        git_object_free(object);
    }

    git_annotated_commit* toAnnotatedCommit(const QString& ref_ish) const {
        git_reference *ref;
        git_object *obj;
        git_annotated_commit* commit = nullptr;
        int err = 0;

        err = git_reference_dwim(&ref, repo, ref_ish.toLocal8Bit());
        if (err == GIT_OK) {
            git_annotated_commit_from_ref(&commit, repo, ref);
            git_reference_free(ref);
            return commit;
        }

        err = git_revparse_single(&obj, repo, ref_ish.toLocal8Bit());
        if (err == GIT_OK) {
            err = git_annotated_commit_lookup(&commit, repo, git_object_id(obj));
            git_object_free(obj);
        }

        return commit;
    };
};

GitRepository::GitRepository(QObject *parent) :
    QObject(parent),
    d(new GitRepositoryData)
{
    connect(this, &GitRepository::refsChanged, this, &GitRepository::checkStatusAsync);
}

GitRepository::~GitRepository()
{
    // Let any in-flight background status worker finish before we tear down the
    // LFS store and registry entry it may still be reading through the clean
    // filter. The worker holds its own repo handle and the shared mutex, so this
    // is a plain QFuture wait (not AsyncFuture) and does not spin the event loop.
    if (d->mStatusFuture.isRunning()) {
        d->mStatusFuture.waitForFinished();
    }

    if (d->mLfsStore) {
        LfsStoreRegistry::unregisterStore(d->mLfsStore->gitDirPath(), d->mLfsStore);
        d->mLfsStore.reset();
    }
    delete d;
}

void GitRepository::setDirectory(const QDir &dir)
{
    if(d->mDirectory != dir) {
        d->unregisterImageProvider();
        d->mDirectory = dir;

        if (auto* provider = GitCommitImageProvider::instance()) {
            if (!dir.path().isEmpty() && dir.path() != ".") {
                d->mImageProviderId = provider->registerRepository(dir.path());
            }
        }

        emit directoryChanged();
        emit imageProviderIdChanged();
    }
}

QDir GitRepository::directory()
{
    return d->mDirectory;
}

QString GitRepository::directoryPath() const
{
    return d->mDirectory.path();
}

void GitRepository::initRepository()
{
    if (d->mLfsStore) {
        LfsStoreRegistry::unregisterStore(d->mLfsStore->gitDirPath(), d->mLfsStore);
        d->mLfsStore.reset();
    }
    if (d->repo) {
        git_repository_free(d->repo);
        d->repo = nullptr;
    }

    auto path = d->mDirectory.absolutePath().toLocal8Bit();
    int error = git_repository_open(&(d->repo), path);
    if(error != GIT_OK) {
        git_repository_init_options opts = GIT_REPOSITORY_INIT_OPTIONS_INIT;
        opts.flags = GIT_REPOSITORY_INIT_MKPATH;
        opts.initial_head = "main";
        check(git_repository_init_ext(&(d->repo), path, &opts));

        // libgit2 init may not create objects/pack, which is needed for fetch.
        if (d->repo) {
            const char* gitPath = git_repository_path(d->repo);
            if (gitPath) {
                QDir(QString::fromUtf8(gitPath)).mkpath(QStringLiteral("objects/pack"));
            }
        }

        // Set init.defaultBranch so that git_repository_is_empty() recognises
        // refs/heads/main as the initial (unborn) branch.  Without this,
        // libgit2 compares HEAD against the global/system default ("master")
        // and incorrectly reports the repo as non-empty.
        if (d->repo) {
            git_config* cfg = nullptr;
            if (git_repository_config(&cfg, d->repo) == GIT_OK && cfg) {
                auto guard = qScopeGuard([&cfg]() { git_config_free(cfg); });
                git_config_set_string(cfg, "init.defaultBranch", "main");
            }
        }
    }

#ifdef Q_OS_WIN
    enableLongPaths(d->repo);
#endif

    if (d->repo) {
        const char* gitPath = git_repository_path(d->repo);
        if (gitPath) {
            d->mLfsStore = std::make_shared<LfsStore>(QString::fromUtf8(gitPath), d->mLfsPolicy);
            LfsStoreRegistry::registerStore(d->mLfsStore);
        }
    }

    ensureLfsAttributes();
    ensureStandardLfsFilterConfig(d->repo);

    emit remotesChanged();
    emit headBranchNameChanged();
}

void GitRepository::setLfsPolicy(const LfsPolicy& policy)
{
    d->mLfsPolicy = policy;
    if (d->mLfsStore) {
        d->mLfsStore->setPolicy(policy);
    }
    ensureLfsAttributes();
}

std::shared_ptr<LfsStore> GitRepository::lfsStore() const
{
    return d->mLfsStore;
}

void GitRepository::ensureLfsAttributes()
{
    if (!d->repo || !d->mLfsStore) {
        return;
    }

    const QString workDir = d->mDirectory.absolutePath();
    const QString attributesPath = QDir(workDir).filePath(QStringLiteral(".gitattributes"));

    QByteArray existingContents;
    if (QFile::exists(attributesPath)) {
        QFile readFile(attributesPath);
        if (readFile.open(QIODevice::ReadOnly)) {
            existingContents = readFile.readAll();
        }
    }

    const QString tag = d->mLfsPolicy.attributesSectionTag();
    const QString beginMarker = QStringLiteral("# %1:begin-lfs").arg(tag);
    const QString endMarker = QStringLiteral("# %1:end-lfs").arg(tag);

    QStringList lines = existingContents.isEmpty()
                            ? QStringList{}
                            : QString::fromUtf8(existingContents).split('\n');
    QStringList before;
    QStringList after;
    int beginIndex = -1;
    int endIndex = -1;
    for (int i = 0; i < lines.size(); ++i) {
        const QString trimmed = lines.at(i).trimmed();
        if (trimmed == beginMarker) {
            beginIndex = i;
        } else if (trimmed == endMarker) {
            endIndex = i;
            break;
        }
    }

    if (beginIndex >= 0 && endIndex >= beginIndex) {
        before = lines.mid(0, beginIndex);
        after = lines.mid(endIndex + 1);
    } else {
        before = lines;
    }

    QStringList managed;
    const QStringList extensions = d->mLfsPolicy.trackedExtensions();
    for (const QString& ext : extensions) {
        if (ext.isEmpty()) {
            continue;
        }
        if (managed.isEmpty()) {
            managed.append(beginMarker);
        }
        managed.append(QStringLiteral("*.%1 filter=lfs diff=lfs merge=lfs -text").arg(ext));
    }

    if (!managed.isEmpty()) {
        managed.append(endMarker);
    }

    QStringList combined;
    combined.reserve(before.size() + managed.size() + after.size());
    combined.append(before);
    if (!managed.isEmpty()) {
        if (!combined.isEmpty() && !combined.last().isEmpty()) {
            combined.append(QString());
        }
        combined.append(managed);
    }
    if (!after.isEmpty()) {
        if (!combined.isEmpty() && !combined.last().isEmpty()
            && !after.first().isEmpty()) {
            combined.append(QString());
        }
        combined.append(after);
    }

    const QByteArray newContents = combined.join('\n').toUtf8();
    if (newContents == existingContents) {
        return;
    }

    QFile writeFile(attributesPath);
    if (!writeFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return;
    }
    writeFile.write(newContents);
}

//Returns an error message
QString GitRepository::addRemote(const QString &name, const QUrl &url) noexcept
{
    try {
        addRemoteHelper(name, url.toString());
    } catch (const std::runtime_error& error) {
        return QString::fromLocal8Bit(error.what()).trimmed();
    }
    return QString();
}

// Accepts a raw URL string, bypassing QUrl parsing.
// Needed for SSH SCP-syntax URLs (e.g. git@host:user/repo.git) which QUrl
// cannot round-trip correctly through its strict parser.
QString GitRepository::addRemote(const QString &name, const QString &rawUrl) noexcept
{
    try {
        addRemoteHelper(name, rawUrl);
    } catch (const std::runtime_error& error) {
        return QString::fromLocal8Bit(error.what()).trimmed();
    }
    return QString();
}

QString GitRepository::removeRemote(const QString &name) noexcept
{
    try {
        check(git_remote_delete(d->repo, name.toLocal8Bit()));
        emit remotesChanged();
    } catch (const std::runtime_error& error) {
        return QString::fromLocal8Bit(error.what()).trimmed();
    }
    return QString();
}

QUrl GitRepository::remoteUrl(QString name) const
{
    const QString raw = rawRemoteUrl(name);
    return raw.isEmpty() ? QUrl() : QUrl(raw);
}

QString GitRepository::rawRemoteUrl(QString name) const
{
    name = fixUpRemote(name);

    git_remote* remote = nullptr;
    int error = git_remote_lookup(&remote, d->repo, name.toLocal8Bit());
    QString url;
    if(error == GIT_OK) {
        url = QString::fromLocal8Bit(git_remote_url(remote));
        git_remote_free(remote);
    }
    return url;
}

QVector<GitRemoteInfo> GitRepository::remotes() const
{
    QVector<GitRemoteInfo> remotes;

    if(d->repo) {
        git_strarray remoteNames = {nullptr, 0};
        const int error = git_remote_list(&remoteNames, d->repo);
        if (error != GIT_OK) {
            return remotes;
        }
        remotes.reserve(remoteNames.count);

        for(size_t i = 0; i < remoteNames.count; i++) {
            QString name = QString::fromLocal8Bit(remoteNames.strings[i]);
            GitRemoteInfo info(name, remoteUrl(name));
            remotes.append(info);
        }

        git_strarray_dispose(&remoteNames);
    }

    return remotes;
}

QFuture<GitRepository::RemoteConnectionReport> GitRepository::testRemoteConnectionDetailed(const QUrl& url,
                                                                                            bool probeLfs)
{
    return QtConcurrent::run([url, probeLfs]() -> RemoteConnectionReport {
        RemoteConnectionReport report;
        try {
            GitRepository tempRepository;
            tempRepository.setDirectory(QDir::temp().absoluteFilePath(QUuid::createUuid().toString(QUuid::WithoutBraces)));
            tempRepository.initRepository();
            const QString remoteName = QStringLiteral("test");

            int error = GIT_OK;
            {
                auto remote = makeScopedPtr(git_remote_free);
                error = git_remote_lookup(&remote, tempRepository.d->repo, remoteName.toLocal8Bit());
            }
            if (error != GIT_OK) {
                tempRepository.addRemoteHelper(remoteName, url.toString());
            } else {
                check(git_remote_set_url(tempRepository.d->repo,
                                         remoteName.toLocal8Bit(),
                                         url.toString().toLocal8Bit()));
            }

            auto remote = makeScopedPtr(git_remote_free);
            check(git_remote_lookup(&remote, tempRepository.d->repo, remoteName.toLocal8Bit()));

            git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;
            callbacks.credentials = GitRepositoryData::credentailCallBack;
            callbacks.certificate_check = GitRepositoryData::certificateCheckCallback;

            check(git_remote_connect(remote, GIT_DIRECTION_FETCH, &callbacks, nullptr, nullptr));
            report.transportOk = true;

            if (!probeLfs) {
                return report;
            }

            report.lfsProbeAttempted = true;
            const char* gitDirRaw = git_repository_path(tempRepository.d->repo);
            if (!gitDirRaw) {
                report.lfsErrorMessage = QStringLiteral("Unable to resolve git metadata path for LFS probe.");
                return report;
            }

            LfsBatchClient client(QString::fromUtf8(gitDirRaw));
            const auto batchFuture = client.batch(QStringLiteral("download"),
                                                  QVector<LfsBatchClient::ObjectSpec>(),
                                                  remoteName);

            if (!AsyncFuture::waitForFinished(batchFuture, 10000)) {
                report.lfsErrorMessage = QStringLiteral("LFS probe timed out.");
                return report;
            }

            const auto batchResult = batchFuture.result();
            if (!batchResult.hasError()) {
                report.lfsOk = true;
                return report;
            }

            report.lfsErrorMessage = batchResult.errorMessage();
            report.lfsHttpStatus = parseHttpStatusFromMessage(report.lfsErrorMessage);

            const int authCode = static_cast<int>(LfsFetchErrorCode::Auth);
            if (batchResult.errorCode() == authCode || report.lfsHttpStatus == 401 || report.lfsHttpStatus == 403) {
                report.lfsUnauthorized = true;
            }
        } catch (const std::runtime_error& error) {
            report.transportOk = false;
            report.transportErrorMessage = QString::fromLocal8Bit(error.what()).trimmed();
        }

        return report;
    });
}

QFuture<QString> GitRepository::testRemoteConnection(const QUrl &url)
{
    return QtConcurrent::run([url]()->QString  {
        const auto reportFuture = GitRepository::testRemoteConnectionDetailed(url, false);
        AsyncFuture::waitForFinished(reportFuture, 20000);
        const auto report = reportFuture.result();
        if (!report.transportOk) {
            return report.transportErrorMessage;
        }
        return QString();
    });
}

QString GitRepository::repositoryNameFromUrl(const QUrl &url)
{
    return QFileInfo(url.fileName()).baseName();
}

void GitRepository::initGitEngine()
{
    git_libgit2_init();
    LfsFilter::registerFilter();
}

void GitRepository::shutdownGitEngine()
{
    LfsFilter::unregisterFilter();
    git_libgit2_shutdown();
}

bool GitRepository::isRepository(const QDir& dir)
{
    git_repository *repo = nullptr;
    int err = git_repository_open_ext(
        &repo,
        dir.absolutePath().toLatin1().constData(),
        GIT_REPOSITORY_OPEN_NO_SEARCH,
        nullptr
        );

    if (err == 0) {
        git_repository_free(repo);
        return true;
    }

    // err < 0: could be GIT_ENOTFOUND (not a repo) or another error
    return false;
}

namespace {
GitRepository::GitFuture fetchRefsForDirectory(const QDir& repositoryDir,
                                               const QString& remote,
                                               std::function<void(const ProgressState&)> reportProgress,
                                               const GitCredentials& credentials)
{
    const QByteArray path = repositoryDir.absolutePath().toLocal8Bit();
    const QString fixedRemote = remote;
    return QtConcurrent::run([path, fixedRemote, reportProgress, credentials]() mutable {
        return mtry([path, fixedRemote, reportProgress, credentials]() mutable -> ResultBase {
            git_repository* repo = nullptr;
            GitRepositoryData::check(git_repository_open(&repo, path));
            std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

            // Ensure objects/pack exists — libgit2 writes temporary pack
            // files here during fetch and produces a wrong path if it is
            // missing (e.g. repos created by git_repository_init_ext).
            const char* gitDir = git_repository_path(repo);
            if (gitDir) {
                QDir(QString::fromUtf8(gitDir)).mkpath(QStringLiteral("objects/pack"));
            }

            git_remote* gitRemote = nullptr;
            GitRepositoryData::check(git_remote_lookup(&gitRemote, repo, fixedRemote.toLocal8Bit()));
            std::unique_ptr<git_remote, decltype(&git_remote_free)> gitRemoteHolder(gitRemote, &git_remote_free);

            git_fetch_options options = GIT_FETCH_OPTIONS_INIT;
            options.callbacks.credentials = GitRepositoryData::credentailCallBack;
            options.callbacks.certificate_check = GitRepositoryData::certificateCheckCallback;
            options.callbacks.transfer_progress = GitRepositoryData::fetchProgress;
            SshCallbackPayload callbackPayload;
            callbackPayload.reportProgress = reportProgress;
            callbackPayload.allowAgent = true;
            callbackPayload.agentMaxAttempts = 1;
            callbackPayload.agentAttempts = 0;
            callbackPayload.httpsToken = credentials.httpsToken;
            options.callbacks.payload = static_cast<void*>(&callbackPayload);

            const int fetchError = git_remote_fetch(gitRemote, nullptr, &options, nullptr);
            if (fetchError != GIT_OK) {
                const QString msg = gitErrorMessageWithPrefix(QStringLiteral("Failed to fetch"));
                const bool isAuth = isHttpAuthFailure(fetchError, msg);
                const int code = isAuth
                                 ? static_cast<int>(GitRepository::GitErrorCode::HttpAuthFailed)
                                 : fetchError;
                return ResultBase(msg, code);
            }
            return ResultBase();
        });
    });
}
}

bool GitRepository::isPushRejectedByRemoteAdvanceError(int errorCode)
{
    return errorCode == static_cast<int>(GitRepository::GitErrorCode::PushRejectedByRemoteAdvance);
}

QFuture<ResultBase> GitRepository::clone(const QUrl &url)
{
    Q_ASSERT(d->repo == nullptr);
    if(d->repo != nullptr) {
        AsyncFuture::completed<QString>(QStringLiteral("Repository isn't null, this is a bug"));
    }

    //Need to use a custom future for handling progress
    return progressFuture<ResultBase>([=](QFutureInterface<ResultBase> progressInterface) {
        auto dir = directory();

        struct Repo {
            git_repository* repo = nullptr;
        };

        const GitCredentials credentials = d->m_credentials;   // snapshot on main thread
        auto future = QtConcurrent::run([dir, url, progressInterface, credentials]() mutable ->Result<Repo> {
            return mtry([=]() mutable ->Result<Repo> {
                progressInterface.setProgressValueAndText(progressInterface.progressValue() + 1,
                                                          QStringLiteral("Cloning from ") + url.toString());

                if(!url.isValid()) {
                    throw std::runtime_error("Url is invalid on clone");
                }

                if(!dir.exists()) {
                    git_repository* repo = nullptr;

                    auto shouldRetryWithFiles = [](int errorCode, int errorClass, const QString& message) {
                        if(errorCode == GIT_EAUTH) {
                            return true;
                        }
                        if(errorClass == GIT_ERROR_SSH || errorClass == GIT_ERROR_NET) {
                            return true;
                        }
                        auto lowered = message.toLower();
                        return lowered.contains(QStringLiteral("auth"))
                               || lowered.contains(QStringLiteral("publickey"))
                               || lowered.contains(QStringLiteral("permission denied"))
                               || lowered.contains(QStringLiteral("credentials"))
                               || lowered.contains(QStringLiteral("failed getting response"));
                    };

                    auto cloneWithCredentials = [&](bool allowAgent,
                                                    QString* errorMessage,
                                                    int* errorClass,
                                                    int* errorCode) -> git_repository* {
                        git_repository* localRepo = nullptr;

                        git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
                        clone_opts.fetch_opts.callbacks.certificate_check = GitRepositoryData::certificateCheckCallback;
                        clone_opts.fetch_opts.callbacks.credentials = GitRepositoryData::credentailCallBack;
                        clone_opts.fetch_opts.callbacks.transfer_progress = GitRepositoryData::fetchProgress;
                        SshCallbackPayload callbackPayload;
                        callbackPayload.reportProgress = [progressInterface](const ProgressState& progress) mutable {
                            setFutureProgress(&progressInterface, progress);
                        };
                        callbackPayload.allowAgent = allowAgent;
                        callbackPayload.agentMaxAttempts = 1;
                        callbackPayload.agentAttempts = 0;
                        callbackPayload.httpsToken = credentials.httpsToken;

                        clone_opts.fetch_opts.callbacks.payload = static_cast<void*>(&callbackPayload);

                        clone_opts.checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;
                        clone_opts.checkout_opts.progress_cb = GitRepositoryData::cloneCheckoutProgress;
                        clone_opts.checkout_opts.progress_payload = static_cast<void*>(&callbackPayload);

#ifdef Q_OS_WIN
                        // Enable long path support before the checkout phase
                        // writes files to disk.
                        clone_opts.repository_cb = [](git_repository** out, const char* path, int bare, void* /*payload*/) -> int {
                            int err = git_repository_init(out, path, bare);
                            if (err == GIT_OK && *out) {
                                enableLongPaths(*out);
                            }
                            return err;
                        };
#endif

                        auto urlByteArray = url.toString().toLocal8Bit();
                        auto repoDirectory = dir.absolutePath().toLocal8Bit();

                        int err = git_clone(&localRepo, urlByteArray, repoDirectory, &clone_opts);
                        if(err == GIT_OK) {
                            return localRepo;
                        }

                        const git_error *errInfo = git_error_last();
                        if(errorMessage) {
                            if(errInfo && errInfo->message) {
                                *errorMessage = QString::fromUtf8(errInfo->message).trimmed();
                            } else {
                                *errorMessage = QStringLiteral("Unknown git error");
                            }
                        }
                        if(errorClass) {
                            *errorClass = errInfo ? errInfo->klass : 0;
                        }
                        if(errorCode) {
                            *errorCode = err;
                        }

                        if(localRepo) {
                            git_repository_free(localRepo);
                        }
                        return nullptr;
                    };

                    QString errorMessage;
                    int errorClass = 0;
                    int errorCode = 0;

                    repo = cloneWithCredentials(true, &errorMessage, &errorClass, &errorCode);
                    if(!repo && shouldRetryWithFiles(errorCode, errorClass, errorMessage)) {
                        if(dir.exists()) {
                            QDir cleanupDir(dir.absolutePath());
                            cleanupDir.removeRecursively();
                        }
                        repo = cloneWithCredentials(false, &errorMessage, &errorClass, &errorCode);
                    }

                    if(!repo) {
                        const int code = (errorClass == GIT_ERROR_HTTP
                                          && (errorMessage.contains(QLatin1String("401"))
                                              || errorMessage.contains(QLatin1String("authentication"))))
                                         ? static_cast<int>(GitRepository::GitErrorCode::HttpAuthFailed)
                                         : errorCode;
                        return Result<Repo>(errorMessage, code);
                    }

                    return Result<Repo>(Repo({repo}));
                } else {
                    if(dir.isEmpty()) {
                        throw std::runtime_error(QString("Can't clone %1 because the directory is empty")
                                                     .arg(url.toString())
                                                     .toStdString());
                    } else {
                        throw std::runtime_error(QString("Can't clone %1 because directory %2 already exists")
                                                     .arg(url.toString(),
                                                          dir.absolutePath())
                                                     .toStdString());
                    }
                }

            });
        });

        return AsyncFuture::observe(future)
            .context(this, [future, this, progressInterface]() mutable -> GitFuture {
                const auto cloneResult = future.result();
                if (cloneResult.hasError()) {
                    return AsyncFuture::completed(ResultBase(cloneResult.errorMessage(), cloneResult.errorCode()));
                }

                // Apply tail of the clone: swap in the repo handle, re-register
                // the shared LFS store, and write config. Serialize against the
                // status worker before LFS hydration streams in (issue #546).
                {
                    auto locker = d->lockRepo();
                    d->repo = cloneResult.value().repo;
                    if (d->mLfsStore) {
                        LfsStoreRegistry::unregisterStore(d->mLfsStore->gitDirPath(), d->mLfsStore);
                        d->mLfsStore.reset();
                    }
                    const char* gitPath = git_repository_path(d->repo);
                    if (gitPath) {
                        d->mLfsStore = std::make_shared<LfsStore>(QString::fromUtf8(gitPath), d->mLfsPolicy);
                        LfsStoreRegistry::registerStore(d->mLfsStore);
                    }
                    ensureLfsAttributes();
                    ensureStandardLfsFilterConfig(d->repo);
                }
                return LfsHydrator::runLfsHydrationForDirectory(d->mDirectory, this, LfsHydrator::makeLfsTransferProgress(progressInterface));
            }).future();
    });
}

GitRepository::GitFuture GitRepository::hydrateLfsFiles()
{
    return GitRepository::hydrateLfsFiles(d->mDirectory, this);
}

GitRepository::GitFuture GitRepository::hydrateLfsFiles(const QDir& repositoryDir, QObject* context)
{
    return LfsHydrator::runLfsHydrationForDirectory(repositoryDir, context);
}

QFuture<bool> GitRepository::hasMissingLfsFiles(const QDir& repositoryDir, QObject* context)
{
    auto planFuture = LfsHydrator::prepareLfsHydrationPlan(repositoryDir);
    return AsyncFuture::observe(planFuture)
        .context(context, [planFuture]() -> bool {
            const auto& result = planFuture.result();
            if (result.hasError()) {
                return false;
            }
            return !result.value().missingPointers.isEmpty();
        }).future();
}

/**
* @brief GitRepository::modifiedFileCount
* @return
*/
int GitRepository::modifiedFileCount() const {
    return d->mModifiedFilesCount;
}

int GitRepository::imageProviderId() const {
    return d->mImageProviderId;
}

bool GitRepository::hasCommits() const
{
    if (!d->repo) {
        return false;
    }

    int emptyResult = git_repository_is_empty(d->repo);
    if (emptyResult == 0) {
        return true;
    }
    if (emptyResult == 1) {
        return false;
    }

    // Treat unexpected errors as "no commits" so callers stay conservative.
    return false;
}

void GitRepository::checkStatus()
{
    if (d->repo) {
        int count = 0;
        {
            // Hold the lock only for the git read, not across the signal that
            // setModifiedFileCount emits — a slot may re-enter checkStatus()
            // and deadlock on this non-recursive mutex (e.g. cwProjectSyncHealth).
            auto locker = d->lockRepo();
            count = computeModifiedFileCount(d->repo, d->mDirectory.absolutePath());
        }
        setModifiedFileCount(count);
    }
}

QFuture<bool> GitRepository::checkStatusAsync()
{
    if (!d->repo) {
        return QtConcurrent::run([]() { return false; });
    }

    // Coalesce: keep at most one background status worker in flight. A burst of
    // refsChanged emissions (e.g. a rapid commitAll loop) marks a refresh
    // pending and re-uses the running future instead of spawning overlapping
    // workers that would race the main thread's git operations (issue #546).
    if (d->mStatusFuture.isRunning()) {
        d->mStatusRefreshPending = true;
        return d->mStatusBoolFuture;
    }
    d->mStatusRefreshPending = false;

    const QString dirPath = d->mDirectory.absolutePath();
    auto repoMutex = d->mRepoMutex;
    auto countFuture = QtConcurrent::run([dirPath, repoMutex]() -> int {
        // Serialize against main-thread git operations on the same repository.
        QMutexLocker locker(repoMutex.get());
        git_repository* repo = nullptr;
        if (git_repository_open(&repo, dirPath.toLocal8Bit().constData()) != GIT_OK) {
            return 0;
        }
        auto repoGuard = qScopeGuard([&repo]() { git_repository_free(repo); });
        return computeModifiedFileCount(repo, dirPath);
    });
    d->mStatusFuture = countFuture;

    auto boolFuture = AsyncFuture::observe(countFuture).context(this, [this, countFuture]() {
        int count = countFuture.result();
        setModifiedFileCount(count);
        if (d->mStatusRefreshPending) {
            checkStatusAsync();
        }
        return count > 0;
    }).future();
    d->mStatusBoolFuture = boolFuture;

    return boolFuture;
}

void GitRepository::resetHard(const QString& refSpec)
{
    auto locker = d->lockRepo();

    git_object* object;
    check(git_revparse_single(&object, d->repo, refSpec.toLocal8Bit()));

    git_checkout_options checkoutOptions = GIT_CHECKOUT_OPTIONS_INIT;
    check(git_reset(d->repo, object, GIT_RESET_HARD, &checkoutOptions));

    git_object_free(object);

    locker.unlock();
    emit refsChanged();
}

void GitRepository::cleanUntracked()
{
    if (!d->repo) {
        return;
    }

    auto locker = d->lockRepo();

    git_status_list* list = nullptr;
    git_status_options opt = GIT_STATUS_OPTIONS_INIT;
    opt.show  = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
    // Do NOT recurse into untracked directories: report each new untracked
    // directory as a single entry so we can removeRecursively() it in one
    // call.  Recursing would yield individual files, leaving the parent
    // directory behind as an empty (but still present) directory.
    opt.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED;

    if (git_status_list_new(&list, d->repo, &opt) != GIT_OK) {
        return;
    }
    auto listGuard = qScopeGuard([&list]() { git_status_list_free(list); });

    const QDir repoDir(d->mDirectory.absolutePath());
    const size_t entryCount = git_status_list_entrycount(list);
    for (size_t i = 0; i < entryCount; ++i) {
        const git_status_entry* entry = git_status_byindex(list, i);
        if (!entry || !(entry->status & GIT_STATUS_WT_NEW)) {
            continue;
        }
        const char* rawPath = (entry->index_to_workdir != nullptr)
                              ? entry->index_to_workdir->new_file.path
                              : nullptr;
        if (!rawPath) {
            continue;
        }
        const QString fullPath = repoDir.absoluteFilePath(
            QString::fromUtf8(rawPath));
        const QFileInfo fi(fullPath);
        if (fi.isDir()) {
            QDir(fullPath).removeRecursively();
        } else {
            QFile::remove(fullPath);
        }
    }
}

void GitRepository::commitAll(const QString &subject,
                              const QString &description,
                              const CommitProgress& progress)
{
    Q_ASSERT(account());

    // Serialize against the background status worker so the LFS clean filter,
    // index, and config are never touched from two threads at once (issue #546).
    auto locker = d->lockRepo();

    ensureStandardLfsFilterConfig(d->repo);

    git_index *index;
    git_tree* parentTree = nullptr;

    git_status_list* statusList = nullptr;
    git_status_options statusOptions = GIT_STATUS_OPTIONS_INIT;
    statusOptions.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
    statusOptions.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS;
    check(git_status_list_new(&statusList, d->repo, &statusOptions));
    const CommitEntryCounts entryCounts =
        commitEntryCounts(d->repo, d->mDirectory.absolutePath(), statusList, d->mLfsStore.get());
    if (entryCounts.pending <= 0) {
        git_status_list_free(statusList);
        return;
    }

    const int progressTotal = entryCounts.pending + entryCounts.lfsPointerPass;
    int progressDone = 0;
    auto reportProgress = [&progress, &progressDone, progressTotal]() {
        if (progress) {
            progressDone = std::min(progressDone + 1, progressTotal);
            progress(progressDone, progressTotal);
        }
    };

    check(git_repository_index(&index, d->repo));
    QSet<QString> stagedPaths;
    const int stagedEntryCount =
        stageFilteredStatusEntries(d->repo,
                                   d->mDirectory.absolutePath(),
                                   index,
                                   statusList,
                                   &stagedPaths,
                                   reportProgress);
    git_status_list_free(statusList);
    statusList = nullptr;
    if (stagedEntryCount <= 0) {
        git_index_free(index);
        return;
    }

    git_oid commit_oid,tree_oid;
    git_tree *tree;
    git_object *parent = nullptr;
    git_reference *ref = nullptr;
    git_signature *signature;

    int error = git_revparse_ext(&parent, &ref, d->repo, "HEAD");
    if (error == GIT_ENOTFOUND) {
        // printf("HEAD not found. Creating first commit\n");
    } else if (error != 0) {
        check(error);
    } else if (parent != nullptr) {
        check(git_commit_tree(&parentTree, reinterpret_cast<git_commit*>(parent)));
    }

    check(git_index_write_tree(&tree_oid, index));
    check(git_index_write(index));

    // Ensure LFS-eligible files are staged as pointer blobs even if the
    // libgit2 filter driver is bypassed by index-wide staging paths.
    if (d->mLfsStore) {
        const QDir workDir = d->mDirectory;
        for (const QString& relativePath : std::as_const(stagedPaths)) {
            const QString absolutePath = workDir.filePath(relativePath);
            if (!isLfsPointerPassCandidate(*d->mLfsStore, absolutePath)) {
                continue;
            }
            reportProgress();

            const QByteArray pathUtf8 = relativePath.toUtf8();
            const git_index_entry* existing = git_index_get_bypath(index, pathUtf8.constData(), 0);
            if (!existing || !existing->path) {
                continue;
            }

            QFile candidateFile(absolutePath);
            if (candidateFile.open(QIODevice::ReadOnly)) {
                const QByteArray prefix = candidateFile.read(1024);
                LfsPointer existingPointer;
                if (LfsPointer::parse(prefix, &existingPointer) && existingPointer.isValid()) {
                    continue;
                }
            }

            const auto pointerResult = d->mLfsStore->storeFile(absolutePath);
            if (pointerResult.hasError()) {
                continue;
            }

            const QByteArray pointerText = pointerResult.value().toPointerText();
            if (pointerText.isEmpty()) {
                continue;
            }

            git_oid pointerBlobOid;
            if (git_blob_create_frombuffer(&pointerBlobOid,
                                           d->repo,
                                           pointerText.constData(),
                                           static_cast<size_t>(pointerText.size())) != GIT_OK) {
                continue;
            }

            git_index_entry updated = *existing;
            updated.id = pointerBlobOid;
            git_index_add(index, &updated);
        }

        check(git_index_write(index));
        check(git_index_write_tree(&tree_oid, index));
    }

    check(git_tree_lookup(&tree, d->repo, &tree_oid));

    const bool treeMatchesParent = parentTree != nullptr && git_oid_equal(git_tree_id(parentTree), &tree_oid);
    if (treeMatchesParent) {
        git_index_free(index);
        git_tree_free(parentTree);
        git_tree_free(tree);
        return;
    }

    check(git_signature_now(&signature,
                            account()->name().toLocal8Bit(),
                            account()->email().toLocal8Bit()));

    auto comment = subject + "\n\n" + description;

    check(git_commit_create_v(
        &commit_oid,
        d->repo,
        "HEAD",
        signature,
        signature,
        NULL,
        comment.toLocal8Bit(),
        tree,
        parent ? 1 : 0, parent));

    git_index_free(index);
    git_signature_free(signature);
    git_tree_free(parentTree);
    git_tree_free(tree);

    locker.unlock();
    emit refsChanged();
}

GitRepository::GitFuture GitRepository::push(QString refSpec, QString remote)
{
    // Config write touches .git/config — serialize against the status worker,
    // which writes the same config from its own handle (issue #546). The lock is
    // released before the network transfer below; we never hold it across I/O.
    {
        auto locker = d->lockRepo();
        ensureStandardLfsFilterConfig(d->repo);
    }
    auto future = progressFuture<ResultBase>(
        [=](QFutureInterface<ResultBase> progressInterface)
        {
            auto fixRefSpec = refSpec;
            if(refSpec.isEmpty()) {
                auto headBranch = headBranchName();
                fixRefSpec = QString("refs/heads/%1").arg(headBranch);
            }

            const LfsPushRefSpec parsedRefSpec = parsePushRefSpec(fixRefSpec);
            if (hasRefGlobPattern(parsedRefSpec.sourceRef) || hasRefGlobPattern(parsedRefSpec.destinationRef)) {
                return AsyncFuture::completed(ResultBase(
                    QStringLiteral("Wildcard push refspecs are not supported"),
                    static_cast<int>(GitRepository::GitErrorCode::PushWildcardRefSpecUnsupported)));
            }

            auto path = d->mDirectory.absolutePath().toLocal8Bit();
            auto fixRemote = fixUpRemote(remote);
            const GitCredentials credentials = d->m_credentials;   // snapshot on main thread
            auto prePushUploadFuture = LfsHydrator::runLfsPrePushUpload(path, fixRefSpec, fixRemote, this, credentials.httpsToken,
                                                           LfsHydrator::makeLfsTransferProgress(progressInterface));

            return AsyncFuture::observe(prePushUploadFuture)
                .context(this, [=]() -> GitFuture {
                    const auto prePushResult = prePushUploadFuture.result();
                    const bool unsupportedLfsRemote = prePushResult.hasError()
                        && prePushResult.errorMessage() == QStringLiteral("Unsupported LFS remote URL");
                    if (prePushResult.hasError() && !unsupportedLfsRemote) {
                        return AsyncFuture::completed(prePushResult);
                    }

                    return QtConcurrent::run([=]() {
                        return mtry([=]() mutable ->ResultBase {
                            git_push_options options;
                            git_remote* gitRemote = makeScopedPtr(&git_remote_free);

                            auto repo = makeScopedPtr(git_repository_free);
                            check(git_repository_open(&repo, path));

                            auto localRefSpec = fixRefSpec.toLocal8Bit();
                            std::array<const char*, 1> refspec = {localRefSpec};
                            const git_strarray refspecs = {const_cast<char**>(refspec.data()), 1};

                            check(git_remote_lookup(&gitRemote, repo, fixRemote.toLocal8Bit()));

                            check(git_push_options_init(&options, GIT_PUSH_OPTIONS_VERSION ));
                            options.callbacks.credentials = GitRepositoryData::credentailCallBack;
                            options.callbacks.certificate_check = GitRepositoryData::certificateCheckCallback;
                            options.callbacks.push_transfer_progress = GitRepositoryData::transferProgress;
                            SshCallbackPayload callbackPayload;
                            callbackPayload.reportProgress = [progressInterface](const ProgressState& progress) mutable {
                                setFutureProgress(&progressInterface, progress);
                            };
                            callbackPayload.allowAgent = true;
                            callbackPayload.agentMaxAttempts = 1;
                            callbackPayload.agentAttempts = 0;
                            callbackPayload.httpsToken = credentials.httpsToken;
                            options.callbacks.payload = static_cast<void*>(&callbackPayload);

                            const int pushError = git_remote_push(gitRemote, &refspecs, &options);
                            if (pushError != GIT_OK) {
                                const QString errorMessage = gitErrorMessageWithPrefix(QStringLiteral("Failed to push"));
                                return ResultBase(errorMessage,
                                                  classifyPushErrorCode(pushError, errorMessage));
                            }

                            git_remote_free(gitRemote);

                            if (unsupportedLfsRemote) {
                                return ResultBase(QStringLiteral("LFS upload skipped: remote URL does not support LFS"),
                                                  ResultBase::Warning);
                            }
                            return ResultBase();
                        });
                    });
                }).future();
        });
    emitRefsChangedOnSuccess(future);
    return future;
}

GitRepository::MergeFuture GitRepository::pull(const QString& remote)
{
    {
        auto locker = d->lockRepo();
        ensureStandardLfsFilterConfig(d->repo);
    }
    QString fixedRemote = fixUpRemote(remote);
    auto future = progressFuture<Result<MergeResult>>(
        [=](QFutureInterface<Result<MergeResult>> progressInterface)
        {
            auto fetchFuture = fetchRefsForDirectory(
                d->mDirectory,
                fixedRemote,
                [progressInterface](const ProgressState& progress) mutable {
                    setFutureProgress(&progressInterface, progress);
                },
                d->m_credentials);
            AsyncFuture::observe(fetchFuture).onProgress([=]() mutable {
                if(!fetchFuture.progressText().isEmpty()) {
                    setFutureProgress(&progressInterface, fetchFuture.progressText());
                }
            });
            return AsyncFuture::observe(fetchFuture)
                .context(this,
                         [=]()
                         {
                             const auto fetchResult = fetchFuture.result();
                             if (fetchResult.hasError()) {
                                 return AsyncFuture::completed(Result<MergeResult>(fetchResult.errorMessage(),
                                                                                    fetchResult.errorCode()));
                             }

                             d->reopenRepository();

                             auto mergeResult = mtry(
                                 [=]() mutable ->Result<MergeResult>
                                 {
                                     auto currentBranch = headBranchName();

                                     if(!currentBranch.isEmpty()) {
                                         auto remoteBranch = fixedRemote + QStringLiteral("/") + currentBranch;

                                         //remote branch exists
                                         if(remoteBranchExists(remoteBranch)) {
                                             setFutureProgress(&progressInterface, ProgressState(QStringLiteral("Merging"), 0, 1));
                                             return merge({remoteBranch});
                                         }
                                     }
                                     return Result<MergeResult>(); //QStringLiteral("Current branch name is empty"));
                                 });

                             return LfsHydrator::runMergeHydrationForDirectory(mergeResult, d->mDirectory, this,
                                                                  LfsHydrator::makeLfsTransferProgress(progressInterface));
                         }).future();
        });
    emitRefsChangedOnSuccess(future);
    return future;
}

GitRepository::MergeFuture GitRepository::pullRebaseOrMerge(const QString& remote)
{
    {
        auto locker = d->lockRepo();
        ensureStandardLfsFilterConfig(d->repo);
    }
    QString fixedRemote = fixUpRemote(remote);
    auto future = progressFuture<Result<MergeResult>>(
        [=](QFutureInterface<Result<MergeResult>> progressInterface)
        {
            auto fetchFuture = fetchRefsForDirectory(
                d->mDirectory,
                fixedRemote,
                [progressInterface](const ProgressState& progress) mutable {
                    setFutureProgress(&progressInterface, progress);
                },
                d->m_credentials);
            AsyncFuture::observe(fetchFuture).onProgress([=]() mutable {
                if(!fetchFuture.progressText().isEmpty()) {
                    setFutureProgress(&progressInterface, fetchFuture.progressText());
                }
            });

            return AsyncFuture::observe(fetchFuture)
                .context(this, [=]() mutable {
                    const auto fetchResult = fetchFuture.result();
                    if (fetchResult.hasError()) {
                        return AsyncFuture::completed(Result<MergeResult>(fetchResult.errorMessage(),
                                                                          fetchResult.errorCode()));
                    }

                    d->reopenRepository();

                    auto pullResult = mtry([=]() mutable -> Result<MergeResult> {
                        const auto currentBranch = headBranchName();
                        if (currentBranch.isEmpty()) {
                            return Result<MergeResult>();
                        }

                        const auto remoteBranch = fixedRemote + QStringLiteral("/") + currentBranch;
                        if (!remoteBranchExists(remoteBranch)) {
                            return Result<MergeResult>();
                        }

                        const auto aheadBehindResult = aheadBehindCommitCounts(d->mDirectory.absolutePath(),
                                                                               QStringLiteral("HEAD"),
                                                                               remoteBranch);
                        if (aheadBehindResult.hasError()) {
                            return Result<MergeResult>(aheadBehindResult.errorMessage(),
                                                       aheadBehindResult.errorCode());
                        }

                        const auto counts = aheadBehindResult.value();
                        if (counts.ahead == 0 || counts.behind == 0) {
                            setFutureProgress(&progressInterface, ProgressState(QStringLiteral("Merging"), 0, 1));
                            return merge({remoteBranch});
                        }

                        setFutureProgress(&progressInterface, ProgressState(QStringLiteral("Rebasing"), 0, 1));
                        // Apply phase: the rebase rewrites the worktree/index and
                        // smudges LFS files. Serialize against the status worker;
                        // released before the merge() fallback, which self-locks.
                        const auto rebaseResult = [&]() {
                            auto locker = d->lockRepo();
                            return runRebaseOntoRemoteBranch(d->repo, remoteBranch, account());
                        }();
                        if (rebaseResult.hasError()) {
                            return Result<MergeResult>(rebaseResult.errorMessage(),
                                                       rebaseResult.errorCode());
                        }

                        if (rebaseResult.value() == MergeResult::MergeConflicts) {
                            setFutureProgress(&progressInterface, ProgressState(QStringLiteral("Merging"), 0, 1));
                            return merge({remoteBranch});
                        }

                        return Result<MergeResult>(MergeResult(rebaseResult.value()));
                    });

                    return LfsHydrator::runMergeHydrationForDirectory(pullResult, d->mDirectory, this,
                                                         LfsHydrator::makeLfsTransferProgress(progressInterface));
                }).future();
        });
    emitRefsChangedOnSuccess(future);
    return future;
}

GitRepository::GitFuture GitRepository::pullPush(const QString &refSpec, const QString &remote)
{
    return progressFuture<ResultBase>([=](QFutureInterface<ResultBase> progressInterface) {
        auto pullFuture = pull(remote);
        return AsyncFuture::observe(pullFuture)
            .context(this, [=]() ->GitFuture
                     {
                         AsyncFuture::observe(pullFuture).onProgress([=]() mutable {
                             setFutureProgress(&progressInterface, pullFuture.progressText());
                         });

                         return mbind(pullFuture, [=](const Result<MergeResult>& mergeResult) -> GitFuture {
                             if(mergeResult.value().state() == GitRepository::MergeResult::MergeConflicts) {
                                 return AsyncFuture::completed<ResultBase>(ResultBase(QStringLiteral("Merge Conflicts need to be resolved")));
                             }

                             auto pushFuture = push(refSpec, remote);

                             AsyncFuture::observe(pushFuture).onProgress([=]() mutable {
                                 setFutureProgress(&progressInterface, pushFuture.progressText());
                             });

                             return pushFuture;
                         });
                     }).future();
    });
}

GitRepository::GitFuture GitRepository::fetch(const QString& remote)
{
    {
        auto locker = d->lockRepo();
        ensureStandardLfsFilterConfig(d->repo);
    }
    return progressFuture<ResultBase>(
        [=](QFutureInterface<ResultBase> progressInterface)
        {
            auto fetchFuture = fetchRefsForDirectory(
                d->mDirectory,
                fixUpRemote(remote),
                [progressInterface](const ProgressState& progress) mutable {
                    setFutureProgress(&progressInterface, progress);
                },
                d->m_credentials);

            return AsyncFuture::observe(fetchFuture)
                .context(this, [=]() mutable -> GitFuture {
                    const auto fetchResult = fetchFuture.result();
                    if (fetchResult.hasError()) {
                        return AsyncFuture::completed(fetchResult);
                    }

                    d->reopenRepository();

                    return LfsHydrator::runLfsHydrationForDirectory(d->mDirectory, this, LfsHydrator::makeLfsTransferProgress(progressInterface));
                }).future();
        });
}

GitRepository::MergeResult GitRepository::merge(const QStringList &refSpecs)
{
    // Apply phase: serialize the index/worktree/config/LFS mutation against the
    // status worker and other repo ops (issue #546). RAII covers every return.
    auto locker = d->lockRepo();

    ensureStandardLfsFilterConfig(d->repo);

    auto state = git_repository_state(d->repo);
    if (state != GIT_REPOSITORY_STATE_NONE) {
        throw std::runtime_error("Can't merged not in a clean state");
    }

    auto resolveHeads = [this](const QStringList& refSpecs) {

        QVector<git_annotated_commit*> commits;
        commits.reserve(refSpecs.size());

        for(const auto& ref_ish : refSpecs) {
            auto commit = d->toAnnotatedCommit(ref_ish);
            if(commit) {
                commits.append(d->toAnnotatedCommit(ref_ish));
            } else {
                throw std::runtime_error(QStringLiteral("Can't find ref:\"%1\"")
                                             .arg(ref_ish)
                                             .toStdString());
            }
            git_annotated_commit_free(commit);
        }

        return commits;
    };

    auto perform_fastforward = [this](git_repository *repo, const git_oid *target_oid, int is_unborn)->int
    {
        git_checkout_options ff_checkout_options = GIT_CHECKOUT_OPTIONS_INIT;
        git_reference *target_ref;
        git_reference *new_target_ref;
        git_object *target = NULL;
        int err = 0;

        if (is_unborn) {
            const char *symbolic_ref;
            git_reference *head_ref;

            /* HEAD reference is unborn, lookup manually so we don't try to resolve it */
            err = git_reference_lookup(&head_ref, repo, "HEAD");
            if (err != 0) {
                fprintf(stderr, "failed to lookup HEAD ref\n");
                return -1;
            }

            /* Grab the reference HEAD should be pointing to */
            symbolic_ref = git_reference_symbolic_target(head_ref);

            /* Create our master reference on the target OID */
            err = git_reference_create(&target_ref, repo, symbolic_ref, target_oid, 0, NULL);
            if (err != 0) {
                fprintf(stderr, "failed to create master reference\n");
                return -1;
            }

            git_reference_free(head_ref);
        } else {
            /* HEAD exists, just lookup and resolve */
            err = git_repository_head(&target_ref, repo);
            if (err != 0) {
                fprintf(stderr, "failed to get HEAD reference\n");
                return -1;
            }
        }

        /* Lookup the target object */
        err = git_object_lookup(&target, repo, target_oid, GIT_OBJECT_COMMIT);
        if (err != 0) {
            fprintf(stderr, "failed to lookup OID %s\n", git_oid_tostr_s(target_oid));
            return -1;
        }

        /* Checkout the result so the workdir is in the expected state */
        ff_checkout_options.checkout_strategy = GIT_CHECKOUT_SAFE;
        if (onlyBenignHydratedLfsStatusEntries(repo, d->mDirectory.absolutePath())) {
            ff_checkout_options.checkout_strategy = GIT_CHECKOUT_FORCE;
        }
        err = git_checkout_tree(repo, target, &ff_checkout_options);
        if (err != 0) {
            return -1;
        }

        /* Move the target reference to the target OID */
        err = git_reference_set_target(&new_target_ref, target_ref, target_oid, NULL);
        if (err != 0) {
            fprintf(stderr, "failed to move HEAD reference\n");
            return -1;
        }

        git_reference_free(target_ref);
        git_reference_free(new_target_ref);
        git_object_free(target);

        return 0;
    };

    auto create_merge_commit = [this, refSpecs](git_index *index,
                                                QVector<git_annotated_commit*> commits)
    {
        git_oid tree_oid, commit_oid;
        git_tree *tree;
        git_signature *sign;
        git_reference *merge_ref = nullptr;
        git_annotated_commit *merge_commit;
        git_reference *head_ref;
        QVector<git_commit*> parents(commits.size() + 1);
        git_repository *repo = d->repo;
        //        git_commit **parents = calloc(commits.size() + 1, sizeof(git_commit *));
        const char *msg_target = nullptr;

        //Grab our need references
        check(git_repository_head(&head_ref, repo));
        merge_commit = d->toAnnotatedCommit(refSpecs.at(0));
        if(!merge_commit) {
            throw std::runtime_error("Can't resolve " + refSpecs.at(0).toStdString());
        }

        //Get the signature
        check(git_signature_now(&sign,
                                account()->name().toLocal8Bit(),
                                account()->email().toLocal8Bit()));

        //DWIM the merge_ref
        check(git_reference_dwim(&merge_ref, repo, refSpecs.at(0).toLocal8Bit()));

        /* Prepare a standard merge commit message */
        if (merge_ref != nullptr) {
            check(git_branch_name(&msg_target, merge_ref));
        } else {
            msg_target = git_oid_tostr_s(git_annotated_commit_id(merge_commit));
        }

        auto commitMessage = QStringLiteral("Merged %1 %2")
                                 .arg(merge_ref ? "branch" : "commit")
                                 .arg(msg_target);

        /* Setup our parent commits */
        check(git_reference_peel((git_object **)&parents[0], head_ref, GIT_OBJECT_COMMIT));
        for (auto i = 0; i < commits.size(); i++) {
            git_commit_lookup(&parents[i + 1], repo, git_annotated_commit_id(commits[i]));
        }

        /* Prepare our commit tree */
        check(git_index_write(index));
        check(git_index_write_tree(&tree_oid, index));
        check(git_tree_lookup(&tree, repo, &tree_oid));

        /* Commit time ! */
        check(git_commit_create(&commit_oid,
                                repo, git_reference_name(head_ref),
                                sign, sign,
                                NULL, commitMessage.toLocal8Bit(),
                                tree,
                                parents.size(), (const git_commit **)parents.data()));

        /* We're done merging, cleanup the repository state */
        git_repository_state_cleanup(repo);
    };


    QVector<git_annotated_commit*> commitsToMerge = resolveHeads(refSpecs);

    git_merge_analysis_t analysis;
    git_merge_preference_t preference;
    check(git_merge_analysis(&analysis, &preference,
                             d->repo,
                             const_cast<const git_annotated_commit**>(commitsToMerge.data()),
                             commitsToMerge.size()));

    if (analysis & GIT_MERGE_ANALYSIS_UP_TO_DATE) {
        return MergeResult(MergeResult::AlreadyUpToDate);
    } else if (analysis & GIT_MERGE_ANALYSIS_UNBORN ||
               (analysis & GIT_MERGE_ANALYSIS_FASTFORWARD &&
                !(preference & GIT_MERGE_PREFERENCE_NO_FASTFORWARD))) {
        const git_oid *target_oid;

        // if (analysis & GIT_MERGE_ANALYSIS_UNBORN) {
        //     printf("Unborn\n");
        // } else {
        //     printf("Fast-forward\n");
        // }

        // Since this is a fast-forward, there can be only one merge head
        target_oid = git_annotated_commit_id(commitsToMerge.at(0));
        Q_ASSERT(commitsToMerge.size() == 1);

        check(perform_fastforward(d->repo, target_oid, (analysis & GIT_MERGE_ANALYSIS_UNBORN)));
        return MergeResult(MergeResult::FastForward);
    } if (analysis & GIT_MERGE_ANALYSIS_NORMAL) {
        git_merge_options merge_opts = GIT_MERGE_OPTIONS_INIT;
        git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;

        merge_opts.flags = 0;
        merge_opts.file_flags = GIT_MERGE_FILE_DEFAULT;

        checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE|GIT_CHECKOUT_ALLOW_CONFLICTS;

        if (preference & GIT_MERGE_PREFERENCE_FASTFORWARD_ONLY) {
            throw std::runtime_error("Fast-forward is preferred, but only a merge is possible");
            return MergeResult();
        }

        check(git_merge(d->repo,
                        const_cast<const git_annotated_commit**>(commitsToMerge.data()),
                        commitsToMerge.size(),
                        &merge_opts, &checkout_opts));

        git_index *index;
        check(git_repository_index(&index, d->repo));

        auto removeIndexPathIfPresent = [](git_index* index, const QByteArray& path) {
            const auto conflictErr = git_index_conflict_remove(index, path.constData());
            if (conflictErr != 0 && conflictErr != GIT_ENOTFOUND) {
                check(conflictErr);
            }

            const auto err = git_index_remove_bypath(index, path.constData());
            if (err != 0 && err != GIT_ENOTFOUND) {
                check(err);
            }
        };

        auto writeBuffer = [](const char* gitPath, const QDir& repoDir, const QByteArray& buffer) {
            auto path = repoDir.absoluteFilePath(QString::fromUtf8(gitPath));
            QFileInfo fileInfo(path);
            if (!fileInfo.dir().exists()) {
                fileInfo.dir().mkpath(QStringLiteral("."));
            }
            QFile file(path);
            if (!file.open(QFile::WriteOnly | QFile::Truncate)) {
                throw std::runtime_error(("Failed to open " + path).toStdString());
            }
            file.write(buffer);
        };

        auto stageBufferAtPath = [this](git_index* index,
                                        const QByteArray& path,
                                        const QByteArray& buffer,
                                        unsigned int defaultMode = GIT_FILEMODE_BLOB) {
            git_oid blobOid;
            check(git_blob_create_frombuffer(&blobOid,
                                             d->repo,
                                             buffer.constData(),
                                             static_cast<size_t>(buffer.size())));

            const git_index_entry* existing = git_index_get_bypath(index, path.constData(), 0);
            git_index_entry updated = {};
            if (existing != nullptr) {
                updated = *existing;
            }

            updated.id = blobOid;
            updated.mode = existing != nullptr ? existing->mode : defaultMode;
            updated.path = path.constData();
            updated.file_size = static_cast<git_off_t>(buffer.size());

            check(git_index_add(index, &updated));
        };

        auto applyOneSidedRenameResolutions = [this, index, &commitsToMerge, writeBuffer, stageBufferAtPath, removeIndexPathIfPresent]() {
            if (commitsToMerge.size() != 1) {
                return;
            }

            git_reference* headRef = nullptr;
            check(git_repository_head(&headRef, d->repo));

            git_commit* ourCommit = nullptr;
            check(git_reference_peel(reinterpret_cast<git_object**>(&ourCommit), headRef, GIT_OBJECT_COMMIT));
            git_reference_free(headRef);

            git_commit* theirCommit = nullptr;
            check(git_commit_lookup(&theirCommit, d->repo, git_annotated_commit_id(commitsToMerge.at(0))));

            git_oid mergeBaseOid;
            check(git_merge_base(&mergeBaseOid,
                                 d->repo,
                                 git_commit_id(ourCommit),
                                 git_commit_id(theirCommit)));

            git_commit* baseCommit = nullptr;
            check(git_commit_lookup(&baseCommit, d->repo, &mergeBaseOid));

            git_tree* baseTree = nullptr;
            git_tree* ourTree = nullptr;
            git_tree* theirTree = nullptr;
            check(git_commit_tree(&baseTree, baseCommit));
            check(git_commit_tree(&ourTree, ourCommit));
            check(git_commit_tree(&theirTree, theirCommit));

            auto readTreePath = [this](git_tree* tree, const QByteArray& path) {
                git_tree_entry* entry = nullptr;
                const auto pathErr = git_tree_entry_bypath(&entry, tree, path.constData());
                if (pathErr == GIT_ENOTFOUND) {
                    return QByteArray();
                }
                check(pathErr);

                git_blob* blob = nullptr;
                check(git_blob_lookup(&blob, d->repo, git_tree_entry_id(entry)));
                QByteArray out(static_cast<const char*>(git_blob_rawcontent(blob)),
                               static_cast<qsizetype>(git_blob_rawsize(blob)));
                git_blob_free(blob);
                git_tree_entry_free(entry);
                return out;
            };

            auto renamedPaths = [this](git_tree* fromTree, git_tree* toTree) {
                QHash<QByteArray, QByteArray> out;
                git_diff* diff = nullptr;
                check(git_diff_tree_to_tree(&diff, d->repo, fromTree, toTree, nullptr));

                git_diff_find_options findOptions = GIT_DIFF_FIND_OPTIONS_INIT;
                findOptions.flags = GIT_DIFF_FIND_RENAMES;
                check(git_diff_find_similar(diff, &findOptions));

                const size_t deltaCount = git_diff_num_deltas(diff);
                for (size_t i = 0; i < deltaCount; ++i) {
                    const git_diff_delta* delta = git_diff_get_delta(diff, i);
                    if (delta->status == GIT_DELTA_RENAMED) {
                        out.insert(QByteArray(delta->old_file.path), QByteArray(delta->new_file.path));
                    }
                }
                git_diff_free(diff);
                return out;
            };

            auto mergeBuffers = [](const QByteArray& baseBuffer,
                                   const QByteArray& renamedBuffer,
                                   const QByteArray& otherBuffer,
                                   const QByteArray& basePath,
                                   const QByteArray& renamedPath,
                                   const QByteArray& otherPath) {
                const bool renamedMatchesBase = renamedBuffer == baseBuffer;
                const bool otherMatchesBase = otherBuffer == baseBuffer;

                if (renamedMatchesBase && !otherMatchesBase) {
                    return otherBuffer;
                }
                if (!renamedMatchesBase && otherMatchesBase) {
                    return renamedBuffer;
                }
                if (renamedMatchesBase && otherMatchesBase) {
                    return renamedBuffer;
                }

                git_merge_file_input ancestorInput = GIT_MERGE_FILE_INPUT_INIT;
                git_merge_file_input oursInput = GIT_MERGE_FILE_INPUT_INIT;
                git_merge_file_input theirsInput = GIT_MERGE_FILE_INPUT_INIT;
                git_merge_file_options options = GIT_MERGE_FILE_OPTIONS_INIT;
                git_merge_file_result result = {};

                ancestorInput.ptr = baseBuffer.constData();
                ancestorInput.size = static_cast<size_t>(baseBuffer.size());
                ancestorInput.path = basePath.constData();
                ancestorInput.mode = GIT_FILEMODE_BLOB;

                oursInput.ptr = renamedBuffer.constData();
                oursInput.size = static_cast<size_t>(renamedBuffer.size());
                oursInput.path = renamedPath.constData();
                oursInput.mode = GIT_FILEMODE_BLOB;

                theirsInput.ptr = otherBuffer.constData();
                theirsInput.size = static_cast<size_t>(otherBuffer.size());
                theirsInput.path = otherPath.constData();
                theirsInput.mode = GIT_FILEMODE_BLOB;

                check(git_merge_file(&result,
                                     &ancestorInput,
                                     &oursInput,
                                     &theirsInput,
                                     &options));

                if (!result.automergeable) {
                    git_merge_file_result_free(&result);
                    result = {};
                    git_merge_file_options retryOptions = GIT_MERGE_FILE_OPTIONS_INIT;
                    retryOptions.favor = GIT_MERGE_FILE_FAVOR_OURS;
                    check(git_merge_file(&result,
                                         &ancestorInput,
                                         &oursInput,
                                         &theirsInput,
                                         &retryOptions));
                }

                QByteArray mergedBuffer = result.ptr != nullptr && result.len > 0
                    ? QByteArray(result.ptr, static_cast<int>(result.len))
                    : QByteArray();
                git_merge_file_result_free(&result);
                return mergedBuffer;
            };

            auto composeSegmentWisePath = [](const QByteArray& oldPath,
                                             const QByteArray& ourNewPath,
                                             const QByteArray& theirNewPath) -> QByteArray {
                if (oldPath.isEmpty() || ourNewPath.isEmpty() || theirNewPath.isEmpty()) {
                    return QByteArray();
                }

                if (ourNewPath == theirNewPath) {
                    return ourNewPath;
                }

                const QList<QByteArray> oldSegments = oldPath.split('/');
                const QList<QByteArray> ourSegments = ourNewPath.split('/');
                const QList<QByteArray> theirSegments = theirNewPath.split('/');
                if (oldSegments.size() != ourSegments.size()
                    || oldSegments.size() != theirSegments.size()) {
                    return QByteArray();
                }

                QList<QByteArray> mergedSegments = oldSegments;
                for (int i = 0; i < oldSegments.size(); ++i) {
                    const bool oursChanged = ourSegments.at(i) != oldSegments.at(i);
                    if (!oursChanged) {
                        continue;
                    }
                    mergedSegments[i] = ourSegments.at(i);
                }

                for (int i = 0; i < oldSegments.size(); ++i) {
                    const bool theirsChanged = theirSegments.at(i) != oldSegments.at(i);
                    if (!theirsChanged) {
                        continue;
                    }

                    if (mergedSegments.at(i) != oldSegments.at(i)
                        && mergedSegments.at(i) != theirSegments.at(i)) {
                        return QByteArray();
                    }
                    mergedSegments[i] = theirSegments.at(i);
                }

                return mergedSegments.join('/');
            };

            auto repoDir = QDir(git_repository_path(d->repo));
            repoDir.cdUp();

            const auto ourRenames = renamedPaths(baseTree, ourTree);
            const auto theirRenames = renamedPaths(baseTree, theirTree);

            for (auto it = ourRenames.cbegin(); it != ourRenames.cend(); ++it) {
                const QByteArray oldPath = it.key();
                const QByteArray ourNewPath = it.value();
                const QByteArray theirNewPath = theirRenames.value(oldPath);

                if (theirNewPath.isEmpty() || ourNewPath == theirNewPath) {
                    continue;
                }

                const QByteArray composedPath = composeSegmentWisePath(oldPath, ourNewPath, theirNewPath);
                if (composedPath.isEmpty()) {
                    continue;
                }

                const QByteArray baseBuffer = readTreePath(baseTree, oldPath);
                const QByteArray ourBuffer = readTreePath(ourTree, ourNewPath);
                const QByteArray theirBuffer = readTreePath(theirTree, theirNewPath);
                if (baseBuffer.isEmpty() && ourBuffer.isEmpty() && theirBuffer.isEmpty()) {
                    continue;
                }

                const QByteArray mergedBuffer = mergeBuffers(baseBuffer,
                                                             ourBuffer,
                                                             theirBuffer,
                                                             oldPath,
                                                             ourNewPath,
                                                             theirNewPath);

                QFile::remove(repoDir.absoluteFilePath(QString::fromUtf8(oldPath)));
                if (ourNewPath != composedPath) {
                    QFile::remove(repoDir.absoluteFilePath(QString::fromUtf8(ourNewPath)));
                }
                if (theirNewPath != composedPath) {
                    QFile::remove(repoDir.absoluteFilePath(QString::fromUtf8(theirNewPath)));
                }

                writeBuffer(composedPath.constData(), repoDir, mergedBuffer);
                removeIndexPathIfPresent(index, oldPath);
                removeIndexPathIfPresent(index, ourNewPath);
                removeIndexPathIfPresent(index, theirNewPath);
                stageBufferAtPath(index, composedPath, mergedBuffer);
            }

            auto reconcileRenameMap = [&](const QHash<QByteArray, QByteArray>& renameMap,
                                          const QHash<QByteArray, QByteArray>& otherRenameMap,
                                          git_tree* renamedTree,
                                          git_tree* otherTree) {
                for (auto it = renameMap.cbegin(); it != renameMap.cend(); ++it) {
                    const QByteArray oldPath = it.key();
                    const QByteArray newPath = it.value();

                    if (otherRenameMap.contains(oldPath)) {
                        continue;
                    }

                    const QByteArray baseBuffer = readTreePath(baseTree, oldPath);
                    const QByteArray renamedBuffer = readTreePath(renamedTree, newPath);
                    const QByteArray otherBuffer = readTreePath(otherTree, oldPath);

                    if (renamedBuffer.isEmpty() && otherBuffer.isEmpty()) {
                        continue;
                    }

                    const QByteArray mergedBuffer = mergeBuffers(baseBuffer,
                                                                 renamedBuffer,
                                                                 otherBuffer,
                                                                 oldPath,
                                                                 newPath,
                                                                 oldPath);

                    QFile::remove(repoDir.absoluteFilePath(QString::fromUtf8(oldPath)));
                    writeBuffer(newPath.constData(), repoDir, mergedBuffer);
                    removeIndexPathIfPresent(index, oldPath);
                    stageBufferAtPath(index, newPath, mergedBuffer);
                }
            };

            reconcileRenameMap(ourRenames, theirRenames, ourTree, theirTree);
            reconcileRenameMap(theirRenames, ourRenames, theirTree, ourTree);

            git_tree_free(theirTree);
            git_tree_free(ourTree);
            git_tree_free(baseTree);
            git_commit_free(baseCommit);
            git_commit_free(theirCommit);
            git_commit_free(ourCommit);
        };

        applyOneSidedRenameResolutions();

        auto createMergeCommit = [&index, &commitsToMerge, create_merge_commit]() {
            create_merge_commit(index, commitsToMerge);
            return MergeResult(MergeResult::MergeCommitCreated);
        };

        if (git_index_has_conflicts(index)) {
            /* Handle conflicts */


            //ResolveWithOurs is based on this post in github
            //https://github.com/libgit2/objective-git/issues/665
            //https://github.com/libgit2/libgit2/issues/3940#issuecomment-250447791
            //https://stackoverflow.com/questions/51977074/objectivegit-resolving-file-conflicts-with-gtindex-enumerateconflictedfilesw
            auto resolveWithOurs = [writeBuffer, stageBufferAtPath](git_repository* repo, git_index* index, const QDir& repoDir) {

                /**
                 * This removes the diff text. For example git_index_entry would be:
                 *
                 *   "<<<<<<< HEAD
                 *   :( Hello world!
                 *   =======
                 *    :D Hello world!
                 *   >>>>>>> testBranch
                 *    "
                 *
                 *    Returns QByteArray:
                 *    :( Hello world!
                 *
                 */
                auto useOurs = [](const char* gitPath, const QDir& repoDir)->QByteArray {
                    auto path = repoDir.absoluteFilePath(gitPath);

                    if(!QFile::exists(path)) {
                        qDebug() << "entry->path:" << path << "doesn't exist";
                    }

                    QFile file(path);
                    if (!file.open(QFile::ReadOnly)) {
                        qDebug() << "Failed to open" << path << "for reading";
                        return QByteArray();
                    }

                    enum State {
                        Same,
                        Ours,
                        Theirs
                    };

                    QByteArray out;

                    State state = Same;
                    while(!file.atEnd()) {
                        bool keepLine = true;
                        auto line = QString::fromUtf8(file.readLine());
                        switch(state) {
                        case Same:
                            if(line == QStringLiteral("<<<<<<< HEAD\n")) {
                                state = Ours;
                                keepLine = false;
                            }
                            break;
                        case Ours:
                            if(line == QStringLiteral("=======\n")) {
                                state = Theirs;
                                keepLine = false;
                            }
                            break;
                        case Theirs:
                            //Always throw away their's
                            keepLine = false;
                            static const auto regex = QRegularExpression(QStringLiteral("^>>>>>>>\\s.*\n$"));
                            if(line.contains(regex)) {
                                state = Same;
                            }
                            break;
                        };

                        if(keepLine) {
                            out.append(line.toUtf8());
                        }
                    }

                    return out;
                };

                auto entryMatches = [](const git_index_entry* lhs, const git_index_entry* rhs) {
                    if (lhs == nullptr || rhs == nullptr) {
                        return lhs == rhs;
                    }
                    return lhs->mode == rhs->mode && git_oid_cmp(&lhs->id, &rhs->id) == 0;
                };

                auto entryContent = [repo](const git_index_entry* entry) {
                    if (entry == nullptr) {
                        return QByteArray();
                    }

                    git_blob* blob = nullptr;
                    check(git_blob_lookup(&blob, repo, &entry->id));
                    QByteArray out(static_cast<const char*>(git_blob_rawcontent(blob)),
                                   static_cast<qsizetype>(git_blob_rawsize(blob)));
                    git_blob_free(blob);
                    return out;
                };

                // Collect all conflict entries before processing. Calling
                // git_index_conflict_remove while iterating with
                // git_index_conflict_iterator invalidates the iterator and
                // silently skips remaining conflicts (see issue #370).
                struct ConflictEntry {
                    QByteArray ancestorPath;
                    QByteArray ourPath;
                    QByteArray theirPath;
                    git_oid ancestorOid;
                    git_oid ourOid;
                    git_oid theirOid;
                    uint32_t ancestorMode = 0;
                    uint32_t ourMode = 0;
                    uint32_t theirMode = 0;
                };

                QList<ConflictEntry> collectedConflicts;
                {
                    git_index_conflict_iterator* iterator;
                    check(git_index_conflict_iterator_new(&iterator, index));

                    const git_index_entry *ancestor;
                    const git_index_entry *our;
                    const git_index_entry *their;

                    auto copyEntryData = [](const git_index_entry* src, QByteArray& path,
                                            git_oid& oid, uint32_t& mode) {
                        if (src && src->path) {
                            path = QByteArray(src->path);
                            git_oid_cpy(&oid, &src->id);
                            mode = src->mode;
                        }
                    };

                    while (git_index_conflict_next(&ancestor, &our, &their, iterator) == 0) {
                        ConflictEntry entry;
                        copyEntryData(ancestor, entry.ancestorPath, entry.ancestorOid, entry.ancestorMode);
                        copyEntryData(our, entry.ourPath, entry.ourOid, entry.ourMode);
                        copyEntryData(their, entry.theirPath, entry.theirOid, entry.theirMode);
                        collectedConflicts.append(std::move(entry));
                    }
                    git_index_conflict_iterator_free(iterator);
                }

                auto makeIndexEntry = [](const QByteArray& path, const git_oid& oid, uint32_t mode) -> git_index_entry {
                    git_index_entry e = {};
                    e.path = path.constData();
                    git_oid_cpy(&e.id, &oid);
                    e.mode = mode;
                    return e;
                };

                for (const ConflictEntry& conflict : collectedConflicts) {
                    const QByteArray conflictPath = !conflict.ourPath.isEmpty()
                        ? conflict.ourPath
                        : (!conflict.ancestorPath.isEmpty() ? conflict.ancestorPath : conflict.theirPath);

                    if (conflictPath.isEmpty()) {
                        continue;
                    }

                    QList<QByteArray> conflictPaths;
                    if (!conflict.ancestorPath.isEmpty()) {
                        conflictPaths.append(conflict.ancestorPath);
                    }
                    if (!conflict.ourPath.isEmpty() && !conflictPaths.contains(conflict.ourPath)) {
                        conflictPaths.append(conflict.ourPath);
                    }
                    if (!conflict.theirPath.isEmpty() && !conflictPaths.contains(conflict.theirPath)) {
                        conflictPaths.append(conflict.theirPath);
                    }

                    const bool oursRenamed = !conflict.ancestorPath.isEmpty() && !conflict.ourPath.isEmpty() && conflict.ourPath != conflict.ancestorPath;
                    const bool theirsRenamed = !conflict.ancestorPath.isEmpty() && !conflict.theirPath.isEmpty() && conflict.theirPath != conflict.ancestorPath;
                    const bool renameModifyConflict =
                        !conflict.ancestorPath.isEmpty() &&
                        !conflict.ourPath.isEmpty() &&
                        !conflict.theirPath.isEmpty() &&
                        (oursRenamed != theirsRenamed) &&
                        ((oursRenamed && conflict.theirPath == conflict.ancestorPath) ||
                         (theirsRenamed && conflict.ourPath == conflict.ancestorPath));

                    if (renameModifyConflict) {
                        git_index_entry renamedEntry = oursRenamed
                            ? makeIndexEntry(conflict.ourPath, conflict.ourOid, conflict.ourMode)
                            : makeIndexEntry(conflict.theirPath, conflict.theirOid, conflict.theirMode);
                        git_index_entry modifiedEntry = oursRenamed
                            ? makeIndexEntry(conflict.theirPath, conflict.theirOid, conflict.theirMode)
                            : makeIndexEntry(conflict.ourPath, conflict.ourOid, conflict.ourMode);
                        git_index_entry ancestorEntry = makeIndexEntry(conflict.ancestorPath, conflict.ancestorOid, conflict.ancestorMode);
                        const QByteArray targetPath = oursRenamed ? conflict.ourPath : conflict.theirPath;

                        QByteArray mergedBuffer;
                        const bool renamedMatchesAncestor = entryMatches(&renamedEntry, &ancestorEntry);
                        const bool modifiedMatchesAncestor = entryMatches(&modifiedEntry, &ancestorEntry);

                        if (renamedMatchesAncestor && !modifiedMatchesAncestor) {
                            mergedBuffer = entryContent(&modifiedEntry);
                        } else if (!renamedMatchesAncestor && modifiedMatchesAncestor) {
                            mergedBuffer = entryContent(&renamedEntry);
                        } else if (renamedMatchesAncestor && modifiedMatchesAncestor) {
                            mergedBuffer = entryContent(&renamedEntry);
                        } else {
                            git_merge_file_result mergeResult = {};
                            check(git_merge_file_from_index(&mergeResult,
                                                            repo,
                                                            &ancestorEntry,
                                                            &renamedEntry,
                                                            &modifiedEntry,
                                                            nullptr));
                            mergedBuffer = mergeResult.ptr != nullptr && mergeResult.len > 0
                                ? QByteArray(mergeResult.ptr, static_cast<int>(mergeResult.len))
                                : QByteArray();
                            git_merge_file_result_free(&mergeResult);
                        }

                        for (const auto& path : conflictPaths) {
                            git_index_conflict_remove(index, path.constData());
                        }
                        for (const auto& path : conflictPaths) {
                            if (path != targetPath) {
                                QFile::remove(repoDir.absoluteFilePath(QString::fromUtf8(path)));
                            }
                        }

                        writeBuffer(targetPath.constData(), repoDir, mergedBuffer);
                        stageBufferAtPath(index, targetPath, mergedBuffer);
                        continue;
                    }

                    for (const auto& path : conflictPaths) {
                        git_index_conflict_remove(index, path.constData());
                    }

                    // If "ours" deleted or renamed away from the conflicted path, keep that result
                    // by removing the conflicting worktree entry and not re-adding it to the index.
                    if (conflict.ourPath.isEmpty()) {
                        for (const auto& path : conflictPaths) {
                            QFile::remove(repoDir.absoluteFilePath(QString::fromUtf8(path)));
                        }
                        continue;
                    }

                    for (const auto& path : conflictPaths) {
                        if (path != conflict.ourPath) {
                            QFile::remove(repoDir.absoluteFilePath(QString::fromUtf8(path)));
                        }
                    }

                    // Remove the diff tags from the file
                    auto buffer = useOurs(conflict.ourPath.constData(), repoDir);
                    writeBuffer(conflict.ourPath.constData(), repoDir, buffer);

                    // Add the file back into the index
                    stageBufferAtPath(index, conflict.ourPath, buffer);
                }
                check(git_index_write(index));

                Q_ASSERT(!git_index_has_conflicts(index));
            };

            QDir repoDir(git_repository_path(d->repo));
            repoDir.cdUp();
            resolveWithOurs(d->repo, index, repoDir);

            if(git_index_has_conflicts(index)) {
                //We should never get here
                return MergeResult(MergeResult::MergeConflicts);
            }
            return createMergeCommit();
        } else {
            return createMergeCommit();
        }
    }

    return MergeResult();
}

void GitRepository::createBranch(const QString &branchName, const QString& refSpec, bool checkout)
{
    Q_ASSERT(d->repo);

    auto locker = d->lockRepo();

    git_reference* ref;
    git_annotated_commit* commit;

    if(refSpec.isEmpty()) {
        git_reference* head;
        check(git_repository_head(&head, d->repo));
        check(git_annotated_commit_from_ref(&commit, d->repo, head));
        git_reference_free(head);
    } else {
        check(git_annotated_commit_from_revspec(&commit, d->repo, refSpec.toLocal8Bit()));
    }

    check(git_branch_create_from_annotated(&ref, d->repo, branchName.toLocal8Bit(), commit, false));

    if(checkout) {
        d->checkout(git_annotated_commit_id(commit), QString("refs/heads/") + branchName);
    }

    locker.unlock();
    emit refsChanged();
}

void GitRepository::deleteBranch(const QString &branchName)
{

}

GitRepository::GitFuture GitRepository::deleteBranchRemote(const QString &branchName)
{
    return push(":refs/heads/" + branchName);
}

bool GitRepository::remoteBranchExists(const QString &refSpec) const
{
    auto commit = makeScopedPtr(git_annotated_commit_free);
    commit = d->toAnnotatedCommit(refSpec);
    return commit != nullptr;
}

GitRepository::GitFuture GitRepository::checkout(const QString& refSpec, CheckoutMode mode)
{
    auto future = progressFuture<ResultBase>(
        [=](QFutureInterface<ResultBase> progressInterface)
        {
            auto path = d->mDirectory.absolutePath().toLocal8Bit();
            auto localRefSpec = refSpec.toLocal8Bit();
            auto repoMutex = d->mRepoMutex;

            auto prepareFuture = QtConcurrent::run([=]() mutable {
                return mtry([=]() mutable -> Monad::Result<LfsHydrator::LfsHydrationPlan> {
                    // Apply phase: serialize the worktree/index/HEAD mutation
                    // against the status worker and other repo ops (issue #546).
                    QMutexLocker locker(repoMutex.get());
                    auto repo = makeScopedPtr(git_repository_free);
                    check(git_repository_open(&repo, path));

                    git_object* object = nullptr;
                    check(git_revparse_single(&object, repo, localRefSpec.constData()));

                    git_checkout_options checkoutOptions = GIT_CHECKOUT_OPTIONS_INIT;
                    checkoutOptions.checkout_strategy = mode == CheckoutMode::Force
                                                            ? GIT_CHECKOUT_FORCE
                                                            : GIT_CHECKOUT_SAFE;
                    check(git_checkout_tree(repo, object, &checkoutOptions));

                    git_reference* resolvedRef = nullptr;
                    if (git_reference_dwim(&resolvedRef, repo, localRefSpec.constData()) == GIT_OK && resolvedRef) {
                        check(git_repository_set_head(repo, git_reference_name(resolvedRef)));
                        git_reference_free(resolvedRef);
                    } else {
                        check(git_repository_set_head_detached(repo, git_object_id(object)));
                    }

                    git_object_free(object);
                    return LfsHydrator::buildLfsHydrationPlan(repo);
                });
            });

            return AsyncFuture::observe(prepareFuture)
                .context(this, [=]() {
                    const auto prepareResult = prepareFuture.result();
                    if (prepareResult.hasError()) {
                        return AsyncFuture::completed(ResultBase(prepareResult.errorMessage(), prepareResult.errorCode()));
                    }
                    return LfsHydrator::runLfsHydrationPipeline(prepareResult.value(), this,
                                                   LfsHydrator::makeLfsTransferProgress(progressInterface));
                }).future();
        });
    emitRefsChangedOnSuccess(future);
    return future;
}

GitRepository::GitFuture GitRepository::reset(const QString& refSpec, ResetMode mode)
{
    auto future = progressFuture<ResultBase>(
        [=](QFutureInterface<ResultBase> progressInterface)
        {
            auto path = d->mDirectory.absolutePath().toLocal8Bit();
            auto localRefSpec = refSpec.toLocal8Bit();
            auto repoMutex = d->mRepoMutex;

            auto prepareFuture = QtConcurrent::run([=]() mutable {
                return mtry([=]() mutable -> Monad::Result<LfsHydrator::LfsHydrationPlan> {
                    // Apply phase: serialize the worktree/index mutation against
                    // the status worker and other repo ops (issue #546).
                    QMutexLocker locker(repoMutex.get());
                    auto repo = makeScopedPtr(git_repository_free);
                    check(git_repository_open(&repo, path));

                    git_object* object = nullptr;
                    check(git_revparse_single(&object, repo, localRefSpec.constData()));

                    git_reset_t resetType = GIT_RESET_HARD;
                    git_checkout_options checkoutOptions = GIT_CHECKOUT_OPTIONS_INIT;
                    git_checkout_options* checkoutOptionsPtr = nullptr;

                    switch (mode) {
                    case ResetMode::Soft:
                        resetType = GIT_RESET_SOFT;
                        break;
                    case ResetMode::Mixed:
                        resetType = GIT_RESET_MIXED;
                        break;
                    case ResetMode::Hard:
                        resetType = GIT_RESET_HARD;
                        checkoutOptions.checkout_strategy = GIT_CHECKOUT_FORCE
                            | GIT_CHECKOUT_REMOVE_UNTRACKED;
                        checkoutOptionsPtr = &checkoutOptions;
                        break;
                    }

                    check(git_reset(repo, object, resetType, checkoutOptionsPtr));
                    git_object_free(object);

                    if (mode != ResetMode::Hard) {
                        return Monad::Result<LfsHydrator::LfsHydrationPlan>(LfsHydrator::LfsHydrationPlan{});
                    }
                    return LfsHydrator::buildLfsHydrationPlan(repo);
                });
            });

            return AsyncFuture::observe(prepareFuture)
                .context(this, [=]() {
                    const auto prepareResult = prepareFuture.result();
                    if (prepareResult.hasError()) {
                        return AsyncFuture::completed(ResultBase(prepareResult.errorMessage(), prepareResult.errorCode()));
                    }
                    return LfsHydrator::runLfsHydrationPipeline(prepareResult.value(), this,
                                                   LfsHydrator::makeLfsTransferProgress(progressInterface));
                }).future();
        });
    emitRefsChangedOnSuccess(future);
    return future;
}


static QString buildRestoreCommitMessage(git_repository* repo,
                                         git_commit* targetCommit,
                                         git_commit* headCommit)
{
    const char* targetSummary = git_commit_summary(targetCommit);
    QString subject = QStringLiteral("Restored to: %1")
                          .arg(QString::fromUtf8(targetSummary ? targetSummary : "unknown"));

    const git_oid* targetOid = git_commit_id(targetCommit);
    const git_oid* headOid = git_commit_id(headCommit);

    git_time_t targetTime = git_commit_time(targetCommit);
    int targetOffset = git_commit_time_offset(targetCommit);
    QDateTime targetDateTime = QDateTime::fromSecsSinceEpoch(targetTime,
                                   QTimeZone::fromSecondsAheadOfUtc(targetOffset * 60));

    QString body = QStringLiteral("Target: %1 — \"%2\" (%3)\n")
                       .arg(oidToString(targetOid).left(10),
                            QString::fromUtf8(targetSummary ? targetSummary : ""),
                            targetDateTime.toString(Qt::ISODate));

    body += QStringLiteral("Previous HEAD: %1 — \"%2\"\n")
                .arg(oidToString(headOid).left(10),
                     QString::fromUtf8(git_commit_summary(headCommit)));

    // Walk from HEAD to target to enumerate rolled-back commits
    bool isAncestor = git_graph_descendant_of(repo, headOid, targetOid) == 1;
    if (isAncestor)
    {
        git_revwalk* revwalk = nullptr;
        if (git_revwalk_new(&revwalk, repo) == GIT_OK && revwalk)
        {
            std::unique_ptr<git_revwalk, decltype(&git_revwalk_free)>
                revwalkHolder(revwalk, &git_revwalk_free);

            git_revwalk_sorting(revwalk, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);
            git_revwalk_push(revwalk, headOid);
            git_revwalk_hide(revwalk, targetOid);

            QStringList rolledBack;
            git_oid walkOid;
            while (git_revwalk_next(&walkOid, revwalk) == GIT_OK)
            {
                git_commit* walkCommit = nullptr;
                if (git_commit_lookup(&walkCommit, repo, &walkOid) == GIT_OK)
                {
                    rolledBack.append(QStringLiteral("  %1 %2")
                                          .arg(oidToString(&walkOid).left(10),
                                               QString::fromUtf8(git_commit_summary(walkCommit))));
                    git_commit_free(walkCommit);
                }

                if (rolledBack.size() >= 10)
                {
                    break;
                }
            }

            // Count remaining commits (capped to avoid full graph traversal)
            constexpr int kMaxRemaining = 1000;
            int remaining = 0;
            while (remaining < kMaxRemaining && git_revwalk_next(&walkOid, revwalk) == GIT_OK)
            {
                remaining++;
            }

            if (!rolledBack.isEmpty())
            {
                int total = rolledBack.size() + remaining;
                bool capped = (remaining == kMaxRemaining);
                body += QStringLiteral("\nRolled back %1%2 commits:\n")
                            .arg(total)
                            .arg(capped ? QStringLiteral("+") : QString());
                body += rolledBack.join(QLatin1Char('\n'));
                if (remaining > 0)
                {
                    body += QStringLiteral("\n  ... and %1%2 more")
                                .arg(remaining)
                                .arg(capped ? QStringLiteral("+") : QString());
                }
            }
        }
    }

    return subject + QStringLiteral("\n\n") + body;
}

GitRepository::GitFuture GitRepository::restoreToCommit(const QString& targetSha)
{
    Q_ASSERT(account());

    auto accountName = account()->name().toLocal8Bit();
    auto accountEmail = account()->email().toLocal8Bit();

    auto future = progressFuture<ResultBase>(
        [=](QFutureInterface<ResultBase> progressInterface)
        {
            auto path = d->mDirectory.absolutePath().toLocal8Bit();
            auto localTargetSha = targetSha.toLocal8Bit();
            auto repoMutex = d->mRepoMutex;

            auto prepareFuture = QtConcurrent::run([=]() mutable {
                return mtry([=]() mutable -> Monad::Result<LfsHydrator::LfsHydrationPlan> {
                    // Apply phase: creates a commit and checks out, writing the
                    // index/worktree. Serialize against the status worker (#546).
                    QMutexLocker locker(repoMutex.get());
                    auto repo = makeScopedPtr(git_repository_free);
                    check(git_repository_open(&repo, path));

                    // Look up target commit
                    git_oid targetOid;
                    check(git_oid_fromstr(&targetOid, localTargetSha.constData()));

                    git_commit* targetCommit = nullptr;
                    check(git_commit_lookup(&targetCommit, repo, &targetOid));
                    std::unique_ptr<git_commit, decltype(&git_commit_free)>
                        targetHolder(targetCommit, &git_commit_free);

                    // Get target's tree
                    git_tree* targetTree = nullptr;
                    check(git_commit_tree(&targetTree, targetCommit));
                    std::unique_ptr<git_tree, decltype(&git_tree_free)>
                        treeHolder(targetTree, &git_tree_free);

                    // Look up HEAD as parent
                    git_object* parentObj = nullptr;
                    git_reference* headRef = nullptr;
                    check(git_revparse_ext(&parentObj, &headRef, repo, "HEAD"));
                    std::unique_ptr<git_object, decltype(&git_object_free)>
                        parentHolder(parentObj, &git_object_free);
                    std::unique_ptr<git_reference, decltype(&git_reference_free)>
                        headRefHolder(headRef, &git_reference_free);

                    auto* headCommit = reinterpret_cast<git_commit*>(parentObj);

                    // Build commit message
                    QString message = buildRestoreCommitMessage(repo, targetCommit, headCommit);

                    // Create signature
                    git_signature* sig = nullptr;
                    check(git_signature_now(&sig, accountName.constData(), accountEmail.constData()));
                    std::unique_ptr<git_signature, decltype(&git_signature_free)>
                        sigHolder(sig, &git_signature_free);

                    // Create forward commit with target's tree
                    git_oid commitOid;
                    check(git_commit_create_v(
                        &commitOid,
                        repo,
                        "HEAD",
                        sig,
                        sig,
                        NULL,
                        message.toUtf8().constData(),
                        targetTree,
                        1, parentObj));

                    // Force-checkout target tree to working directory
                    git_checkout_options checkoutOpts = GIT_CHECKOUT_OPTIONS_INIT;
                    checkoutOpts.checkout_strategy = GIT_CHECKOUT_FORCE | GIT_CHECKOUT_REMOVE_UNTRACKED;
                    check(git_checkout_tree(repo, reinterpret_cast<git_object*>(targetTree), &checkoutOpts));

                    // Update index to match target tree
                    git_index* index = nullptr;
                    check(git_repository_index(&index, repo));
                    std::unique_ptr<git_index, decltype(&git_index_free)>
                        indexHolder(index, &git_index_free);
                    check(git_index_read_tree(index, targetTree));
                    check(git_index_write(index));

                    return LfsHydrator::buildLfsHydrationPlan(repo);
                });
            });

            return AsyncFuture::observe(prepareFuture)
                .context(this, [=]() {
                    const auto prepareResult = prepareFuture.result();
                    if (prepareResult.hasError()) {
                        return AsyncFuture::completed(ResultBase(prepareResult.errorMessage(), prepareResult.errorCode()));
                    }
                    return LfsHydrator::runLfsHydrationPipeline(prepareResult.value(), this,
                                                   LfsHydrator::makeLfsTransferProgress(progressInterface));
                }).future();
        });
    emitRefsChangedOnSuccess(future);
    return future;
}

void GitRepository::setModifiedFileCount(int count) {
    if(d->mModifiedFilesCount != count) {
        d->mModifiedFilesCount = count;
        emit modifiedFileCountChanged();
    }
}

void GitRepository::check(int error)
{
    return GitRepositoryData::check(error);
}


QString GitRepository::fixUpRemote(const QString &remote)
{
    if(remote.isEmpty()) {
        return QStringLiteral("origin");
    } else {
        return remote;
    }
}

void GitRepository::addRemoteHelper(const QString &name, const QString &url)
{
    auto remote = makeScopedPtr(&git_remote_free);
    check(git_remote_create(&remote,
                            d->repo,
                            name.toLocal8Bit(),
                            url.toLocal8Bit()));
    emit remotesChanged();
}

QString GitRepository::headBranchName() const
{
    if(d->repo == nullptr) {
        return QString();
    }

    git_reference* head = nullptr;
    const int headError = git_repository_head(&head, d->repo);
    if (headError != GIT_OK || head == nullptr) {
        return QString();
    }

    QString name;
    if (git_reference_is_branch(head) != 0) {
        const char* branchName = nullptr;
        if (git_branch_name(&branchName, head) == GIT_OK && branchName != nullptr) {
            name = QString::fromLocal8Bit(branchName);
        }
    }

    git_reference_free(head);
    return name;
}

GitRepository::AheadBehindFuture GitRepository::remoteAheadBehindCommitCounts(const QString& remote,
                                                                              const QString& branchName) const
{
    const QString repositoryPath = d->mDirectory.absolutePath();
    const QString fixedRemote = remote.isEmpty() ? QStringLiteral("origin") : remote;
    const QString fixedBranch = branchName.isEmpty() ? headBranchName() : branchName;
    const QString localRefSpec = QStringLiteral("refs/heads/%1").arg(fixedBranch);
    const QString remoteRefSpec = QStringLiteral("refs/heads/%1").arg(fixedBranch);
    const GitCredentials credentials = d->m_credentials;

    return QtConcurrent::run([repositoryPath, fixedRemote, fixedBranch, localRefSpec, remoteRefSpec, credentials]() {
        return mtry([repositoryPath, fixedRemote, fixedBranch, localRefSpec, remoteRefSpec, credentials]() -> Monad::Result<AheadBehindCounts> {
            if (repositoryPath.isEmpty()) {
                return Monad::Result<AheadBehindCounts>(QStringLiteral("Repository path is empty."));
            }
            if (fixedBranch.isEmpty()) {
                return Monad::Result<AheadBehindCounts>(QStringLiteral("Current branch is empty."));
            }

            git_repository* repo = nullptr;
            const int openResult = git_repository_open(&repo, repositoryPath.toLocal8Bit().constData());
            if (openResult != GIT_OK || repo == nullptr) {
                return Monad::Result<AheadBehindCounts>(
                    gitErrorMessageWithPrefix(QStringLiteral("Failed to open repository for remote ahead/behind")),
                    openResult);
            }
            std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

            git_object* localObj = nullptr;
            const int localResult = git_revparse_single(&localObj, repo, localRefSpec.toLocal8Bit().constData());
            if (localResult != GIT_OK || localObj == nullptr) {
                return Monad::Result<AheadBehindCounts>(
                    gitErrorMessageWithPrefix(QStringLiteral("Failed to resolve local branch for remote ahead/behind")),
                    localResult);
            }
            std::unique_ptr<git_object, decltype(&git_object_free)> localObjHolder(localObj, &git_object_free);

            git_remote* gitRemote = nullptr;
            const int lookupResult = git_remote_lookup(&gitRemote, repo, fixedRemote.toLocal8Bit().constData());
            if (lookupResult != GIT_OK || gitRemote == nullptr) {
                return Monad::Result<AheadBehindCounts>(
                    gitErrorMessageWithPrefix(QStringLiteral("Failed to lookup remote for ahead/behind")),
                    lookupResult);
            }
            std::unique_ptr<git_remote, decltype(&git_remote_free)> gitRemoteHolder(gitRemote, &git_remote_free);

            git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;
            SshCallbackPayload callbackPayload;
            callbackPayload.httpsToken = credentials.httpsToken;
            callbacks.credentials = GitRepositoryData::credentailCallBack;
            callbacks.certificate_check = GitRepositoryData::certificateCheckCallback;
            callbacks.payload = &callbackPayload;
            const int connectResult = git_remote_connect(gitRemote, GIT_DIRECTION_FETCH, &callbacks, nullptr, nullptr);
            if (connectResult != GIT_OK) {
                const QString msg = gitErrorMessageWithPrefix(QStringLiteral("Failed to connect remote for ahead/behind"));
                const int code = isHttpAuthFailure(connectResult, msg)
                                 ? static_cast<int>(GitRepository::GitErrorCode::HttpAuthFailed)
                                 : connectResult;
                return Monad::Result<AheadBehindCounts>(msg, code);
            }

            const git_remote_head** remoteHeads = nullptr;
            size_t remoteHeadCount = 0;
            const int lsResult = git_remote_ls(&remoteHeads, &remoteHeadCount, gitRemote);
            git_remote_disconnect(gitRemote);
            if (lsResult != GIT_OK) {
                return Monad::Result<AheadBehindCounts>(
                    gitErrorMessageWithPrefix(QStringLiteral("Failed to list remote refs for ahead/behind")),
                    lsResult);
            }

            const QByteArray remoteRefSpecBytes = remoteRefSpec.toLocal8Bit();
            const git_oid* remoteOid = nullptr;
            for (size_t i = 0; i < remoteHeadCount; ++i) {
                const git_remote_head* remoteHead = remoteHeads[i];
                if (remoteHead == nullptr || remoteHead->name == nullptr) {
                    continue;
                }

                if (QByteArray(remoteHead->name) == remoteRefSpecBytes) {
                    remoteOid = &remoteHead->oid;
                    break;
                }
            }

            if (remoteOid == nullptr) {
                return Monad::Result<AheadBehindCounts>(
                    QStringLiteral("Failed to resolve remote branch '%1/%2'.").arg(fixedRemote, fixedBranch));
            }

            git_odb* objectDb = nullptr;
            const int odbResult = git_repository_odb(&objectDb, repo);
            if (odbResult != GIT_OK || objectDb == nullptr) {
                return Monad::Result<AheadBehindCounts>(
                    gitErrorMessageWithPrefix(QStringLiteral("Failed to open object database for ahead/behind")),
                    odbResult);
            }
            std::unique_ptr<git_odb, decltype(&git_odb_free)> objectDbHolder(objectDb, &git_odb_free);

            const bool hasRemoteTipObject = git_odb_exists(objectDb, remoteOid) == 1;
            if (!hasRemoteTipObject) {
                // Lightweight remote checks do not download objects. If the advertised
                // remote tip is unknown locally, we can still report "behind" and
                // estimate local-only "ahead" against the last fetched tracking tip.
                AheadBehindCounts fallbackCounts;
                fallbackCounts.behind = 1;

                const QString trackingRefSpec = QStringLiteral("refs/remotes/%1/%2").arg(fixedRemote, fixedBranch);
                git_object* trackingObj = nullptr;
                const int trackingResult = git_revparse_single(&trackingObj,
                                                               repo,
                                                               trackingRefSpec.toLocal8Bit().constData());
                if (trackingResult == GIT_OK && trackingObj != nullptr) {
                    std::unique_ptr<git_object, decltype(&git_object_free)> trackingObjHolder(trackingObj,
                                                                                               &git_object_free);
                    size_t ahead = 0;
                    size_t behind = 0;
                    const int localGraphResult = git_graph_ahead_behind(&ahead,
                                                                        &behind,
                                                                        repo,
                                                                        git_object_id(localObj),
                                                                        git_object_id(trackingObj));
                    if (localGraphResult == GIT_OK) {
                        fallbackCounts.ahead = ahead;
                    }
                }

                return Monad::Result<AheadBehindCounts>(fallbackCounts);
            }

            size_t ahead = 0;
            size_t behind = 0;
            const int graphResult = git_graph_ahead_behind(&ahead,
                                                           &behind,
                                                           repo,
                                                           git_object_id(localObj),
                                                           remoteOid);
            if (graphResult != GIT_OK) {
                return Monad::Result<AheadBehindCounts>(
                    gitErrorMessageWithPrefix(QStringLiteral("Failed to compute remote ahead/behind")),
                    graphResult);
            }

            AheadBehindCounts counts;
            counts.ahead = ahead;
            counts.behind = behind;
            return Monad::Result<AheadBehindCounts>(counts);
        });
    });
}

Monad::ResultString GitRepository::headCommitOid(const QString& repositoryPath)
{
    git_repository* repo = nullptr;
    const int openResult = git_repository_open(&repo, repositoryPath.toLocal8Bit().constData());
    if (openResult != GIT_OK || repo == nullptr) {
        return Monad::ResultString(gitErrorMessageWithPrefix(QStringLiteral("Failed to open repository")),
                                   openResult);
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    git_oid headOid;
    const int headResult = git_reference_name_to_id(&headOid, repo, "HEAD");
    if (headResult == GIT_EUNBORNBRANCH || headResult == GIT_ENOTFOUND) {
        return Monad::ResultString(QString());
    }
    if (headResult != GIT_OK) {
        return Monad::ResultString(gitErrorMessageWithPrefix(QStringLiteral("Failed to resolve HEAD")),
                                   headResult);
    }

    char oidBuffer[GIT_OID_HEXSZ + 1];
    git_oid_tostr(oidBuffer, sizeof(oidBuffer), &headOid);
    return Monad::ResultString(QString::fromLatin1(oidBuffer));
}

Monad::ResultString GitRepository::headCommitMessage(const QString& repositoryPath)
{
    git_repository* repo = nullptr;
    const int openResult = git_repository_open(&repo, repositoryPath.toLocal8Bit().constData());
    if (openResult != GIT_OK || repo == nullptr) {
        return Monad::ResultString(gitErrorMessageWithPrefix(QStringLiteral("Failed to open repository")),
                                   openResult);
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    git_oid headOid;
    const int headResult = git_reference_name_to_id(&headOid, repo, "HEAD");
    if (headResult == GIT_EUNBORNBRANCH || headResult == GIT_ENOTFOUND) {
        return Monad::ResultString(QString());
    }
    if (headResult != GIT_OK) {
        return Monad::ResultString(gitErrorMessageWithPrefix(QStringLiteral("Failed to resolve HEAD")),
                                   headResult);
    }

    git_commit* commit = nullptr;
    const int lookupResult = git_commit_lookup(&commit, repo, &headOid);
    if (lookupResult != GIT_OK || commit == nullptr) {
        return Monad::ResultString(gitErrorMessageWithPrefix(QStringLiteral("Failed to lookup HEAD commit")),
                                   lookupResult);
    }
    std::unique_ptr<git_commit, decltype(&git_commit_free)> commitHolder(commit, &git_commit_free);

    const char* message = git_commit_message(commit);
    return Monad::ResultString(message != nullptr ? QString::fromUtf8(message) : QString());
}

Monad::ResultString GitRepository::mergeBaseCommitOid(const QString& repositoryPath,
                                                      const QString& firstCommitOid,
                                                      const QString& secondCommitOid)
{
    if (firstCommitOid.isEmpty() || secondCommitOid.isEmpty()) {
        return Monad::ResultString(QString());
    }

    git_repository* repo = nullptr;
    const int openResult = git_repository_open(&repo, repositoryPath.toLocal8Bit().constData());
    if (openResult != GIT_OK || repo == nullptr) {
        return Monad::ResultString(gitErrorMessageWithPrefix(QStringLiteral("Failed to open repository for merge-base")),
                                   openResult);
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    git_oid firstOid;
    if (git_oid_fromstr(&firstOid, firstCommitOid.toLatin1().constData()) != GIT_OK) {
        return Monad::ResultString(QStringLiteral("Invalid first oid for merge-base."));
    }

    git_oid secondOid;
    if (git_oid_fromstr(&secondOid, secondCommitOid.toLatin1().constData()) != GIT_OK) {
        return Monad::ResultString(QStringLiteral("Invalid second oid for merge-base."));
    }

    git_oid mergeBaseOid;
    const int mergeBaseResult = git_merge_base(&mergeBaseOid, repo, &firstOid, &secondOid);
    if (mergeBaseResult == GIT_ENOTFOUND) {
        return Monad::ResultString(QString());
    }
    if (mergeBaseResult != GIT_OK) {
        return Monad::ResultString(gitErrorMessageWithPrefix(QStringLiteral("Failed to resolve merge-base")),
                                   mergeBaseResult);
    }

    char oidBuffer[GIT_OID_HEXSZ + 1];
    git_oid_tostr(oidBuffer, sizeof(oidBuffer), &mergeBaseOid);
    return Monad::ResultString(QString::fromLatin1(oidBuffer));
}

Monad::Result<QStringList> GitRepository::commitParentOids(const QString& repositoryPath,
                                                           const QString& commitOid)
{
    if (commitOid.isEmpty()) {
        return Monad::Result<QStringList>(QStringList{});
    }

    git_repository* repo = nullptr;
    const int openResult = git_repository_open(&repo, repositoryPath.toLocal8Bit().constData());
    if (openResult != GIT_OK || repo == nullptr) {
        return Monad::Result<QStringList>(
            gitErrorMessageWithPrefix(QStringLiteral("Failed to open repository for commit parents")),
            openResult);
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    git_oid oid;
    if (git_oid_fromstr(&oid, commitOid.toLatin1().constData()) != GIT_OK) {
        return Monad::Result<QStringList>(QStringLiteral("Invalid oid for commit parents."));
    }

    git_commit* commit = nullptr;
    const int lookupResult = git_commit_lookup(&commit, repo, &oid);
    if (lookupResult != GIT_OK || commit == nullptr) {
        return Monad::Result<QStringList>(
            gitErrorMessageWithPrefix(QStringLiteral("Failed to resolve commit for parents")),
            lookupResult);
    }
    std::unique_ptr<git_commit, decltype(&git_commit_free)> commitHolder(commit, &git_commit_free);

    QStringList parentOids;
    const unsigned int parentCount = git_commit_parentcount(commit);
    parentOids.reserve(static_cast<int>(parentCount));
    for (unsigned int i = 0; i < parentCount; ++i) {
        const git_oid* parentOid = git_commit_parent_id(commit, i);
        if (parentOid == nullptr) {
            continue;
        }

        char oidBuffer[GIT_OID_HEXSZ + 1];
        git_oid_tostr(oidBuffer, sizeof(oidBuffer), parentOid);
        parentOids.append(QString::fromLatin1(oidBuffer));
    }

    return Monad::Result<QStringList>(parentOids);
}

Monad::Result<GitRepository::AheadBehindCounts> GitRepository::aheadBehindCommitCounts(
    const QString& repositoryPath,
    const QString& localRefSpec,
    const QString& upstreamRefSpec)
{
    if (localRefSpec.isEmpty() || upstreamRefSpec.isEmpty()) {
        return Monad::Result<AheadBehindCounts>(QStringLiteral("Local or upstream ref is empty."));
    }

    git_repository* repo = nullptr;
    const int openResult = git_repository_open(&repo, repositoryPath.toLocal8Bit().constData());
    if (openResult != GIT_OK || repo == nullptr) {
        return Monad::Result<AheadBehindCounts>(
            gitErrorMessageWithPrefix(QStringLiteral("Failed to open repository for ahead/behind")),
            openResult);
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    git_object* localObj = nullptr;
    const int localResult = git_revparse_single(&localObj, repo, localRefSpec.toLocal8Bit().constData());
    if (localResult != GIT_OK || localObj == nullptr) {
        return Monad::Result<AheadBehindCounts>(
            gitErrorMessageWithPrefix(QStringLiteral("Failed to resolve local ref for ahead/behind")),
            localResult);
    }
    std::unique_ptr<git_object, decltype(&git_object_free)> localObjHolder(localObj, &git_object_free);

    git_object* upstreamObj = nullptr;
    const int upstreamResult = git_revparse_single(&upstreamObj, repo, upstreamRefSpec.toLocal8Bit().constData());
    if (upstreamResult != GIT_OK || upstreamObj == nullptr) {
        return Monad::Result<AheadBehindCounts>(
            gitErrorMessageWithPrefix(QStringLiteral("Failed to resolve upstream ref for ahead/behind")),
            upstreamResult);
    }
    std::unique_ptr<git_object, decltype(&git_object_free)> upstreamObjHolder(upstreamObj, &git_object_free);

    size_t ahead = 0;
    size_t behind = 0;
    const int graphResult = git_graph_ahead_behind(&ahead,
                                                   &behind,
                                                   repo,
                                                   git_object_id(localObj),
                                                   git_object_id(upstreamObj));
    if (graphResult != GIT_OK) {
        return Monad::Result<AheadBehindCounts>(
            gitErrorMessageWithPrefix(QStringLiteral("Failed to compute ahead/behind")),
            graphResult);
    }

    AheadBehindCounts counts;
    counts.ahead = ahead;
    counts.behind = behind;
    return Monad::Result<AheadBehindCounts>(counts);
}

Monad::Result<QStringList> GitRepository::diffPathsBetweenCommits(const QString& repositoryPath,
                                                                  const QString& beforeCommitOid,
                                                                  const QString& afterCommitOid)
{
    if (afterCommitOid.isEmpty() || beforeCommitOid == afterCommitOid) {
        return Monad::Result<QStringList>(QStringList());
    }

    git_repository* repo = nullptr;
    const int openResult = git_repository_open(&repo, repositoryPath.toLocal8Bit().constData());
    if (openResult != GIT_OK || repo == nullptr) {
        return Monad::Result<QStringList>(gitErrorMessageWithPrefix(QStringLiteral("Failed to open repository for diff")),
                                          openResult);
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    git_oid afterOid;
    if (git_oid_fromstr(&afterOid, afterCommitOid.toLatin1().constData()) != GIT_OK) {
        return Monad::Result<QStringList>(QStringLiteral("Invalid after-head oid for commit diff."));
    }

    git_commit* afterCommit = nullptr;
    if (git_commit_lookup(&afterCommit, repo, &afterOid) != GIT_OK || afterCommit == nullptr) {
        return Monad::Result<QStringList>(gitErrorMessageWithPrefix(QStringLiteral("Failed to load after-head commit")));
    }
    std::unique_ptr<git_commit, decltype(&git_commit_free)> afterCommitHolder(afterCommit, &git_commit_free);

    git_tree* afterTree = nullptr;
    if (git_commit_tree(&afterTree, afterCommit) != GIT_OK || afterTree == nullptr) {
        return Monad::Result<QStringList>(gitErrorMessageWithPrefix(QStringLiteral("Failed to load after-head tree")));
    }
    std::unique_ptr<git_tree, decltype(&git_tree_free)> afterTreeHolder(afterTree, &git_tree_free);

    git_commit* beforeCommit = nullptr;
    git_tree* beforeTree = nullptr;
    if (!beforeCommitOid.isEmpty()) {
        git_oid beforeOid;
        if (git_oid_fromstr(&beforeOid, beforeCommitOid.toLatin1().constData()) != GIT_OK) {
            return Monad::Result<QStringList>(QStringLiteral("Invalid before-head oid for commit diff."));
        }

        if (git_commit_lookup(&beforeCommit, repo, &beforeOid) != GIT_OK || beforeCommit == nullptr) {
            return Monad::Result<QStringList>(gitErrorMessageWithPrefix(QStringLiteral("Failed to load before-head commit")));
        }

        if (git_commit_tree(&beforeTree, beforeCommit) != GIT_OK || beforeTree == nullptr) {
            git_commit_free(beforeCommit);
            beforeCommit = nullptr;
            return Monad::Result<QStringList>(gitErrorMessageWithPrefix(QStringLiteral("Failed to load before-head tree")));
        }
    }
    std::unique_ptr<git_commit, decltype(&git_commit_free)> beforeCommitHolder(beforeCommit, &git_commit_free);
    std::unique_ptr<git_tree, decltype(&git_tree_free)> beforeTreeHolder(beforeTree, &git_tree_free);

    git_diff* diff = nullptr;
    git_diff_options diffOptions = GIT_DIFF_OPTIONS_INIT;
    if (git_diff_tree_to_tree(&diff, repo, beforeTree, afterTree, &diffOptions) != GIT_OK || diff == nullptr) {
        return Monad::Result<QStringList>(gitErrorMessageWithPrefix(QStringLiteral("Failed to build commit diff")));
    }
    std::unique_ptr<git_diff, decltype(&git_diff_free)> diffHolder(diff, &git_diff_free);

    QStringList paths;
    const size_t deltaCount = git_diff_num_deltas(diff);
    paths.reserve(static_cast<int>(deltaCount) * 2);
    for (size_t i = 0; i < deltaCount; ++i) {
        const git_diff_delta* delta = git_diff_get_delta(diff, i);
        if (!delta) {
            continue;
        }

        if (delta->old_file.path && delta->old_file.path[0] != '\0') {
            paths.append(QString::fromUtf8(delta->old_file.path));
        }
        if (delta->new_file.path && delta->new_file.path[0] != '\0') {
            paths.append(QString::fromUtf8(delta->new_file.path));
        }
    }

    return Monad::Result<QStringList>(uniqueSortedPaths(paths));
}

Monad::Result<QByteArray> GitRepository::fileContentAtCommit(const QString& repositoryPath,
                                                             const QString& commitOid,
                                                             const QString& relativePath)
{
    if (commitOid.isEmpty() || relativePath.isEmpty()) {
        return Monad::Result<QByteArray>(QByteArray());
    }

    git_repository* repo = nullptr;
    const int openResult = git_repository_open(&repo, repositoryPath.toLocal8Bit().constData());
    if (openResult != GIT_OK || repo == nullptr) {
        return Monad::Result<QByteArray>(gitErrorMessageWithPrefix(QStringLiteral("Failed to open repository for commit file lookup")),
                                         openResult);
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    git_oid commitId;
    if (git_oid_fromstr(&commitId, commitOid.toLatin1().constData()) != GIT_OK) {
        return Monad::Result<QByteArray>(QStringLiteral("Invalid commit oid for commit file lookup."));
    }

    git_commit* commit = nullptr;
    if (git_commit_lookup(&commit, repo, &commitId) != GIT_OK || commit == nullptr) {
        return Monad::Result<QByteArray>(gitErrorMessageWithPrefix(QStringLiteral("Failed to load commit for file lookup")));
    }
    std::unique_ptr<git_commit, decltype(&git_commit_free)> commitHolder(commit, &git_commit_free);

    git_tree* tree = nullptr;
    if (git_commit_tree(&tree, commit) != GIT_OK || tree == nullptr) {
        return Monad::Result<QByteArray>(gitErrorMessageWithPrefix(QStringLiteral("Failed to load commit tree for file lookup")));
    }
    std::unique_ptr<git_tree, decltype(&git_tree_free)> treeHolder(tree, &git_tree_free);

    const QString normalizedPath = QDir::fromNativeSeparators(relativePath);
    git_tree_entry* entry = nullptr;
    const int entryResult = git_tree_entry_bypath(&entry, tree, normalizedPath.toUtf8().constData());
    if (entryResult == GIT_ENOTFOUND) {
        return Monad::Result<QByteArray>(QByteArray());
    }
    if (entryResult != GIT_OK || entry == nullptr) {
        return Monad::Result<QByteArray>(gitErrorMessageWithPrefix(QStringLiteral("Failed to resolve path in commit tree")));
    }
    std::unique_ptr<git_tree_entry, decltype(&git_tree_entry_free)> entryHolder(entry, &git_tree_entry_free);

    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return Monad::Result<QByteArray>(QByteArray());
    }

    const git_oid* blobOid = git_tree_entry_id(entry);
    if (!blobOid || git_oid_is_zero(blobOid)) {
        return Monad::Result<QByteArray>(QByteArray());
    }

    git_blob* blob = nullptr;
    if (git_blob_lookup(&blob, repo, blobOid) != GIT_OK || !blob) {
        return Monad::Result<QByteArray>(gitErrorMessageWithPrefix(QStringLiteral("Failed to load blob from commit tree")));
    }
    std::unique_ptr<git_blob, decltype(&git_blob_free)> blobHolder(blob, &git_blob_free);

    const auto* raw = static_cast<const char*>(git_blob_rawcontent(blob));
    const auto size = static_cast<int>(git_blob_rawsize(blob));
    if (!raw || size <= 0) {
        return Monad::Result<QByteArray>(QByteArray());
    }

    return Monad::Result<QByteArray>(QByteArray(raw, size));
}

QByteArray GitRepository::fileContentAtCommit(const QString& commitOid,
                                               const QString& relativePath) const
{
    const QString repoPath = d->mDirectory.absolutePath();
    if (repoPath.isEmpty()) {
        qWarning("GitRepository::fileContentAtCommit: repository is not open");
        return {};
    }

    auto result = fileContentAtCommit(repoPath, commitOid, relativePath);
    if (result.hasError()) {
        qWarning("GitRepository::fileContentAtCommit: %s", qPrintable(result.errorMessage()));
        return {};
    }
    return result.value();
}

void GitRepository::setAccount(Account* account) {
    if(d->mAccount != account) {
        d->mAccount = account;
        emit accountChanged();
    }
}

Account* GitRepository::account() const {
    return d->mAccount;
}

void GitRepository::setCredentials(const GitCredentials& credentials)
{
    d->m_credentials = credentials;
}

GitCredentials GitRepository::credentials() const
{
    return d->m_credentials;
}
