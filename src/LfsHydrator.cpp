#include "LfsHydrator.h"

#include "GitOidUtils.h"
#include "GitRefSpecUtil.h"
#include "RSAKeyGenerator.h"
#include "LfsFilter.h"
#include "LfsStore.h"
#include "LfsPolicy.h"
#include "LfsBatchClient.h"
#include "Monad/Result.h"
#include "Monad/Monad.h"

#include "git2.h"
#include <git2/index.h>
#include <git2/sys/errors.h>

#include <QByteArray>
#include <QCryptographicHash>
#include <QDebug>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <QVector>
#include <QtConcurrent>

#include "asyncfuture.h"

#include <algorithm>
#include <functional>
#include <memory>

using namespace Monad;

namespace QQuickGit {
namespace LfsHydrator {

namespace {

QString findWorktreeFileForLfsOid(const QString& workTreeRoot, const QString& oid)
{
    if (workTreeRoot.isEmpty() || oid.isEmpty()) {
        return QString();
    }

    QDirIterator it(workTreeRoot,
                    QDir::Files | QDir::NoDotAndDotDot,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString path = it.next();
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            continue;
        }

        QCryptographicHash hash(QCryptographicHash::Sha256);
        while (!file.atEnd()) {
            const QByteArray chunk = file.read(256 * 1024);
            if (chunk.isEmpty() && file.error() != QFile::NoError) {
                hash.reset();
                break;
            }
            if (!chunk.isEmpty()) {
                hash.addData(chunk);
            }
        }

        if (QString::fromLatin1(hash.result().toHex()) == oid) {
            return path;
        }
    }

    return QString();
}

struct PrePushCredentialPayload {
    int totalMaxAttempts = 8;
    int totalAttempts = 0;
    int sshAgentMaxAttempts = 1;
    int sshAgentAttempts = 0;
    int sshKeyMaxAttempts = 1;
    int sshKeyAttempts = 0;
    QString httpsToken;   // empty = SSH-only path (default, no behaviour change)
};

struct LfsPushUploadPlan {
    QString gitDirPath;
    QVector<LfsBatchClient::ObjectSpec> objects;
    QHash<QString, LfsPointer> pointersByOid;
};

struct LfsTreeCollectPayload {
    git_repository* repo = nullptr;
    QHash<QString, LfsPointer>* pointersByOid = nullptr;
};

QVector<git_oid> resolvePushSourceCommits(git_repository* repo, const QString& sourceRef)
{
    QVector<git_oid> commitOids;
    if (!repo || sourceRef.isEmpty()) {
        return commitOids;
    }

    auto appendIfUnique = [&commitOids](const git_oid* oid) {
        if (!oid || git_oid_is_zero(oid)) {
            return;
        }
        for (const git_oid& existing : std::as_const(commitOids)) {
            if (git_oid_cmp(&existing, oid) == 0) {
                return;
            }
        }
        commitOids.push_back(*oid);
    };

    if (hasRefGlobPattern(sourceRef)) {
        git_reference_iterator* iterator = nullptr;
        if (git_reference_iterator_glob_new(&iterator, repo, sourceRef.toUtf8().constData()) != GIT_OK || !iterator) {
            return commitOids;
        }
        std::unique_ptr<git_reference_iterator, decltype(&git_reference_iterator_free)> iteratorHolder(
            iterator,
            &git_reference_iterator_free);

        git_reference* reference = nullptr;
        while (git_reference_next(&reference, iterator) == GIT_OK) {
            std::unique_ptr<git_reference, decltype(&git_reference_free)> referenceHolder(reference, &git_reference_free);
            reference = nullptr;

            git_object* commitObj = nullptr;
            if (git_reference_peel(&commitObj, referenceHolder.get(), GIT_OBJECT_COMMIT) != GIT_OK || !commitObj) {
                continue;
            }
            std::unique_ptr<git_object, decltype(&git_object_free)> commitHolder(commitObj, &git_object_free);
            appendIfUnique(git_object_id(commitObj));
        }
        return commitOids;
    }

    git_object* sourceObj = nullptr;
    if (git_revparse_single(&sourceObj, repo, sourceRef.toUtf8().constData()) != GIT_OK || !sourceObj) {
        return commitOids;
    }
    std::unique_ptr<git_object, decltype(&git_object_free)> sourceHolder(sourceObj, &git_object_free);

    git_object* sourceCommitObj = nullptr;
    if (git_object_peel(&sourceCommitObj, sourceObj, GIT_OBJECT_COMMIT) != GIT_OK || !sourceCommitObj) {
        return commitOids;
    }
    std::unique_ptr<git_object, decltype(&git_object_free)> sourceCommitHolder(sourceCommitObj, &git_object_free);
    appendIfUnique(git_object_id(sourceCommitObj));
    return commitOids;
}

int collectLfsPointersFromTree(const char* root, const git_tree_entry* entry, void* payload)
{
    Q_UNUSED(root);
    auto* state = reinterpret_cast<LfsTreeCollectPayload*>(payload);
    if (!state || !state->repo || !state->pointersByOid) {
        return 0;
    }

    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    QByteArray content = blobContent(state->repo, git_tree_entry_id(entry), 4096);
    if (content.isEmpty()) {
        return 0;
    }

    LfsPointer pointer;
    if (!LfsPointer::parse(content, &pointer)) {
        return 0;
    }
    if (pointer.oid.isEmpty() || state->pointersByOid->contains(pointer.oid)) {
        return 0;
    }

    state->pointersByOid->insert(pointer.oid, pointer);
    return 0;
}

void collectLfsPointerFromBlobOid(git_repository* repo,
                                  const git_oid* blobOid,
                                  QHash<QString, LfsPointer>* pointersByOid)
{
    if (!repo || !blobOid || !pointersByOid || git_oid_is_zero(blobOid)) {
        return;
    }

    QByteArray content = blobContent(repo, blobOid, 4096);
    if (content.isEmpty()) {
        return;
    }

    LfsPointer pointer;
    if (!LfsPointer::parse(content, &pointer)) {
        return;
    }
    if (pointer.oid.isEmpty() || pointersByOid->contains(pointer.oid)) {
        return;
    }

    pointersByOid->insert(pointer.oid, pointer);
}

void collectLfsPointersFromDiff(git_repository* repo,
                                git_tree* parentTree,
                                git_tree* commitTree,
                                QHash<QString, LfsPointer>* pointersByOid)
{
    if (!repo || !commitTree || !pointersByOid) {
        return;
    }

    git_diff* diff = nullptr;
    git_diff_options diffOptions = GIT_DIFF_OPTIONS_INIT;
    if (git_diff_tree_to_tree(&diff, repo, parentTree, commitTree, &diffOptions) != GIT_OK || !diff) {
        return;
    }
    std::unique_ptr<git_diff, decltype(&git_diff_free)> diffHolder(diff, &git_diff_free);

    const size_t deltaCount = git_diff_num_deltas(diff);
    for (size_t i = 0; i < deltaCount; ++i) {
        const git_diff_delta* delta = git_diff_get_delta(diff, i);
        if (!delta) {
            continue;
        }

        const git_oid* blobOid = &delta->new_file.id;
        if (git_oid_is_zero(blobOid)) {
            continue;
        }

        collectLfsPointerFromBlobOid(repo, blobOid, pointersByOid);
    }
}

bool hideRemoteTrackingTips(git_repository* repo,
                            git_revwalk* revwalk,
                            const QString& remoteName)
{
    if (!repo || !revwalk || remoteName.isEmpty()) {
        return false;
    }

    const QString glob = QStringLiteral("refs/remotes/%1/*").arg(remoteName);
    git_reference_iterator* iterator = nullptr;
    if (git_reference_iterator_glob_new(&iterator, repo, glob.toUtf8().constData()) != GIT_OK || !iterator) {
        return false;
    }
    std::unique_ptr<git_reference_iterator, decltype(&git_reference_iterator_free)> iteratorHolder(
        iterator,
        &git_reference_iterator_free);

    bool hidAny = false;
    git_reference* reference = nullptr;
    while (git_reference_next(&reference, iterator) == GIT_OK) {
        std::unique_ptr<git_reference, decltype(&git_reference_free)> referenceHolder(reference, &git_reference_free);
        reference = nullptr;

        const git_oid* remoteTip = git_reference_target(referenceHolder.get());
        if (!remoteTip) {
            continue;
        }

        if (git_revwalk_hide(revwalk, remoteTip) == GIT_OK) {
            hidAny = true;
        }
    }
    return hidAny;
}

int prePushRemoteCredentialCallback(git_credential **out,
                                    const char *url,
                                    const char *username_from_url,
                                    unsigned int allowed_types,
                                    void *payload)
{
    auto prePushPayload = reinterpret_cast<PrePushCredentialPayload*>(payload);
    if (prePushPayload) {
        prePushPayload->totalAttempts++;
        if (prePushPayload->totalAttempts > prePushPayload->totalMaxAttempts) {
            return GIT_PASSTHROUGH;
        }
    }

    const QString urlText = url ? QString::fromUtf8(url) : QString();
    const QUrl parsedUrl(urlText);
    const QString urlUser = parsedUrl.userName();
    const QString urlPassword = parsedUrl.password();
    const QString userNameText = (username_from_url && *username_from_url)
        ? QString::fromUtf8(username_from_url)
        : (urlUser.isEmpty() ? QStringLiteral("git") : urlUser);
    const QByteArray userNameUtf8 = userNameText.toUtf8();
    const char *userName = userNameUtf8.constData();
    if (allowed_types & GIT_CREDENTIAL_USERPASS_PLAINTEXT) {
        if (prePushPayload && !prePushPayload->httpsToken.isEmpty()) {
            return git_credential_userpass_plaintext_new(
                out, "x-access-token",
                prePushPayload->httpsToken.toUtf8().constData());
        }
        if (!userNameText.isEmpty() && !urlPassword.isEmpty()) {
            const QByteArray passwordUtf8 = urlPassword.toUtf8();
            const int result = git_credential_userpass_plaintext_new(out,
                                                                      userNameUtf8.constData(),
                                                                      passwordUtf8.constData());
            if (result == GIT_OK) {
                return GIT_OK;
            }
        }
    }

    if (allowed_types & GIT_CREDENTIAL_USERNAME) {
        const int result = git_credential_username_new(out, userName);
        if (result == GIT_OK) {
            return GIT_OK;
        }
    }

    if (allowed_types & GIT_CREDENTIAL_DEFAULT) {
        const int result = git_credential_default_new(out);
        if (result == GIT_OK) {
            return GIT_OK;
        }
    }

    if (allowed_types & GIT_CREDENTIAL_SSH_KEY) {
        const bool allowAgent = !prePushPayload || prePushPayload->sshAgentAttempts < prePushPayload->sshAgentMaxAttempts;
        if (allowAgent) {
            const int agentResult = git_credential_ssh_key_from_agent(out, userName);
            if (agentResult == GIT_OK) {
                if (prePushPayload) {
                    prePushPayload->sshAgentAttempts++;
                }
                return GIT_OK;
            }
        }

        const bool allowSshKey = !prePushPayload || prePushPayload->sshKeyAttempts < prePushPayload->sshKeyMaxAttempts;
        if (!allowSshKey) {
            return GIT_PASSTHROUGH;
        }

        RSAKeyGenerator key;
        const QString host = extractHostFromUrl(url);
        const bool usedSshConfig = key.loadFromSshConfigHost(host);
        if (!usedSshConfig) {
            key.loadOrGenerate();
        }

        const QByteArray publicKeyPath = key.publicKeyPath().toLocal8Bit();
        const QByteArray privateKeyPath = key.privateKeyPath().toLocal8Bit();
        const char* publicKey = publicKeyPath.isEmpty() ? nullptr : publicKeyPath.constData();
        const char* privateKey = privateKeyPath.isEmpty() ? nullptr : privateKeyPath.constData();
        const int keyResult = git_credential_ssh_key_new(out, userName, publicKey, privateKey, "");
        if (prePushPayload && keyResult == GIT_OK) {
            prePushPayload->sshKeyAttempts++;
        }
        return keyResult;
    }

    return GIT_PASSTHROUGH;
}

bool hideAdvertisedRemoteTips(git_repository* repo,
                              git_revwalk* revwalk,
                              const QString& remoteName,
                              const QString& httpsToken = QString())
{
    if (!repo || !revwalk || remoteName.isEmpty()) {
        return false;
    }

    git_remote* remote = nullptr;
    if (git_remote_lookup(&remote, repo, remoteName.toUtf8().constData()) != GIT_OK || !remote) {
        return false;
    }
    std::unique_ptr<git_remote, decltype(&git_remote_free)> remoteHolder(remote, &git_remote_free);

    const char* remoteUrlRaw = git_remote_url(remote);
    const QString remoteUrl = remoteUrlRaw ? QString::fromUtf8(remoteUrlRaw) : QString();
    git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;
    PrePushCredentialPayload credentialPayload;
    credentialPayload.httpsToken = httpsToken;
    callbacks.credentials = prePushRemoteCredentialCallback;
    callbacks.payload = &credentialPayload;
    const int connectResult = git_remote_connect(remote, GIT_DIRECTION_PUSH, &callbacks, nullptr, nullptr);
    if (connectResult != GIT_OK) {
        return false;
    }

    const git_remote_head** remoteHeads = nullptr;
    size_t remoteHeadCount = 0;
    bool listedAdvertisedTips = false;
    const int lsResult = git_remote_ls(&remoteHeads, &remoteHeadCount, remote);
    if (lsResult == GIT_OK) {
        listedAdvertisedTips = true;
        if (remoteHeads) {
            for (size_t i = 0; i < remoteHeadCount; ++i) {
                const git_remote_head* head = remoteHeads[i];
                if (!head || git_oid_is_zero(&head->oid)) {
                    continue;
                }
                git_revwalk_hide(revwalk, &head->oid);
            }
        }
    }

    git_remote_disconnect(remote);
    return listedAdvertisedTips;
}

Monad::Result<LfsPushUploadPlan> buildLfsPushUploadPlan(git_repository* repo,
                                                        const QString& refSpec,
                                                        const QString& remoteName,
                                                        const QString& httpsToken = QString())
{
    if (!repo) {
        return Monad::Result<LfsPushUploadPlan>(QStringLiteral("Failed to open repository for LFS push upload"));
    }

    const LfsPushRefSpec parsed = parsePushRefSpec(refSpec);
    if (parsed.sourceRef.isEmpty()) {
        // Delete-only pushes (e.g. :refs/heads/topic) have no source object.
        // They do not need LFS upload preflight.
        return Monad::Result<LfsPushUploadPlan>(LfsPushUploadPlan{});
    }

    const char* gitPathRaw = git_repository_path(repo);
    if (!gitPathRaw) {
        return Monad::Result<LfsPushUploadPlan>(QStringLiteral("Failed to resolve .git path for LFS upload"));
    }

    const QVector<git_oid> sourceCommitOids = resolvePushSourceCommits(repo, parsed.sourceRef);
    if (sourceCommitOids.isEmpty()) {
        if (hasRefGlobPattern(parsed.sourceRef)) {
            // Wildcard refspecs may legitimately match no local refs.
            return Monad::Result<LfsPushUploadPlan>(LfsPushUploadPlan{});
        }
        return Monad::Result<LfsPushUploadPlan>(QStringLiteral("Failed to resolve push source for LFS upload"));
    }

    git_revwalk* revwalk = nullptr;
    if (git_revwalk_new(&revwalk, repo) != GIT_OK || !revwalk) {
        return Monad::Result<LfsPushUploadPlan>(QStringLiteral("Failed to create revwalk for LFS upload"));
    }
    std::unique_ptr<git_revwalk, decltype(&git_revwalk_free)> revwalkHolder(revwalk, &git_revwalk_free);

    git_revwalk_sorting(revwalk, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);
    for (const git_oid& sourceCommitOid : sourceCommitOids) {
        if (git_revwalk_push(revwalk, &sourceCommitOid) != GIT_OK) {
            return Monad::Result<LfsPushUploadPlan>(QStringLiteral("Failed to walk pushed commits for LFS upload"));
        }
    }

    const bool listedAdvertisedTips = hideAdvertisedRemoteTips(repo, revwalk, remoteName, httpsToken);
    if (!listedAdvertisedTips) {
        // Fall back to local tracking refs only when advertised refs are unavailable.
        // Advertised refs are authoritative for push reachability and avoid stale local
        // tracking refs incorrectly hiding commits that still need LFS upload.
        hideRemoteTrackingTips(repo, revwalk, remoteName);
    }

    QHash<QString, LfsPointer> pointersByOid;
    int walkedCommitCount = 0;
    git_oid commitOid;
    while (git_revwalk_next(&commitOid, revwalk) == GIT_OK) {
        walkedCommitCount++;
        git_commit* commit = nullptr;
        if (git_commit_lookup(&commit, repo, &commitOid) != GIT_OK || !commit) {
            continue;
        }
        std::unique_ptr<git_commit, decltype(&git_commit_free)> commitHolder(commit, &git_commit_free);

        git_tree* tree = nullptr;
        if (git_commit_tree(&tree, commit) != GIT_OK || !tree) {
            continue;
        }
        std::unique_ptr<git_tree, decltype(&git_tree_free)> treeHolder(tree, &git_tree_free);

        const unsigned int parentCount = git_commit_parentcount(commit);
        if (parentCount == 0) {
            // Root commit: all tree entries are new to this history slice.
            LfsTreeCollectPayload payload{repo, &pointersByOid};
            if (git_tree_walk(tree, GIT_TREEWALK_PRE, collectLfsPointersFromTree, &payload) != GIT_OK) {
                return Monad::Result<LfsPushUploadPlan>(QStringLiteral("Failed to scan pushed tree for LFS pointers"));
            }
            continue;
        }

        git_commit* firstParentCommit = nullptr;
        if (git_commit_parent(&firstParentCommit, commit, 0) != GIT_OK || !firstParentCommit) {
            continue;
        }
        std::unique_ptr<git_commit, decltype(&git_commit_free)> firstParentCommitHolder(firstParentCommit,
                                                                                          &git_commit_free);

        git_tree* firstParentTree = nullptr;
        if (git_commit_tree(&firstParentTree, firstParentCommit) != GIT_OK || !firstParentTree) {
            continue;
        }
        std::unique_ptr<git_tree, decltype(&git_tree_free)> firstParentTreeHolder(firstParentTree,
                                                                                   &git_tree_free);

        // Merge commits may contain content already reachable from other parents that
        // is already present remotely. Restrict to first-parent diffs to plan uploads
        // only for the pushed side of history.
        collectLfsPointersFromDiff(repo, firstParentTree, tree, &pointersByOid);
    }

    LfsPushUploadPlan plan;
    plan.gitDirPath = QDir(QString::fromUtf8(gitPathRaw)).absolutePath();
    plan.pointersByOid = pointersByOid;
    plan.objects.reserve(pointersByOid.size());
    for (auto it = pointersByOid.begin(); it != pointersByOid.end(); ++it) {
        const LfsPointer pointer = it.value();
        // Defer local object existence checks until the server explicitly requests
        // an upload action for this oid. This avoids false failures when remote
        // reachability cannot be determined up-front.
        plan.objects.push_back(LfsBatchClient::ObjectSpec{pointer.oid, pointer.size});
    }

    return Monad::Result<LfsPushUploadPlan>(plan);
}

// Serial / bounded-concurrency async iteration
// --------------------------------------------
// The LFS transfer paths share one shape: drive a list of async steps, stop on the first error.
// asyncPumpBounded is the single driver (keep up to maxInFlight perItem calls in flight at once);
// asyncForEach is the window-of-one serial wrapper. `perItem` maps one item to a GitFuture
// (QFuture<Monad::ResultBase>); the returned future completes with the first item error, or with
// Monad::ResultBase() once every item finishes. perItem alone decides whether a soft failure aborts
// (return an error) or is swallowed (return success) — the driver only knows "error == abort".
//
// Lifetime: the driver owns a self-referential pump (state -> pump -> state) re-entered from each
// item's completion. On every terminal path it queues a reset that nulls the pump once the stack
// unwinds — you cannot destroy a std::function from inside its own body — breaking the cycle so the
// state frees. Every member is touched only on `context`'s thread (AsyncFuture completions are
// delivered there, queued), so no synchronization is needed. If `context` dies mid-flight the queued
// reset is dropped and the state leaks, which is acceptable: teardown is already underway.
template <typename Item, typename PerItem>
GitRepository::GitFuture asyncPumpBounded(QVector<Item> items,
                                          int maxInFlight,
                                          QObject* context,
                                          PerItem perItem)
{
    auto deferred = AsyncFuture::deferred<Monad::ResultBase>();
    deferred.reportStarted();

    if (items.isEmpty()) {
        deferred.complete(Monad::ResultBase());
        return deferred.future();
    }

    struct PumpState {
        QVector<Item> items;
        std::function<void()> pump;
        int nextIndex = 0;
        int inFlight = 0;
        bool finished = false;
    };

    auto state = std::make_shared<PumpState>();
    state->items = std::move(items);

    auto releasePump = [state, context]() {
        QMetaObject::invokeMethod(context, [state]() { state->pump = nullptr; }, Qt::QueuedConnection);
    };

    state->pump = [state, deferred, context, maxInFlight, perItem = std::move(perItem), releasePump]() mutable {
        if (state->finished) {
            return;
        }

        while (state->nextIndex < state->items.size() && state->inFlight < maxInFlight) {
            const Item& item = state->items.at(state->nextIndex);
            state->nextIndex++;
            state->inFlight++;

            auto itemFuture = perItem(item);
            AsyncFuture::observe(itemFuture)
                .context(context, [state, deferred, itemFuture, releasePump]() mutable {
                    state->inFlight--;
                    if (state->finished) {
                        return;
                    }
                    const Monad::ResultBase result = itemFuture.result();
                    if (result.hasError()) {
                        state->finished = true;
                        deferred.complete(result);
                        releasePump();
                        return;
                    }
                    state->pump();
                });
        }

        if (!state->finished && state->inFlight == 0 && state->nextIndex >= state->items.size()) {
            state->finished = true;
            deferred.complete(Monad::ResultBase());
            releasePump();
        }
    };

    state->pump();
    return deferred.future();
}

// Serial async iteration: run each item through perItem one at a time, stop on the first error,
// complete with Monad::ResultBase() if every item succeeds. A window-of-one asyncPumpBounded.
template <typename Item, typename PerItem>
GitRepository::GitFuture asyncForEach(QVector<Item> items, QObject* context, PerItem perItem)
{
    return asyncPumpBounded(std::move(items), 1, context, std::move(perItem));
}

// Upper bound on LFS object transfers kept in flight at once, shared by the upload and download
// paths. Matches git-lfs's default `lfs.concurrenttransfers`. The shared QNetworkAccessManager
// still caps live connections per host, so this is a ceiling rather than a guarantee.
constexpr int kDefaultLfsConcurrentTransfers = 8;

// Defined below; declared here so the push-upload path can chunk batches the same way the download
// path does (GitHub rejects batch requests with more than 100 objects).
QFuture<Monad::Result<QVector<LfsBatchClient::ObjectResponse>>>
runLfsBatchRequests(const QString& operation,
                    const QVector<LfsBatchClient::ObjectSpec>& specs,
                    std::shared_ptr<LfsBatchClient> client,
                    QObject* context,
                    const QString& remoteName = QString());


QString formatBytesForProgress(qint64 bytes)
{
    const double value = static_cast<double>(std::max<qint64>(0, bytes));
    constexpr double kb = 1024.0;
    constexpr double mb = 1024.0 * kb;
    constexpr double gb = 1024.0 * mb;

    if (value >= gb) {
        return QStringLiteral("%1 GB").arg(value / gb, 0, 'f', 2);
    }
    if (value >= mb) {
        return QStringLiteral("%1 MB").arg(value / mb, 0, 'f', 2);
    }
    if (value >= kb) {
        return QStringLiteral("%1 KB").arg(value / kb, 0, 'f', 1);
    }
    return QStringLiteral("%1 B").arg(static_cast<qint64>(value));
}

// `verb` is the leading present-participle ("Downloading" / "Uploading") so the same
// "<verb> LFS objects (done/total) - transferred/total" line serves both transfer directions.
QString formatLfsAggregateProgressText(const QString& verb,
                                       int completedObjects,
                                       int totalObjects,
                                       qint64 transferredBytes,
                                       qint64 totalBytes)
{
    const QString totalText = totalBytes > 0
        ? formatBytesForProgress(totalBytes)
        : QStringLiteral("?");
    return QStringLiteral("%1 LFS objects (%2/%3) - %4/%5")
        .arg(verb)
        .arg(completedObjects)
        .arg(totalObjects)
        .arg(formatBytesForProgress(transferredBytes))
        .arg(totalText);
}

// Upload-specific aggregate state shared by the per-object transfer steps: the per-oid/at-completion
// byte tallies feeding progress and an `aborted` latch that stops late streaming callbacks from
// reporting progress once a fatal error has been raised. Mirrors DownloadAggregate (minus the
// LfsStore, which uploads read from rather than write to); the bounded iteration lives in
// asyncPumpBounded.
//
// Threading invariant: every member is touched only on the context object's (main) thread — the
// transfer-completion continuations and the streaming-progress callbacks are all delivered there —
// so no synchronization is needed. Do not access these members from a worker thread.
struct UploadAggregate {
    QHash<QString, qint64> bytesByOid;
    int completed = 0;
    qint64 sentBytes = 0;
    bool aborted = false;
};

// Resolves an LFS object's upload byte size: prefer the committed pointer's size, fall back to the
// batch-response size, and finally stat the on-disk object. Shared by the progress denominator and
// the per-object pointer/completion snap so the two can't drift.
qint64 resolveLfsUploadSize(const QHash<QString, LfsPointer>& pointersByOid,
                            const QString& gitDirPath,
                            const QString& oid,
                            qint64 batchSize)
{
    const LfsPointer pointer = pointersByOid.value(oid);
    qint64 size = pointer.isValid() ? pointer.size : batchSize;
    if (size < 0) {
        size = QFileInfo(LfsStore::objectPath(gitDirPath, oid)).size();
    }
    return std::max<qint64>(0, size);
}

GitRepository::GitFuture runLfsUploadActions(const QString& gitDirPath,
                                             const QHash<QString, LfsPointer>& pointersByOid,
                                             const QVector<LfsBatchClient::ObjectResponse>& objects,
                                             std::shared_ptr<LfsBatchClient> client,
                                             QObject* context,
                                             const LfsTransferProgress& progress)
{
    struct UploadTask {
        QString oid;
        qint64 size = -1;
        LfsBatchClient::Action uploadAction;
        LfsBatchClient::Action verifyAction;
        bool hasUpload = false;
        bool hasVerify = false;
    };

    QVector<UploadTask> tasks;
    for (const auto& object : objects) {
        if (object.errorCode != 0) {
            return AsyncFuture::completed(Monad::ResultBase(
                QStringLiteral("LFS batch upload failed for oid %1: %2")
                    .arg(object.oid, object.errorMessage),
                static_cast<int>(LfsFetchErrorCode::Transfer)));
        }

        UploadTask task;
        task.oid = object.oid;
        task.size = object.size;
        if (object.actions.contains(QStringLiteral("upload"))) {
            task.hasUpload = true;
            task.uploadAction = object.actions.value(QStringLiteral("upload"));
        }
        if (object.actions.contains(QStringLiteral("verify"))) {
            task.hasVerify = true;
            task.verifyAction = object.actions.value(QStringLiteral("verify"));
        }
        if (task.hasUpload || task.hasVerify) {
            tasks.push_back(task);
        }
    }

    if (tasks.isEmpty()) {
        return AsyncFuture::completed(Monad::ResultBase());
    }

    // Only upload tasks move bytes on the wire; verify-only tasks still count toward object progress
    // but contribute no bytes to the denominator.
    qint64 totalBytesAccumulator = 0;
    for (const UploadTask& task : tasks) {
        if (task.hasUpload) {
            totalBytesAccumulator += resolveLfsUploadSize(pointersByOid, gitDirPath, task.oid, task.size);
        }
    }

    const int totalObjects = static_cast<int>(tasks.size());
    const qint64 totalBytes = totalBytesAccumulator;

    auto aggregate = std::make_shared<UploadAggregate>();

    auto reportAggregate = [progress, aggregate, totalObjects, totalBytes]() {
        if (progress) {
            progress(formatLfsAggregateProgressText(QStringLiteral("Uploading"),
                                                    aggregate->completed, totalObjects,
                                                    aggregate->sentBytes, totalBytes),
                     aggregate->completed,
                     totalObjects);
        }
    };

    // Uploads (and verifies) one object, streaming sent-byte progress into the aggregate. On success
    // the object's tally is snapped to its full size and `completed` is bumped; the first error
    // latches `aborted` (so in-flight streaming callbacks stop reporting) and propagates, which makes
    // asyncPumpBounded abort the whole push upload.
    auto perTask = [gitDirPath, pointersByOid, client, context, aggregate, reportAggregate]
        (const UploadTask& task) -> GitRepository::GitFuture {
        LfsPointer pointer = pointersByOid.value(task.oid);
        if (!pointer.isValid()) {
            pointer.oid = task.oid;
            pointer.size = resolveLfsUploadSize(pointersByOid, gitDirPath, task.oid, task.size);
        }
        if (!pointer.isValid()) {
            aggregate->aborted = true;
            return AsyncFuture::completed(
                Monad::ResultBase(QStringLiteral("Missing LFS pointer details for oid %1").arg(task.oid),
                                  static_cast<int>(LfsFetchErrorCode::Protocol)));
        }
        QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
        if (!QFileInfo::exists(objectPath)) {
            const QString workTreeRoot = QFileInfo(gitDirPath).dir().absolutePath();
            const QString hydratedPath = findWorktreeFileForLfsOid(workTreeRoot, pointer.oid);
            if (!hydratedPath.isEmpty()) {
                objectPath = hydratedPath;
            }
        }

        const QString oid = pointer.oid;
        const qint64 expectedSize = task.hasUpload ? std::max<qint64>(0, pointer.size) : 0;

        auto runVerify = [client, context, pointer, task]() -> GitRepository::GitFuture {
            if (!task.hasVerify) {
                return AsyncFuture::completed(Monad::ResultBase());
            }
            auto verifyFuture = client->verifyObject(task.verifyAction, pointer);
            return AsyncFuture::observe(verifyFuture)
                .context(context, [verifyFuture]() -> Monad::ResultBase {
                    return verifyFuture.result();
                }).future();
        };

        // Upload (streaming byte progress) then verify; a verify-only task skips straight to verify.
        // The prior error semantics hold: an upload error short-circuits verify.
        GitRepository::GitFuture transferFuture;
        if (!task.hasUpload) {
            transferFuture = runVerify();
        } else {
            auto progressCallback = [aggregate, reportAggregate, oid](qint64 sentBytes, qint64) {
                if (aggregate->aborted) {
                    return;
                }
                const qint64 prior = aggregate->bytesByOid.value(oid, 0);
                aggregate->sentBytes += (sentBytes - prior);
                aggregate->bytesByOid.insert(oid, sentBytes);
                reportAggregate();
            };

            auto uploadFuture = client->uploadObject(task.uploadAction, objectPath, pointer, progressCallback);
            transferFuture = AsyncFuture::observe(uploadFuture)
                .context(context, [uploadFuture, runVerify]() -> GitRepository::GitFuture {
                    const auto uploadResult = uploadFuture.result();
                    if (uploadResult.hasError()) {
                        qDebug() << "[LFS upload-actions] upload failed:" << uploadResult.errorMessage();
                        return AsyncFuture::completed(uploadResult);
                    }
                    return runVerify();
                }).future();
        }

        return AsyncFuture::observe(transferFuture)
            .context(context, [transferFuture, aggregate, reportAggregate, oid, expectedSize]() -> Monad::ResultBase {
                const auto result = transferFuture.result();
                if (result.hasError()) {
                    aggregate->aborted = true;
                    return result;
                }
                if (!aggregate->aborted) {
                    const qint64 prior = aggregate->bytesByOid.value(oid, 0);
                    aggregate->sentBytes += (expectedSize - prior);
                    aggregate->bytesByOid.insert(oid, expectedSize);
                    aggregate->completed++;
                    reportAggregate();
                }
                return Monad::ResultBase();
            }).future();
    };

    if (progress) {
        progress(formatLfsAggregateProgressText(QStringLiteral("Uploading"), 0, totalObjects, 0, totalBytes),
                 0, totalObjects);
    }

    return asyncPumpBounded(std::move(tasks), kDefaultLfsConcurrentTransfers, context, perTask);
}

Monad::ResultBase hydratePointerFiles(const LfsHydrationPlan& plan)
{
    QStringList hydratedPaths;
    for (const auto& item : plan.pointerFiles) {
        if (item.objectPath.isEmpty() || !QFileInfo::exists(item.objectPath)) {
            continue;
        }

        const QString targetPath = QDir(plan.workDir).filePath(item.relativePath);
        QFile current(targetPath);
        if (!current.open(QIODevice::ReadOnly)) {
            continue;
        }
        const QByteArray currentPrefix = current.read(1024);
        LfsPointer currentPointer;
        if (!LfsPointer::parse(currentPrefix, &currentPointer)
            || currentPointer.oid != item.pointer.oid
            || currentPointer.size != item.pointer.size) {
            continue;
        }
        current.close();
        const QFile::Permissions existingPermissions = QFileInfo(targetPath).permissions();

        if (QFileInfo::exists(targetPath) && !QFile::remove(targetPath)) {
            return Monad::ResultBase(QStringLiteral("Failed to replace LFS pointer file: %1").arg(item.relativePath));
        }

        if (!QFile::copy(item.objectPath, targetPath)) {
            return Monad::ResultBase(QStringLiteral("Failed to hydrate LFS file from object store: %1").arg(item.relativePath));
        }

        if (!QFile::setPermissions(targetPath, existingPermissions)) {
            return Monad::ResultBase(QStringLiteral("Failed to restore LFS file permissions: %1").arg(item.relativePath));
        }

        hydratedPaths.append(item.relativePath);
    }

    if (hydratedPaths.isEmpty()) {
        return Monad::ResultBase();
    }

    git_repository* repo = nullptr;
    if (git_repository_open(&repo, plan.workDir.toLocal8Bit().constData()) != GIT_OK || repo == nullptr) {
        return Monad::ResultBase();
    }
    std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);

    git_index* index = nullptr;
    if (git_repository_index(&index, repo) != GIT_OK || index == nullptr) {
        return Monad::ResultBase();
    }
    std::unique_ptr<git_index, decltype(&git_index_free)> indexHolder(index, &git_index_free);

    for (const QString& relativePath : hydratedPaths) {
        const QByteArray pathUtf8 = relativePath.toUtf8();
        const git_index_entry* existing = git_index_get_bypath(index, pathUtf8.constData(), 0);
        if (existing == nullptr) {
            continue;
        }

        const git_oid originalId = existing->id;
        if (git_index_add_bypath(index, pathUtf8.constData()) != GIT_OK) {
            continue;
        }

        const git_index_entry* refreshed = git_index_get_bypath(index, pathUtf8.constData(), 0);
        if (refreshed == nullptr) {
            continue;
        }

        git_index_entry updated = *refreshed;
        updated.id = originalId;
        git_index_add(index, &updated);
    }

    if (git_index_write(index) != GIT_OK) {
        return Monad::ResultBase(QStringLiteral("Failed to write hydrated LFS index state"));
    }

    return Monad::ResultBase();
}

struct LfsDownloadTask {
    LfsPointer pointer;
    QString relativePath;
    LfsBatchClient::Action action;
    bool hasError = false;
    QString errorMessage;
    int errorCode = 0;
};

// Download-specific aggregate state shared by the per-object transfer steps: the object store the
// transfers write into, the per-oid/at-completion byte tallies feeding progress, and an `aborted`
// latch that stops late streaming callbacks from reporting progress once a fatal error has been
// raised. The serial/parallel iteration itself lives in asyncPumpBounded.
//
// Threading invariant: every member is touched only on the context object's (main) thread — the
// transfer-completion continuations and the streaming-progress callbacks are all delivered there
// (AsyncFuture completions are queued; QNetworkReply signals fire on the manager's thread) — so no
// synchronization is needed. Do not access these members from a worker thread.
struct DownloadAggregate {
    explicit DownloadAggregate(const QString& gitDirPath)
        : store(gitDirPath, LfsPolicy())
    {
    }

    LfsStore store;
    QHash<QString, qint64> bytesByOid;
    int completed = 0;
    qint64 receivedBytes = 0;
    bool aborted = false;
};

// Drives the per-object downloads from a single batch response. The batch request is made once by
// the caller; here we resolve each object's download action and stream up to
// kDefaultLfsConcurrentTransfers of them in parallel, reporting aggregate byte progress across all
// objects. Error semantics match the prior serial fetch: the first fatal error aborts the whole
// hydration, while fallback-eligible errors (offline / no-remote) leave the affected pointer file
// in place and let the remaining transfers finish.
GitRepository::GitFuture runLfsDownloadActions(const LfsHydrationPlan& plan,
                                               const QVector<LfsBatchClient::ObjectResponse>& objects,
                                               std::shared_ptr<LfsBatchClient> client,
                                               QObject* context,
                                               const LfsTransferProgress& progress)
{
    QHash<QString, LfsBatchClient::ObjectResponse> responsesByOid;
    for (const auto& object : objects) {
        responsesByOid.insert(object.oid, object);
    }

    // First pointer file wins for a given oid (the same content can appear under several paths),
    // matching the prior linear first-match scan.
    QHash<QString, QString> relativePathByOid;
    for (const auto& item : plan.pointerFiles) {
        if (!relativePathByOid.contains(item.pointer.oid)) {
            relativePathByOid.insert(item.pointer.oid, item.relativePath);
        }
    }

    QVector<LfsDownloadTask> tasks;
    tasks.reserve(plan.missingPointers.size());
    qint64 totalBytesAccumulator = 0;
    for (const LfsPointer& pointer : plan.missingPointers) {
        LfsDownloadTask task;
        task.pointer = pointer;
        task.relativePath = relativePathByOid.value(pointer.oid, pointer.oid);

        if (!responsesByOid.contains(pointer.oid)) {
            task.hasError = true;
            task.errorMessage = QStringLiteral("Missing LFS batch response for oid %1").arg(pointer.oid);
            task.errorCode = static_cast<int>(LfsFetchErrorCode::Protocol);
        } else {
            const auto& response = responsesByOid.value(pointer.oid);
            if (!response.errorMessage.isEmpty()) {
                task.hasError = true;
                task.errorMessage = response.errorMessage;
                task.errorCode = response.errorCode == 404
                    ? static_cast<int>(LfsFetchErrorCode::NotFound)
                    : static_cast<int>(LfsFetchErrorCode::Transfer);
            } else if (!response.actions.contains(QStringLiteral("download"))) {
                task.hasError = true;
                task.errorMessage = QStringLiteral("Missing LFS download action");
                task.errorCode = static_cast<int>(LfsFetchErrorCode::Protocol);
            } else {
                task.action = response.actions.value(QStringLiteral("download"));
            }
        }
        totalBytesAccumulator += std::max<qint64>(0, pointer.size);
        tasks.push_back(task);
    }

    const int totalObjects = static_cast<int>(tasks.size());
    const qint64 totalBytes = totalBytesAccumulator;

    auto aggregate = std::make_shared<DownloadAggregate>(plan.gitDirPath);

    auto reportAggregate = [progress, aggregate, totalObjects, totalBytes]() {
        if (progress) {
            progress(formatLfsAggregateProgressText(QStringLiteral("Downloading"),
                                                    aggregate->completed, totalObjects,
                                                    aggregate->receivedBytes, totalBytes),
                     aggregate->completed,
                     totalObjects);
        }
    };

    // Resolves and streams one object. A fatal error is returned (asyncPumpBounded aborts the whole
    // hydration on it) and latches `aborted` so in-flight transfers stop reporting progress; a
    // fallback-eligible error (offline / no-remote) is swallowed as success so the affected pointer
    // file is left in place and the remaining transfers finish.
    auto perObject = [aggregate, client, context, reportAggregate](const LfsDownloadTask& task)
        -> GitRepository::GitFuture {
        if (task.hasError) {
            if (!LfsStore::shouldFallbackForFetchError(task.errorCode)) {
                aggregate->aborted = true;
                return AsyncFuture::completed(Monad::ResultBase(task.errorMessage, task.errorCode));
            }
            aggregate->completed++;
            reportAggregate();
            return AsyncFuture::completed(Monad::ResultBase());
        }

        const QString oid = task.pointer.oid;
        const qint64 objectSize = std::max<qint64>(0, task.pointer.size);

        auto downloadFuture = client->downloadObject(
            task.action,
            aggregate->store,
            task.pointer,
            [aggregate, reportAggregate, oid](qint64 downloadedBytes, qint64) {
                if (aggregate->aborted) {
                    return;
                }
                const qint64 prior = aggregate->bytesByOid.value(oid, 0);
                aggregate->receivedBytes += (downloadedBytes - prior);
                aggregate->bytesByOid.insert(oid, downloadedBytes);
                reportAggregate();
            });

        return AsyncFuture::observe(downloadFuture)
            .context(context, [aggregate, downloadFuture, reportAggregate, oid, objectSize]() -> Monad::ResultBase {
                if (aggregate->aborted) {
                    return Monad::ResultBase();
                }
                const auto result = downloadFuture.result();
                if (result.hasError() && !LfsStore::shouldFallbackForFetchError(result.errorCode())) {
                    aggregate->aborted = true;
                    return Monad::ResultBase(result.errorMessage(), result.errorCode());
                }
                if (!result.hasError()) {
                    const qint64 prior = aggregate->bytesByOid.value(oid, 0);
                    aggregate->receivedBytes += (objectSize - prior);
                    aggregate->bytesByOid.insert(oid, objectSize);
                }
                aggregate->completed++;
                reportAggregate();
                return Monad::ResultBase();
            }).future();
    };

    if (progress) {
        progress(formatLfsAggregateProgressText(QStringLiteral("Downloading"), 0, totalObjects, 0, totalBytes),
                 0, totalObjects);
    }

    auto transfersFuture = asyncPumpBounded(std::move(tasks), kDefaultLfsConcurrentTransfers, context, perObject);
    return AsyncFuture::observe(transfersFuture)
        .context(context, [transfersFuture, plan, progress]() -> GitRepository::GitFuture {
            const Monad::ResultBase result = transfersFuture.result();
            if (result.hasError()) {
                return AsyncFuture::completed(result);
            }
            if (progress) {
                const int pointerFileCount = static_cast<int>(plan.pointerFiles.size());
                progress(QStringLiteral("Hydrating LFS files"), pointerFileCount, pointerFileCount);
            }
            return AsyncFuture::completed(hydratePointerFiles(plan));
        }).future();
}

// Conservative per-request object cap across hosts. GitHub enforces 100 and rejects anything larger
// with HTTP 413 "More than 100 objects specified"; GitLab/Bitbucket allow more (or document no cap),
// so chunking at 100 is always valid, just more round trips on those hosts. Split the objects across
// as many batch requests as needed and accumulate the per-object responses.
constexpr int kMaxObjectsPerBatchRequest = 100;

// Issues one or more batch requests (chunked to kMaxObjectsPerBatchRequest) for the given specs and
// accumulates every object response. Chunks run serially; the first failing chunk aborts and
// reports its error (the caller decides fallback vs. propagate). Never captures `this`.
QFuture<Monad::Result<QVector<LfsBatchClient::ObjectResponse>>>
runLfsBatchRequests(const QString& operation,
                    const QVector<LfsBatchClient::ObjectSpec>& specs,
                    std::shared_ptr<LfsBatchClient> client,
                    QObject* context,
                    const QString& remoteName)
{
    using BatchObjects = QVector<LfsBatchClient::ObjectResponse>;

    // Split the specs into <=kMaxObjectsPerBatchRequest chunks, then drive them serially.
    QVector<QVector<LfsBatchClient::ObjectSpec>> chunks;
    for (int begin = 0; begin < specs.size(); begin += kMaxObjectsPerBatchRequest) {
        const int count = std::min(kMaxObjectsPerBatchRequest, static_cast<int>(specs.size()) - begin);
        QVector<LfsBatchClient::ObjectSpec> chunk;
        chunk.reserve(count);
        for (int i = begin; i < begin + count; ++i) {
            chunk.push_back(specs.at(i));
        }
        chunks.push_back(std::move(chunk));
    }

    auto objects = std::make_shared<BatchObjects>();

    auto perChunk = [objects, operation, remoteName, client, context](
        const QVector<LfsBatchClient::ObjectSpec>& chunk) -> GitRepository::GitFuture {
        auto batchFuture = client->batch(operation, chunk, remoteName);
        return AsyncFuture::observe(batchFuture)
            .context(context, [objects, batchFuture]() -> Monad::ResultBase {
                const auto batchResult = batchFuture.result();
                if (batchResult.hasError()) {
                    return Monad::ResultBase(batchResult.errorMessage(), batchResult.errorCode());
                }
                objects->append(batchResult.value().objects);
                return Monad::ResultBase();
            }).future();
    };

    auto chunksFuture = asyncForEach(std::move(chunks), context, perChunk);
    return AsyncFuture::observe(chunksFuture)
        .context(context, [chunksFuture, objects]() -> Monad::Result<BatchObjects> {
            const Monad::ResultBase result = chunksFuture.result();
            if (result.hasError()) {
                return Monad::Result<BatchObjects>(result.errorMessage(), result.errorCode());
            }
            return Monad::Result<BatchObjects>(*objects);
        }).future();
}

} // anonymous namespace

GitRepository::GitFuture runLfsPrePushUpload(const QByteArray& repoPath,
                                             const QString& refSpec,
                                             const QString& remoteName,
                                             QObject* context,
                                             const QString& httpsToken,
                                             const LfsTransferProgress& progress)
{
    auto planFuture = QtConcurrent::run([repoPath, refSpec, remoteName, httpsToken]() {
        return mtry([repoPath, refSpec, remoteName, httpsToken]() -> Monad::Result<LfsPushUploadPlan> {
            git_repository* repo = nullptr;
            const int openResult = git_repository_open(&repo, repoPath.constData());
            if (openResult != GIT_OK || !repo) {
                const git_error* err = git_error_last();
                const QString message = (err && err->message)
                    ? QString::fromUtf8(err->message)
                    : QStringLiteral("Failed to open repository for LFS push upload");
                return Monad::Result<LfsPushUploadPlan>(message, openResult);
            }
            std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);
            return buildLfsPushUploadPlan(repo, refSpec, remoteName, httpsToken);
        });
    });

    return AsyncFuture::observe(planFuture)
        .context(context, [planFuture, remoteName, context, progress]() -> GitRepository::GitFuture {
            const auto planResult = planFuture.result();
            if (planResult.hasError()) {
                qDebug() << "[LFS pre-push] plan error:" << planResult.errorMessage();
                return AsyncFuture::completed(Monad::ResultBase(planResult.errorMessage(), planResult.errorCode()));
            }

            const auto plan = planResult.value();
            if (plan.objects.isEmpty()) {
                return AsyncFuture::completed(Monad::ResultBase());
            }

            auto client = std::make_shared<LfsBatchClient>(plan.gitDirPath);
            auto batchFuture = runLfsBatchRequests(QStringLiteral("upload"), plan.objects, client, context, remoteName);
            return AsyncFuture::observe(batchFuture)
                .context(context, [batchFuture, plan, client, context, progress]() -> GitRepository::GitFuture {
                    const auto batchResult = batchFuture.result();
                    if (batchResult.hasError()) {
                        return AsyncFuture::completed(Monad::ResultBase(batchResult.errorMessage(), batchResult.errorCode()));
                    }

                    return runLfsUploadActions(plan.gitDirPath,
                                               plan.pointersByOid,
                                               batchResult.value(),
                                               client,
                                               context,
                                               progress);
                }).future();
        }).future();
}

Monad::Result<LfsHydrationPlan> buildLfsHydrationPlan(git_repository* repo)
{
    if (!repo) {
        return Monad::Result<LfsHydrationPlan>(LfsHydrationPlan{});
    }

    const char* workDirRaw = git_repository_workdir(repo);
    const char* gitDirRaw = git_repository_path(repo);
    if (!workDirRaw || !gitDirRaw) {
        return Monad::Result<LfsHydrationPlan>(LfsHydrationPlan{});
    }

    LfsHydrationPlan plan;
    plan.workDir = QString::fromUtf8(workDirRaw);
    plan.gitDirPath = QDir(QString::fromUtf8(gitDirRaw)).absolutePath();

    const QDir workDir(plan.workDir);
    if (!workDir.exists()) {
        return Monad::Result<LfsHydrationPlan>(plan);
    }

    QSet<QString> pendingOids;
    QSet<QString> plannedPaths;
    auto addPointerCandidate = [&](const QString& relativePath, const LfsPointer& pointer) {
        if (relativePath.isEmpty()
            || relativePath == QStringLiteral(".git")
            || relativePath.startsWith(QStringLiteral(".git/"))
            || plannedPaths.contains(relativePath)) {
            return;
        }

        const QString absolutePath = workDir.filePath(relativePath);
        const QFileInfo fileInfo(absolutePath);
        if (!fileInfo.exists() || !fileInfo.isFile()) {
            return;
        }

        const QString objectPath = LfsStore::objectPath(plan.gitDirPath, pointer.oid);
        plan.pointerFiles.push_back(PointerWorkItem{relativePath, objectPath, pointer});
        plannedPaths.insert(relativePath);
        if (objectPath.isEmpty() || QFileInfo::exists(objectPath) || pendingOids.contains(pointer.oid)) {
            return;
        }

        pendingOids.insert(pointer.oid);
        plan.missingPointers.push_back(pointer);
    };

    QDirIterator it(plan.workDir,
                    QDir::Files | QDir::NoSymLinks,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        const QFileInfo info = it.fileInfo();
        const QString relativePath = QDir::fromNativeSeparators(
            workDir.relativeFilePath(info.absoluteFilePath()));
        if (relativePath.isEmpty()
            || relativePath == QStringLiteral(".git")
            || relativePath.startsWith(QStringLiteral(".git/"))) {
            continue;
        }

        QFile file(info.absoluteFilePath());
        if (!file.open(QIODevice::ReadOnly)) {
            continue;
        }
        const QByteArray prefix = file.read(1024);
        if (prefix.isEmpty()) {
            continue;
        }

        LfsPointer pointer;
        if (!LfsPointer::parse(prefix, &pointer)) {
            continue;
        }
        addPointerCandidate(relativePath, pointer);
    }

    git_index* index = nullptr;
    if (git_repository_index(&index, repo) == GIT_OK && index != nullptr) {
        std::unique_ptr<git_index, decltype(&git_index_free)> indexHolder(index, &git_index_free);
        const size_t entryCount = git_index_entrycount(index);
        for (size_t i = 0; i < entryCount; ++i) {
            const git_index_entry* entry = git_index_get_byindex(index, i);
            if (entry == nullptr || entry->path == nullptr || git_oid_is_zero(&entry->id)) {
                continue;
            }

            QByteArray content = blobContent(repo, &entry->id);
            if (content.isEmpty()) {
                continue;
            }

            LfsPointer pointer;
            if (!LfsPointer::parse(content, &pointer)) {
                continue;
            }

            addPointerCandidate(QString::fromUtf8(entry->path), pointer);
        }
    }

    return Monad::Result<LfsHydrationPlan>(plan);
}

GitRepository::GitFuture runLfsHydrationPipeline(const LfsHydrationPlan& plan,
                                                 QObject* context,
                                                 const LfsTransferProgress& progress)
{
    if (plan.pointerFiles.isEmpty()) {
        return AsyncFuture::completed(Monad::ResultBase());
    }

    const int pointerFileCount = static_cast<int>(plan.pointerFiles.size());
    if (progress) {
        progress(QStringLiteral("Hydrating LFS files"), 0, std::max(1, pointerFileCount));
    }

    if (plan.missingPointers.isEmpty()) {
        if (progress) {
            progress(QStringLiteral("Hydrating LFS files"), pointerFileCount, pointerFileCount);
        }
        return AsyncFuture::completed(hydratePointerFiles(plan));
    }

    // Resolve download actions for every missing object in as few batch requests as the 100-object
    // cap allows, instead of a separate batch round trip per object.
    QVector<LfsBatchClient::ObjectSpec> specs;
    specs.reserve(plan.missingPointers.size());
    for (const LfsPointer& pointer : plan.missingPointers) {
        specs.push_back(LfsBatchClient::ObjectSpec{pointer.oid, pointer.size});
    }

    auto client = std::make_shared<LfsBatchClient>(plan.gitDirPath);
    auto batchFuture = runLfsBatchRequests(QStringLiteral("download"), specs, client, context);
    return AsyncFuture::observe(batchFuture)
        .context(context, [batchFuture, plan, client, context, progress]() -> GitRepository::GitFuture {
            const auto batchResult = batchFuture.result();
            if (batchResult.hasError()) {
                // Offline / no-remote clones still succeed by leaving the pointer files in place.
                if (LfsStore::shouldFallbackForFetchError(batchResult.errorCode())) {
                    return AsyncFuture::completed(hydratePointerFiles(plan));
                }
                return AsyncFuture::completed(Monad::ResultBase(batchResult.errorMessage(), batchResult.errorCode()));
            }

            return runLfsDownloadActions(plan, batchResult.value(), client, context, progress);
        }).future();
}

QFuture<Monad::Result<LfsHydrationPlan>> prepareLfsHydrationPlan(const QDir& repositoryDir)
{
    const QByteArray path = repositoryDir.absolutePath().toLocal8Bit();
    return QtConcurrent::run([path]() {
        return mtry([path]() -> Monad::Result<LfsHydrationPlan> {
            git_repository* repo = nullptr;
            const int openResult = git_repository_open(&repo, path.constData());
            if (openResult != GIT_OK || !repo) {
                const git_error* err = git_error_last();
                const QString message = (err && err->message)
                    ? QString::fromUtf8(err->message)
                    : QStringLiteral("Failed to open repository for LFS hydration");
                return Monad::Result<LfsHydrationPlan>(message, openResult);
            }
            std::unique_ptr<git_repository, decltype(&git_repository_free)> repoHolder(repo, &git_repository_free);
            return buildLfsHydrationPlan(repo);
        });
    });
}

GitRepository::GitFuture runLfsHydrationForDirectory(const QDir& repositoryDir,
                                                     QObject* context,
                                                     const LfsTransferProgress& progress)
{
    auto prepareFuture = prepareLfsHydrationPlan(repositoryDir);
    return AsyncFuture::observe(prepareFuture)
        .context(context, [prepareFuture, context, progress]() -> GitRepository::GitFuture {
            const auto prepareResult = prepareFuture.result();
            if (prepareResult.hasError()) {
                return AsyncFuture::completed(Monad::ResultBase(prepareResult.errorMessage(),
                                                                prepareResult.errorCode()));
            }
            return runLfsHydrationPipeline(prepareResult.value(), context, progress);
        }).future();
}

GitRepository::MergeFuture runMergeHydrationForDirectory(const Monad::Result<GitRepository::MergeResult>& mergeResult,
                                                         const QDir& repositoryDir,
                                                         QObject* context,
                                                         const LfsTransferProgress& progress)
{
    if (mergeResult.hasError()) {
        return AsyncFuture::completed(mergeResult);
    }

    const auto state = mergeResult.value().state();
    const bool shouldHydrate = state == GitRepository::MergeResult::FastForward
                               || state == GitRepository::MergeResult::MergeCommitCreated
                               || state == GitRepository::MergeResult::Rebased;
    if (!shouldHydrate) {
        return AsyncFuture::completed(mergeResult);
    }

    auto hydrateFuture = runLfsHydrationForDirectory(repositoryDir, context, progress);
    return AsyncFuture::observe(hydrateFuture)
        .context(context, [hydrateFuture, mergeResult]() -> Monad::Result<GitRepository::MergeResult> {
            const auto hydrateResult = hydrateFuture.result();
            if (hydrateResult.hasError()) {
                return Monad::Result<GitRepository::MergeResult>(hydrateResult.errorMessage(),
                                                                 hydrateResult.errorCode());
            }
            return mergeResult;
        }).future();
}

} // namespace LfsHydrator
} // namespace QQuickGit
