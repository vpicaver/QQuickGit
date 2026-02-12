//Std includes
#include <stdexcept>
#include <array>
#include <algorithm>

//Our includes
#include "GitRepository.h"
#include "RSAKeyGenerator.h"
#include "Account.h"
#include "LfsFilter.h"
#include "LfsPolicy.h"
#include "LfsBatchClient.h"
#include "LfsStore.h"
#include "Monad/Result.h"
#include "ProgressState.h"
#include "Monad/Monad.h"

//LibGit2 includes
#include "git2.h"
#include <git2/index.h>
#include <libssh2.h>

//Qt includes
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QPointer>
#include <QSet>
#include <QtConcurrent>
#include <QUuid>
#include <QHash>

//Async includes
#include "asyncfuture.h"

using namespace Monad;
using namespace QQuickGit;

namespace {
QString extractHostFromUrl(const char *url)
{
    if(url == nullptr) {
        return QString();
    }

    QString urlText = QString::fromUtf8(url);
    if(urlText.contains("://")) {
        QUrl parsed(urlText);
        return parsed.host();
    }

    // scp-like: user@host:path
    auto atIndex = urlText.indexOf('@');
    if(atIndex >= 0) {
        auto hostStart = atIndex + 1;
        auto hostEnd = urlText.indexOf(':', hostStart);
        if(hostEnd == -1) {
            hostEnd = urlText.indexOf('/', hostStart);
        }
        if(hostEnd == -1) {
            hostEnd = urlText.size();
        }
        return urlText.mid(hostStart, hostEnd - hostStart);
    }

    return QString();
}

QString gitErrorMessageWithPrefix(const QString& prefix)
{
    const git_error* lastError = git_error_last();
    if (lastError && lastError->message) {
        return QStringLiteral("%1: %2").arg(prefix, QString::fromUtf8(lastError->message));
    }
    return prefix;
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

struct SshCallbackPayload {
    QFutureInterface<ResultBase>* progressInterface = nullptr;
    int agentMaxAttempts = 1;
    int agentAttempts = 0;
    bool allowAgent = true;
};

struct PrePushCredentialPayload {
    int totalMaxAttempts = 8;
    int totalAttempts = 0;
    int sshAgentMaxAttempts = 1;
    int sshAgentAttempts = 0;
    int sshKeyMaxAttempts = 1;
    int sshKeyAttempts = 0;
};

QFutureInterface<ResultBase>* progressFromPayload(void* payload)
{
    auto typed = reinterpret_cast<SshCallbackPayload*>(payload);
    if(!typed) {
        return nullptr;
    }
    return typed->progressInterface;
}

struct PointerWorkItem {
    QString relativePath;
    QString objectPath;
    LfsPointer pointer;
};

struct LfsHydrationPlan {
    QString workDir;
    QString gitDirPath;
    QVector<PointerWorkItem> pointerFiles;
    QVector<LfsPointer> missingPointers;
};

struct LfsPushUploadPlan {
    QString gitDirPath;
    QVector<LfsBatchClient::ObjectSpec> objects;
    QHash<QString, LfsPointer> pointersByOid;
};

struct LfsPushRefSpec {
    QString sourceRef;
    QString destinationRef;
};

struct LfsTreeCollectPayload {
    git_repository* repo = nullptr;
    QHash<QString, LfsPointer>* pointersByOid = nullptr;
};

LfsPushRefSpec parsePushRefSpec(QString refSpec)
{
    if (refSpec.startsWith(QLatin1Char('+'))) {
        refSpec.remove(0, 1);
    }

    const int colonIndex = refSpec.indexOf(QLatin1Char(':'));
    if (colonIndex >= 0) {
        return LfsPushRefSpec{refSpec.left(colonIndex), refSpec.mid(colonIndex + 1)};
    }
    return LfsPushRefSpec{refSpec, QString()};
}

bool hasRefGlobPattern(const QString& ref)
{
    return ref.contains(QLatin1Char('*'))
        || ref.contains(QLatin1Char('?'))
        || ref.contains(QLatin1Char('['));
}

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

    git_blob* blob = nullptr;
    if (git_blob_lookup(&blob, state->repo, git_tree_entry_id(entry)) != GIT_OK || !blob) {
        return 0;
    }
    std::unique_ptr<git_blob, decltype(&git_blob_free)> blobHolder(blob, &git_blob_free);

    const char* raw = static_cast<const char*>(git_blob_rawcontent(blob));
    const size_t rawSize = git_blob_rawsize(blob);
    if (!raw || rawSize == 0 || rawSize > 4096) {
        return 0;
    }

    LfsPointer pointer;
    if (!LfsPointer::parse(QByteArray(raw, static_cast<int>(rawSize)), &pointer)) {
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

    git_blob* blob = nullptr;
    if (git_blob_lookup(&blob, repo, blobOid) != GIT_OK || !blob) {
        return;
    }
    std::unique_ptr<git_blob, decltype(&git_blob_free)> blobHolder(blob, &git_blob_free);

    const char* raw = static_cast<const char*>(git_blob_rawcontent(blob));
    const size_t rawSize = git_blob_rawsize(blob);
    if (!raw || rawSize == 0 || rawSize > 4096) {
        return;
    }

    LfsPointer pointer;
    if (!LfsPointer::parse(QByteArray(raw, static_cast<int>(rawSize)), &pointer)) {
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
                              const QString& remoteName)
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
                                                        const QString& remoteName)
{
    qDebug() << "[LFS push-plan] begin" << "refSpec=" << refSpec << "remote=" << remoteName;
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
    qDebug() << "[LFS push-plan] source commits:" << sourceCommitOids.size()
             << "sourceRef=" << parsed.sourceRef;
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

    const bool listedAdvertisedTips = hideAdvertisedRemoteTips(repo, revwalk, remoteName);
    qDebug() << "[LFS push-plan] listed advertised tips:" << listedAdvertisedTips;
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

    qDebug() << "[LFS push-plan] walked commits:" << walkedCommitCount
             << "pointer oids:" << pointersByOid.size()
             << "batch objects:" << plan.objects.size();

    return Monad::Result<LfsPushUploadPlan>(plan);
}

GitRepository::GitFuture runLfsUploadActions(const QString& gitDirPath,
                                             const QHash<QString, LfsPointer>& pointersByOid,
                                             const QVector<LfsBatchClient::ObjectResponse>& objects,
                                             std::shared_ptr<LfsBatchClient> client,
                                             QObject* context)
{
    qDebug() << "[LFS upload-actions] start"
             << "gitDirPath=" << gitDirPath
             << "pointerDetails=" << pointersByOid.size()
             << "batchObjects=" << objects.size();
    struct UploadTask {
        QString oid;
        LfsBatchClient::Action uploadAction;
        LfsBatchClient::Action verifyAction;
        bool hasUpload = false;
        bool hasVerify = false;
    };

    QVector<UploadTask> tasks;
    for (const auto& object : objects) {
        qDebug() << "[LFS upload-actions] object"
                 << "oid=" << object.oid
                 << "errCode=" << object.errorCode
                 << "hasUpload=" << object.actions.contains(QStringLiteral("upload"))
                 << "hasVerify=" << object.actions.contains(QStringLiteral("verify"));
        if (object.errorCode != 0) {
            return AsyncFuture::completed(Monad::ResultBase(
                QStringLiteral("LFS batch upload failed for oid %1: %2")
                    .arg(object.oid, object.errorMessage),
                static_cast<int>(LfsFetchErrorCode::Transfer)));
        }

        UploadTask task;
        task.oid = object.oid;
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
        qDebug() << "[LFS upload-actions] no upload/verify tasks returned by server";
        return AsyncFuture::completed(Monad::ResultBase());
    }

    auto deferred = AsyncFuture::deferred<Monad::ResultBase>();
    deferred.reportStarted();

    auto taskList = std::make_shared<QVector<UploadTask>>(std::move(tasks));
    auto nextIndex = std::make_shared<int>(0);
    auto step = std::make_shared<std::function<void()>>();

    *step = [deferred, context, client, gitDirPath, pointersByOid, taskList, nextIndex, step]() mutable {
        if (*nextIndex >= taskList->size()) {
            deferred.complete(Monad::ResultBase());
            return;
        }

        const UploadTask task = taskList->at(*nextIndex);
        (*nextIndex)++;
        qDebug() << "[LFS upload-actions] running task"
                 << "oid=" << task.oid
                 << "upload=" << task.hasUpload
                 << "verify=" << task.hasVerify;

        if (!pointersByOid.contains(task.oid)) {
            deferred.complete(Monad::ResultBase(QStringLiteral("Missing LFS pointer details for oid %1").arg(task.oid),
                                                static_cast<int>(LfsFetchErrorCode::Protocol)));
            return;
        }
        const LfsPointer pointer = pointersByOid.value(task.oid);
        const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);

        auto runVerify = [deferred, context, client, pointer, task, step]() mutable {
            if (!task.hasVerify) {
                (*step)();
                return;
            }
            auto verifyFuture = client->verifyObject(task.verifyAction, pointer);
            AsyncFuture::observe(verifyFuture)
                .context(context, [deferred, step, verifyFuture]() mutable {
                    const auto verifyResult = verifyFuture.result();
                    if (verifyResult.hasError()) {
                        deferred.complete(verifyResult);
                        return;
                    }
                    (*step)();
                });
        };

        if (!task.hasUpload) {
            runVerify();
            return;
        }

        auto uploadFuture = client->uploadObject(task.uploadAction, objectPath, pointer);
        AsyncFuture::observe(uploadFuture)
            .context(context, [deferred, uploadFuture, runVerify]() mutable {
                const auto uploadResult = uploadFuture.result();
                if (uploadResult.hasError()) {
                    qDebug() << "[LFS upload-actions] upload failed:" << uploadResult.errorMessage();
                    deferred.complete(uploadResult);
                    return;
                }
                qDebug() << "[LFS upload-actions] upload succeeded";
                runVerify();
            });
    };

    (*step)();
    return deferred.future();
}

GitRepository::GitFuture runLfsPrePushUpload(const QByteArray& repoPath,
                                             const QString& refSpec,
                                             const QString& remoteName,
                                             QObject* context)
{
    qDebug() << "[LFS pre-push] begin"
             << "repoPath=" << repoPath
             << "refSpec=" << refSpec
             << "remote=" << remoteName;
    auto planFuture = QtConcurrent::run([repoPath, refSpec, remoteName]() {
        return mtry([repoPath, refSpec, remoteName]() -> Monad::Result<LfsPushUploadPlan> {
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
            return buildLfsPushUploadPlan(repo, refSpec, remoteName);
        });
    });

    return AsyncFuture::observe(planFuture)
        .context(context, [planFuture, remoteName, context]() -> GitRepository::GitFuture {
            const auto planResult = planFuture.result();
            if (planResult.hasError()) {
                qDebug() << "[LFS pre-push] plan error:" << planResult.errorMessage();
                return AsyncFuture::completed(Monad::ResultBase(planResult.errorMessage(), planResult.errorCode()));
            }

            const auto plan = planResult.value();
            qDebug() << "[LFS pre-push] plan ready"
                     << "gitDirPath=" << plan.gitDirPath
                     << "objects=" << plan.objects.size();
            if (plan.objects.isEmpty()) {
                return AsyncFuture::completed(Monad::ResultBase());
            }

            auto client = std::make_shared<LfsBatchClient>(plan.gitDirPath);
            auto batchFuture = client->batch(QStringLiteral("upload"), plan.objects, remoteName);
            return AsyncFuture::observe(batchFuture)
                .context(context, [batchFuture, plan, client, context]() -> GitRepository::GitFuture {
                    const auto batchResult = batchFuture.result();
                    if (batchResult.hasError()) {
                        qDebug() << "[LFS pre-push] batch error:" << batchResult.errorMessage();
                        return AsyncFuture::completed(Monad::ResultBase(batchResult.errorMessage(), batchResult.errorCode()));
                    }

                    qDebug() << "[LFS pre-push] batch success"
                             << "response objects=" << batchResult.value().objects.size();

                    return runLfsUploadActions(plan.gitDirPath,
                                               plan.pointersByOid,
                                               batchResult.value().objects,
                                               client,
                                               context);
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

    git_index* index = nullptr;
    if (git_repository_index(&index, repo) != GIT_OK || !index) {
        return Monad::Result<LfsHydrationPlan>(QStringLiteral("Failed to read git index"));
    }
    std::unique_ptr<git_index, decltype(&git_index_free)> indexHolder(index, &git_index_free);

    LfsHydrationPlan plan;
    plan.workDir = QString::fromUtf8(workDirRaw);
    plan.gitDirPath = QDir(QString::fromUtf8(gitDirRaw)).absolutePath();
    QSet<QString> pendingOids;
    const size_t entryCount = git_index_entrycount(index);
    for (size_t i = 0; i < entryCount; ++i) {
        const git_index_entry* entry = git_index_get_byindex(index, i);
        if (!entry || !entry->path) {
            continue;
        }

        const QString relativePath = QString::fromUtf8(entry->path);
        QFile file(QDir(plan.workDir).filePath(relativePath));
        if (!file.open(QIODevice::ReadOnly)) {
            continue;
        }

        const QByteArray prefix = file.read(1024);
        LfsPointer pointer;
        if (!LfsPointer::parse(prefix, &pointer)) {
            continue;
        }
        const QString objectPath = LfsStore::objectPath(plan.gitDirPath, pointer.oid);
        plan.pointerFiles.push_back(PointerWorkItem{relativePath, objectPath, pointer});
        if (objectPath.isEmpty() || QFileInfo::exists(objectPath) || pendingOids.contains(pointer.oid)) {
            continue;
        }

        pendingOids.insert(pointer.oid);
        plan.missingPointers.push_back(pointer);
    }

    return Monad::Result<LfsHydrationPlan>(plan);
}

Monad::ResultBase hydratePointerFiles(const LfsHydrationPlan& plan)
{
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
    }

    return Monad::ResultBase();
}

GitRepository::GitFuture runLfsHydrationPipeline(const LfsHydrationPlan& plan, QObject* context)
{
    if (plan.pointerFiles.isEmpty()) {
        return AsyncFuture::completed(Monad::ResultBase());
    }

    auto store = std::make_shared<LfsStore>(plan.gitDirPath, LfsPolicy());
    if (plan.missingPointers.isEmpty()) {
        return AsyncFuture::completed(hydratePointerFiles(plan));
    }

    auto deferred = AsyncFuture::deferred<Monad::ResultBase>();
    deferred.reportStarted();

    auto pointers = std::make_shared<QVector<LfsPointer>>(plan.missingPointers);
    auto nextIndex = std::make_shared<int>(0);
    auto step = std::make_shared<std::function<void()>>();

    *step = [deferred, context, store, plan, pointers, nextIndex, step]() mutable {
        if (*nextIndex >= pointers->size()) {
            deferred.complete(hydratePointerFiles(plan));
            return;
        }

        const LfsPointer pointer = pointers->at(*nextIndex);
        (*nextIndex)++;
        auto fetchFuture = store->fetchObject(pointer);
        AsyncFuture::observe(fetchFuture)
            .context(context, [deferred, step, fetchFuture]() mutable {
                const auto result = fetchFuture.result();
                if (result.hasError()) {
                    if (QQuickGit::LfsStore::shouldFallbackForFetchError(result.errorCode())) {
                        (*step)();
                        return;
                    }
                    deferred.complete(Monad::ResultBase(result.errorMessage(), result.errorCode()));
                    return;
                }
                (*step)();
            });
    };

    (*step)();
    return deferred.future();
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

GitRepository::GitFuture runLfsHydrationForDirectory(const QDir& repositoryDir, QObject* context)
{
    auto prepareFuture = prepareLfsHydrationPlan(repositoryDir);
    return AsyncFuture::observe(prepareFuture)
        .context(context, [prepareFuture, context]() -> GitRepository::GitFuture {
            const auto prepareResult = prepareFuture.result();
            if (prepareResult.hasError()) {
                return AsyncFuture::completed(Monad::ResultBase(prepareResult.errorMessage(),
                                                                prepareResult.errorCode()));
            }
            return runLfsHydrationPipeline(prepareResult.value(), context);
        }).future();
}

GitRepository::MergeFuture runMergeHydrationForDirectory(const Monad::Result<GitRepository::MergeResult>& mergeResult,
                                                         const QDir& repositoryDir,
                                                         QObject* context)
{
    if (mergeResult.hasError()) {
        return AsyncFuture::completed(mergeResult);
    }

    const auto state = mergeResult.value().state();
    const bool shouldHydrate = state == GitRepository::MergeResult::FastForward
                               || state == GitRepository::MergeResult::MergeCommitCreated;
    if (!shouldHydrate) {
        return AsyncFuture::completed(mergeResult);
    }

    auto hydrateFuture = runLfsHydrationForDirectory(repositoryDir, context);
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
}

template<typename ProgressInterface>
void setProgress(ProgressInterface* progressInterface, const QString& text) {
    if(!text.isEmpty()) {
        //We have to increment the progress by one to signal that the text changes
        progressInterface->setProgressValueAndText(progressInterface->progressValue()+1, text);
    }
}

template<typename ProgressInterface>
void setProgress(ProgressInterface* progressInterface, const ProgressState& progress) {
    //We have to increment the progress by one to signal that the text changes
    progressInterface->setProgressRange(0, progress.total());
    setProgress(progressInterface, progress.toJsonString());
}


class GitRepositoryData {
public:
    QDir mDirectory;
    git_repository *repo = nullptr;
    int mModifiedFilesCount = 0;
    QPointer<Account> mAccount; //!<
    LfsPolicy mLfsPolicy;
    std::shared_ptr<LfsStore> mLfsStore;

    ~GitRepositoryData() {
        if(repo) {
            git_repository_free(repo);
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

    static int transferProgress(	unsigned int current,
                                unsigned int total,
                                size_t bytes,
                                void* payload)
    {

        auto progressInterface = progressFromPayload(payload);
        if(progressInterface) {
            auto progress = ProgressState(QStringLiteral("Transfering ... ") + bytesToString(bytes),
                                          current,
                                          total);
            setProgress(progressInterface, progress);
        }
        qDebug() << "Current progress:" << bytes << current << total << current / static_cast<double>(total) * 100;
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

            auto progressInterface = progressFromPayload(payload);
            if(progressInterface) {
                auto progress = ProgressState(QStringLiteral("Fetching ... ") + recieved(),
                                              current(),
                                              total());
                setProgress(progressInterface, progress);
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
            auto progressInterface = progressFromPayload(payload);
            if(progressInterface) {
                auto progress = ProgressState(QStringLiteral("Checkout ... ") + path,
                                              current,
                                              total);
                //We have to incremrent the progress by one to singal that the text changed
                setProgress(progressInterface, std::move(progress));
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

}

GitRepository::~GitRepository()
{
    if (d->mLfsStore) {
        LfsStoreRegistry::unregisterStore(d->mLfsStore->gitDirPath(), d->mLfsStore);
        d->mLfsStore.reset();
    }
    delete d;
}

void GitRepository::setDirectory(const QDir &dir)
{
    if(d->mDirectory != dir) {
        d->mDirectory = dir;
        emit directoryChanged();
    }
}

QDir GitRepository::directory()
{
    return d->mDirectory;
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
        bool bare = false;
        check(git_repository_init(&(d->repo), path, bare));
    }

    if (d->repo) {
        const char* gitPath = git_repository_path(d->repo);
        if (gitPath) {
            d->mLfsStore = std::make_shared<LfsStore>(QString::fromUtf8(gitPath), d->mLfsPolicy);
            LfsStoreRegistry::registerStore(d->mLfsStore);
        }
    }

    ensureLfsAttributes();
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

    QStringList lines = QString::fromUtf8(existingContents).split('\n');
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
        if (!combined.isEmpty() && !combined.last().isEmpty()) {
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
        addRemoteHelper(name, url);
    } catch (const std::runtime_error& error) {
        return QString::fromLocal8Bit(error.what()).trimmed();
    }
    return QString();
}

QUrl GitRepository::remoteUrl(QString name) const
{
    name = fixUpRemote(name);

    git_remote* remote;
    int error = git_remote_lookup(&remote, d->repo, name.toLocal8Bit());
    QUrl url;
    if(error == GIT_OK) {
        url = QUrl(QString::fromLocal8Bit(git_remote_url(remote)));
    }
    return url;
}

QVector<GitRemoteInfo> GitRepository::remotes() const
{
    QVector<GitRemoteInfo> remotes;

    git_strarray remoteNames;
    git_remote_list(&remoteNames, d->repo);
    remotes.reserve(remoteNames.count);

    for(size_t i = 0; i < remoteNames.count; i++) {
        QString name = QString::fromLocal8Bit(remoteNames.strings[i]);
        GitRemoteInfo info(name, remoteUrl(name));
        remotes.append(info);
    }

    return remotes;
}

QFuture<QString> GitRepository::testRemoteConnection(const QUrl &url)
{
    return QtConcurrent::run([url]()->QString  {
        try {
            GitRepository tempRepository;
            tempRepository.setDirectory(QDir::temp().absoluteFilePath(QUuid::createUuid().toString(QUuid::WithoutBraces)));
            tempRepository.initRepository();
            QString remoteName = "test";

            int error = GIT_OK;
            {
                auto remote = makeScopedPtr(git_remote_free);
                error = git_remote_lookup(&remote, tempRepository.d->repo, remoteName.toLocal8Bit());
            }
            if(error != GIT_OK) {
                tempRepository.addRemoteHelper(remoteName, url);
            } else {
                check(git_remote_set_url(tempRepository.d->repo,
                                         remoteName.toLocal8Bit(),
                                         url.toString().toLocal8Bit()));
            }

            auto remote = makeScopedPtr(git_remote_free);
            check(git_remote_lookup(&remote, tempRepository.d->repo, remoteName.toLocal8Bit()));

            git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;
            callbacks.credentials = GitRepositoryData::credentailCallBack;

            check(git_remote_connect(remote, GIT_DIRECTION_FETCH, &callbacks, nullptr, nullptr));

        }  catch (const std::runtime_error& error) {
            return QString::fromLocal8Bit(error.what()).trimmed();
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

        auto future = QtConcurrent::run([dir, url, progressInterface]() mutable ->Result<Repo> {
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

                        // Callback signature
                        auto hostkey_cb = [](git_cert *cert, int valid, const char *host, void *payload)->int {
                            Q_UNUSED(valid)
                            Q_UNUSED(host)
                            Q_UNUSED(payload)
                            // Only care about SSH hostkeys
                            if (cert->cert_type == GIT_CERT_HOSTKEY_LIBSSH2) {
                                //always accept the cert, could open the door for man in the middle attack
                                return GIT_OK;
                            }
                            return 0;  // allow other cert types
                        };

                        git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
                        clone_opts.fetch_opts.callbacks.certificate_check = hostkey_cb;
                        clone_opts.fetch_opts.callbacks.credentials = GitRepositoryData::credentailCallBack;
                        clone_opts.fetch_opts.callbacks.transfer_progress = GitRepositoryData::fetchProgress;
                        SshCallbackPayload callbackPayload;
                        callbackPayload.progressInterface = &progressInterface;
                        callbackPayload.allowAgent = allowAgent;
                        callbackPayload.agentMaxAttempts = 1;
                        callbackPayload.agentAttempts = 0;

                        clone_opts.fetch_opts.callbacks.payload = static_cast<void*>(&callbackPayload);

                        clone_opts.checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;
                        clone_opts.checkout_opts.progress_cb = GitRepositoryData::cloneCheckoutProgress;
                        clone_opts.checkout_opts.progress_payload = static_cast<void*>(&callbackPayload);

                        auto urlByteArray = url.toString().toLocal8Bit();
                        auto repoDirectory = dir.absolutePath().toLocal8Bit();

                        int err = git_clone(&localRepo, urlByteArray, repoDirectory, &clone_opts);
                        if(err == GIT_OK) {
                            return localRepo;
                        }

                        const git_error *errInfo = git_error_last();
                        if(errorMessage) {
                            if(errInfo && errInfo->message) {
                                *errorMessage = QString::fromUtf8(errInfo->message);
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
                        throw std::runtime_error(errorMessage.toStdString());
                    }

                    qDebug() << "Finished checking out!";

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
            .context(this, [future, this]() -> GitFuture {
                const auto cloneResult = future.result();
                if (cloneResult.hasError()) {
                    return AsyncFuture::completed(ResultBase(cloneResult.errorMessage(), cloneResult.errorCode()));
                }

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
                return runLfsHydrationForDirectory(d->mDirectory, this);
            }).future();
    });
}

/**
* @brief GitRepository::modifiedFileCount
* @return
*/
int GitRepository::modifiedFileCount() const {
    return d->mModifiedFilesCount;
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
    if(d->repo) {
        git_status_list* list;

        //Shouldn't include ignored files
        git_status_options opt = GIT_STATUS_OPTIONS_INIT;
        opt.show  = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
        opt.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS;

        git_status_list_new(&list, d->repo, &opt);
        auto count = git_status_list_entrycount(list);
        setModifiedFileCount(static_cast<int>(count));
        git_status_list_free(list);
    }
}

void GitRepository::commitAll(const QString &subject,
                              const QString &description)
{
    Q_ASSERT(account());

    git_index_matched_path_cb matched_cb = NULL;
    git_index *index;

    auto match_cb = [](const char *path, const char *spec, void *payload)->int
    {
        return 0;
    };

    std::array<const char*, 1> paths = {"*"};
    git_strarray array = {const_cast<char**>(paths.data()), 1};
    check(git_repository_index(&index, d->repo));
    //    check(git_index_update_all(index, &array, match_cb, nullptr));
    check(git_index_add_all(index, &array, GIT_INDEX_ADD_DEFAULT, match_cb, nullptr));
    //    git_index_write(index);

    git_oid commit_oid,tree_oid;
    git_tree *tree;
    git_object *parent = nullptr;
    git_reference *ref = nullptr;
    git_signature *signature;

    int error = git_revparse_ext(&parent, &ref, d->repo, "HEAD");
    if (error == GIT_ENOTFOUND) {
        printf("HEAD not found. Creating first commit\n");
    } else if (error != 0) {
        check(error);
    }

    check(git_index_write_tree(&tree_oid, index));
    check(git_index_write(index));

    // Ensure LFS-eligible files are staged as pointer blobs even if the
    // libgit2 filter driver is bypassed by index-wide staging paths.
    if (d->mLfsStore) {
        const QDir workDir = d->mDirectory;
        const size_t entryCount = git_index_entrycount(index);
        for (size_t i = 0; i < entryCount; ++i) {
            const git_index_entry* existing = git_index_get_byindex(index, i);
            if (!existing || !existing->path) {
                continue;
            }

            const QString relativePath = QString::fromUtf8(existing->path);
            const QString absolutePath = workDir.filePath(relativePath);
            if (!QFileInfo::exists(absolutePath) || QFileInfo(absolutePath).isDir()) {
                continue;
            }
            if (!d->mLfsStore->isLfsEligible(absolutePath)) {
                continue;
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
    git_tree_free(tree);
    git_index_free(index);

}

GitRepository::GitFuture GitRepository::push(QString refSpec, QString remote)
{
    return progressFuture<ResultBase>(
        [=](QFutureInterface<ResultBase> progressInterface)
        {
            auto fixRefSpec = refSpec;
            if(refSpec.isEmpty()) {
                auto headBranch = headBranchName();
                fixRefSpec = QString("refs/heads/%1").arg(headBranch);
            }

            const LfsPushRefSpec parsedRefSpec = parsePushRefSpec(fixRefSpec);
            if (hasRefGlobPattern(parsedRefSpec.sourceRef) || hasRefGlobPattern(parsedRefSpec.destinationRef)) {
                return AsyncFuture::completed(ResultBase(QStringLiteral("Wildcard push refspecs are not supported"), 2));
            }

            auto path = d->mDirectory.absolutePath().toLocal8Bit();
            auto fixRemote = fixUpRemote(remote);
            qDebug() << "[LFS push] begin"
                     << "repoDir=" << d->mDirectory.absolutePath()
                     << "refSpec=" << fixRefSpec
                     << "remote=" << fixRemote;
            auto prePushUploadFuture = runLfsPrePushUpload(path, fixRefSpec, fixRemote, this);

            return AsyncFuture::observe(prePushUploadFuture)
                .context(this, [=]() -> GitFuture {
                    const auto prePushResult = prePushUploadFuture.result();
                    if (prePushResult.hasError()) {
                        const bool unsupportedLfsRemote =
                            prePushResult.errorMessage() == QStringLiteral("Unsupported LFS remote URL");
                        if (unsupportedLfsRemote) {
                            qWarning() << "[LFS push] skipping LFS upload for unsupported remote URL; continuing with git push";
                        } else {
                            qDebug() << "[LFS push] pre-push upload failed:" << prePushResult.errorMessage();
                            return AsyncFuture::completed(prePushResult);
                        }
                    } else {
                        qDebug() << "[LFS push] pre-push upload complete";
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
                            options.callbacks.push_transfer_progress = GitRepositoryData::transferProgress;
                            SshCallbackPayload callbackPayload;
                            callbackPayload.progressInterface = &progressInterface;
                            callbackPayload.allowAgent = true;
                            callbackPayload.agentMaxAttempts = 1;
                            callbackPayload.agentAttempts = 0;
                            options.callbacks.payload = static_cast<void*>(&callbackPayload);

                            check(git_remote_push(gitRemote, &refspecs, &options));

                            git_remote_free(gitRemote);

                            return ResultBase();
                        });
                    });
                }).future();
        });
}

GitRepository::MergeFuture GitRepository::pull(const QString& remote)
{
    QString fixedRemote = fixUpRemote(remote);
    auto fetchFuture = fetch(remote);

    return progressFuture<Result<MergeResult>>(
        [=](QFutureInterface<Result<MergeResult>> progressInterface)
        {
            AsyncFuture::observe(fetchFuture)
            .onProgress([=]() mutable
                        {
                            //Passes the progress through
                            setProgress(&progressInterface, fetchFuture.progressText());
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

                             auto mergeResult = mtry(
                                 [=]() mutable ->Result<MergeResult>
                                 {
                                     auto currentBranch = headBranchName();

                                     if(!currentBranch.isEmpty()) {
                                         auto remoteBranch = fixedRemote + QStringLiteral("/") + currentBranch;

                                         //remote branch exists
                                         if(remoteBranchExists(remoteBranch)) {
                                             setProgress(&progressInterface, ProgressState(QStringLiteral("Merging"), 0, 1));
                                             return merge({remoteBranch});
                                         }
                                     }
                                     return Result<MergeResult>(); //QStringLiteral("Current branch name is empty"));
                                 });

                             return runMergeHydrationForDirectory(mergeResult, d->mDirectory, this);
                         }).future(); //This strips the progress from fetchFuture
        });
}

GitRepository::GitFuture GitRepository::pullPush(const QString &refSpec, const QString &remote)
{
    return progressFuture<ResultBase>([=](QFutureInterface<ResultBase> progressInterface) {
        auto pullFuture = pull(remote);
        return AsyncFuture::observe(pullFuture)
            .context(this, [=]() ->GitFuture
                     {
                         AsyncFuture::observe(pullFuture).onProgress([=]() mutable {
                             setProgress(&progressInterface, pullFuture.progressText());
                         });

                         return mbind(pullFuture, [=](const Result<MergeResult>& mergeResult) -> GitFuture {
                             if(mergeResult.value().state() == GitRepository::MergeResult::MergeConflicts) {
                                 return AsyncFuture::completed<ResultBase>(ResultBase(QStringLiteral("Merge Conflicts need to be resolved")));
                             }

                             auto pushFuture = push(refSpec, remote);

                             AsyncFuture::observe(pushFuture).onProgress([=]() mutable {
                                 setProgress(&progressInterface, pushFuture.progressText());
                             });

                             return pushFuture;
                         });
                     }).future();
    });
}

GitRepository::GitFuture GitRepository::fetch(const QString& remote)
{
    return progressFuture<ResultBase>(
        [=](QFutureInterface<ResultBase> progressInterface)
        {
            auto path = d->mDirectory.absolutePath().toLocal8Bit();

            return QtConcurrent::run(
                [=]() mutable
                {
                    return mtry(
                        [=]() mutable
                        {
                            auto fixedRemote = fixUpRemote(remote);

                            auto repo = makeScopedPtr(git_repository_free);
                            check(git_repository_open(&repo, path));

                            auto gitRemote = makeScopedPtr(&git_remote_free);
                            check(git_remote_lookup(&gitRemote, repo, fixedRemote.toLocal8Bit()));

                            git_fetch_options options = GIT_FETCH_OPTIONS_INIT;
                            options.callbacks.credentials = GitRepositoryData::credentailCallBack;
                            options.callbacks.transfer_progress = GitRepositoryData::fetchProgress;
                            SshCallbackPayload callbackPayload;
                            callbackPayload.progressInterface = &progressInterface;
                            callbackPayload.allowAgent = true;
                            callbackPayload.agentMaxAttempts = 1;
                            callbackPayload.agentAttempts = 0;
                            options.callbacks.payload = static_cast<void*>(&callbackPayload);
                            check(git_remote_fetch(gitRemote, nullptr, &options, nullptr));

                            return ResultBase();
                        });
                });
        });
}

GitRepository::MergeResult GitRepository::merge(const QStringList &refSpecs)
{

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

    auto perform_fastforward = [](git_repository *repo, const git_oid *target_oid, int is_unborn)->int
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
        err = git_checkout_tree(repo, target, &ff_checkout_options);
        if (err != 0) {
            fprintf(stderr, "failed to checkout HEAD reference\n");
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
        if (analysis & GIT_MERGE_ANALYSIS_UNBORN) {
            printf("Unborn\n");
        } else {
            printf("Fast-forward\n");
        }

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

        auto createMergeCommit = [&index, &commitsToMerge, create_merge_commit]() {
            create_merge_commit(index, commitsToMerge);
            printf("Merge made\n");
            return MergeResult(MergeResult::MergeCommitCreated);
        };

        if (git_index_has_conflicts(index)) {
            /* Handle conflicts */


            //ResolveWithOurs is based on this post in github
            //https://github.com/libgit2/objective-git/issues/665
            //https://github.com/libgit2/libgit2/issues/3940#issuecomment-250447791
            //https://stackoverflow.com/questions/51977074/objectivegit-resolving-file-conflicts-with-gtindex-enumerateconflictedfilesw
            auto resolveWithOurs = [](git_index* index, const QDir& repoDir) {

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

                auto writeBuffer = [](const char* gitPath, const QDir& repoDir, const QByteArray& buffer) {
                    auto path = repoDir.absoluteFilePath(gitPath);
                    QFile file(path);
                    if (!file.open(QFile::WriteOnly)) {
                        qDebug() << "Failed to open" << path << "for writing";
                        return;
                    }
                    file.write(buffer);
                };

                git_index_conflict_iterator* iterator;
                check(git_index_conflict_iterator_new(&iterator, index));

                const git_index_entry *ancestor;
                const git_index_entry *our;
                const git_index_entry *their;
                int err = 0;

                while ((err = git_index_conflict_next(&ancestor, &our, &their, iterator)) == 0) {
                    //After removing the path from our. our->path will be empty
                    QByteArray path = our->path;

                    check(git_index_conflict_remove(index, path));

                    //Remove the diff tags from the file
                    auto buffer = useOurs(path, repoDir);
                    writeBuffer(path, repoDir, std::move(buffer));

                    //Add the file back into the index
                    check(git_index_add_bypath(index, path));
                }
                git_index_conflict_iterator_free(iterator);
                check(git_index_write(index));

                Q_ASSERT(!git_index_has_conflicts(index));
            };

            QDir repoDir(git_repository_path(d->repo));
            repoDir.cdUp();
            resolveWithOurs(index, repoDir);

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
    return progressFuture<ResultBase>(
        [=](QFutureInterface<ResultBase>)
        {
            auto path = d->mDirectory.absolutePath().toLocal8Bit();
            auto localRefSpec = refSpec.toLocal8Bit();

            auto prepareFuture = QtConcurrent::run([=]() mutable {
                return mtry([=]() mutable -> Monad::Result<LfsHydrationPlan> {
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
                    return buildLfsHydrationPlan(repo);
                });
            });

            return AsyncFuture::observe(prepareFuture)
                .context(this, [=]() {
                    const auto prepareResult = prepareFuture.result();
                    if (prepareResult.hasError()) {
                        return AsyncFuture::completed(ResultBase(prepareResult.errorMessage(), prepareResult.errorCode()));
                    }
                    return runLfsHydrationPipeline(prepareResult.value(), this);
                }).future();
        });
}

GitRepository::GitFuture GitRepository::reset(const QString& refSpec, ResetMode mode)
{
    return progressFuture<ResultBase>(
        [=](QFutureInterface<ResultBase>)
        {
            auto path = d->mDirectory.absolutePath().toLocal8Bit();
            auto localRefSpec = refSpec.toLocal8Bit();

            auto prepareFuture = QtConcurrent::run([=]() mutable {
                return mtry([=]() mutable -> Monad::Result<LfsHydrationPlan> {
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
                        checkoutOptions.checkout_strategy = GIT_CHECKOUT_FORCE;
                        checkoutOptionsPtr = &checkoutOptions;
                        break;
                    }

                    check(git_reset(repo, object, resetType, checkoutOptionsPtr));
                    git_object_free(object);

                    if (mode != ResetMode::Hard) {
                        return Monad::Result<LfsHydrationPlan>(LfsHydrationPlan{});
                    }
                    return buildLfsHydrationPlan(repo);
                });
            });

            return AsyncFuture::observe(prepareFuture)
                .context(this, [=]() {
                    const auto prepareResult = prepareFuture.result();
                    if (prepareResult.hasError()) {
                        return AsyncFuture::completed(ResultBase(prepareResult.errorMessage(), prepareResult.errorCode()));
                    }
                    return runLfsHydrationPipeline(prepareResult.value(), this);
                }).future();
        });
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

void GitRepository::addRemoteHelper(const QString &name, const QUrl &url)
{
    auto remote = makeScopedPtr(&git_remote_free);
    check(git_remote_create(&remote,
                            d->repo,
                            name.toLocal8Bit(),
                            url.toString().toLocal8Bit()));
    emit remotesChanged();
}

QString GitRepository::headBranchName() const
{
    git_reference* head;
    git_repository_head(&head, d->repo);

    if(head) {
        const char* branchName;
        git_branch_name(&branchName, head);

        QString name = QString::fromLocal8Bit(branchName);

        git_reference_free(head);
        return name;
    } else {
        return QString();
    }
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

void GitRepository::setAccount(Account* account) {
    if(d->mAccount != account) {
        d->mAccount = account;
        emit accountChanged();
    }
}

Account* GitRepository::account() const {
    return d->mAccount;
}
