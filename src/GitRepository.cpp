//Std includes
#include <stdexcept>
#include <array>

//Our includes
#include "GitRepository.h"
#include "RSAKeyGenerator.h"
#include "Account.h"
#include "Monad/Result.h"
#include "ProgressState.h"
#include "Monad/Monad.h"

//LibGit2 includes
#include "git2.h"
#include <git2/index.h>
#include <libssh2.h>

//Qt includes
#include <QDebug>
#include <QFileInfo>
#include <QPointer>
#include <QtConcurrent>
#include <QUuid>

//Async includes
#include "asyncfuture.h"

using namespace Monad;
using namespace QQuickGit;

template<typename ProgressInterface>
void setProgress(ProgressInterface* interface, const QString& text) {
    if(!text.isEmpty()) {
        //We have to increment the progress by one to signal that the text changes
        interface->setProgressValueAndText(interface->progressValue()+1, text);
    }
}

template<typename ProgressInterface>
void setProgress(ProgressInterface* interface, const ProgressState& progress) {
    //We have to increment the progress by one to signal that the text changes
    interface->setProgressRange(0, progress.total());
    setProgress(interface, progress.toJsonString());
}


class GitRepositoryData {
public:
    QDir mDirectory;
    git_repository *repo = nullptr;
    int mModifiedFilesCount = 0;
    QPointer<Account> mAccount; //!<

    ~GitRepositoryData() {
        if(repo) {
            git_repository_free(repo);
        }
    }

    static int credentailCallBack(git_credential **out,
                                  const char *url,
                                  const char *username_from_url,
                                  unsigned int allowed_types,
                                  void *payload)
    {
        RSAKeyGenerator key;
        key.loadOrGenerate();

        auto publicKeyPath = key.publicKeyPath().toLocal8Bit();
        auto privateKeyPath = key.privateKeyPath().toLocal8Bit();

        return git_credential_ssh_key_new(out, username_from_url, publicKeyPath, privateKeyPath, "");
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

        auto interface = reinterpret_cast<QFutureInterface<ResultBase>*>(payload);
        auto progress = ProgressState(QStringLiteral("Transfering ... ") + bytesToString(bytes),
                                      current,
                                      total);
        setProgress(interface, progress);
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

            auto interface = reinterpret_cast<QFutureInterface<ResultBase>*>(payload);
            auto progress = ProgressState(QStringLiteral("Fetching ... ") + recieved(),
                                          current(),
                                          total());
            setProgress(interface, progress);
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
            auto interface = reinterpret_cast<QFutureInterface<ResultBase>*>(payload);
            auto progress = ProgressState(QStringLiteral("Checkout ... ") + path,
                                          current,
                                          total);
            //We have to increment the progress by one to singal that the text changed
            setProgress(interface, std::move(progress));
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
    auto path = d->mDirectory.absolutePath().toLocal8Bit();
    int error = git_repository_open(&(d->repo), path);
    if(error != GIT_OK) {
        bool bare = false;
        check(git_repository_init(&(d->repo), path, bare));
    }
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
}

void GitRepository::shutdownGitEngine()
{
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

                    // Callback signature
                    auto hostkey_cb = [](git_cert *cert, int valid, const char *host, void *payload)->int {
                        // Only care about SSH hostkeys
                        if (cert->cert_type == GIT_CERT_HOSTKEY_LIBSSH2) {
                            // auto *ssh_cert = (git_cert_hostkey *)cert;
                            // // 'payload' must be a LIBSSH2_SESSION* initialized beforehand
                            // LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)payload;
                            // LIBSSH2_KNOWNHOSTS *kh = libssh2_knownhost_init(session);
                            // unsigned int check;

                            // // 1) Declare a pointer-to-knownhost and initialize to nullptr
                            // struct libssh2_knownhost *hostinfo = nullptr;

                            // // 2) Call libssh2_knownhost_checkp, passing &hostinfo
                            // int rc = libssh2_knownhost_checkp(
                            //     kh,                                        // your known-hosts collection
                            //     host, strlen(host),                        // server name and length
                            //     (const char*)ssh_cert->hostkey,            // raw key blob pointer
                            //     ssh_cert->hostkey_len,                     // key length
                            //     LIBSSH2_KNOWNHOST_TYPE_PLAIN               // typemask: plain hostname…
                            //         | LIBSSH2_KNOWNHOST_KEYENC_RAW,          // …and raw key data
                            //     &hostinfo                                  // <<-- note: &hostinfo, not &check
                            //     );

                            // libssh2_knownhost_free(kh);

                            // // Match==0 means OK
                            // return (rc == LIBSSH2_KNOWNHOST_CHECK_MATCH) ? 0 : GIT_ECERTIFICATE;

                            //always accept the cert, could open the door for man in the middle attack
                            return GIT_OK;
                        }
                        return 0;  // allow other cert types
                    };

                    // Initialize your libssh2 session and store pointer in payload
                    LIBSSH2_SESSION *session = libssh2_session_init();

                    git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
                    clone_opts.fetch_opts.callbacks.certificate_check = hostkey_cb;
                    clone_opts.fetch_opts.callbacks.credentials = GitRepositoryData::credentailCallBack;
                    clone_opts.fetch_opts.callbacks.transfer_progress = GitRepositoryData::fetchProgress;
                    clone_opts.fetch_opts.callbacks.payload = static_cast<void*>(&progressInterface);

                    clone_opts.checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;
                    clone_opts.checkout_opts.progress_cb = GitRepositoryData::cloneCheckoutProgress;
                    clone_opts.checkout_opts.progress_payload = static_cast<void*>(&progressInterface);

                    auto urlByteArray = url.toString().toLocal8Bit();
                    auto repoDirectory = dir.absolutePath().toLocal8Bit();

                    check(git_clone(&repo, urlByteArray, repoDirectory, &clone_opts));

                    qDebug() << "Finished checking out!";

                    return Result<Repo>(Repo({repo}));
                } else {
                    if(dir.isEmpty()) {
                        throw std::runtime_error(QString("Can't clone %1 because the directory is empty")
                                                     .arg(url.toString())
                                                     .toStdString());
                    } else {
                        throw std::runtime_error(QString("Can't clone %1 because directory %2 already exists")
                                                     .arg(url.toString())
                                                     .arg(dir.absolutePath())
                                                     .toStdString());
                    }
                }

            });
        });

        AsyncFuture::observe(future).context(this, [future, this]() {
            d->repo = future.result().value().repo;
        });

        return future;
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

            auto path = d->mDirectory.absolutePath().toLocal8Bit();

            return QtConcurrent::run([=]() {
                return mtry([=]() mutable ->ResultBase {
                    auto fixRemote = fixUpRemote(remote);

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
                    options.callbacks.payload = static_cast<void*>(&progressInterface);

                    check(git_remote_push(gitRemote, &refspecs, &options));

                    git_remote_free(gitRemote);

                    return ResultBase();
                });
            });
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
                             return mbind(fetchFuture.result(),
                                          [=](const ResultBase&)
                                          {
                                              return mtry(
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
                                          });
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
                            options.callbacks.payload = static_cast<void*>(&progressInterface);
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

        for(auto ref_ish : refSpecs) {
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
                    file.open(QFile::ReadOnly);

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
                    file.open(QFile::WriteOnly);
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

void GitRepository::checkout(const QString &refSpec)
{
    git_object* object;
    check(git_revparse_single(&object, d->repo, refSpec.toLocal8Bit()));

    auto id = git_object_id(object);
    d->checkout(id, refSpec);

    git_object_free(object);
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

void GitRepository::setAccount(Account* account) {
    if(d->mAccount != account) {
        d->mAccount = account;
        emit accountChanged();
    }
}

Account* GitRepository::account() const {
    return d->mAccount;
}
