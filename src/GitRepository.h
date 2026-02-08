#ifndef GITREPOSITORY_H
#define GITREPOSITORY_H

//Our includes
#include "GitRemoteInfo.h"
#include "Monad/Result.h"
#include "Account.h"
class GitRepositoryData;

//Async Future includes
#include "asyncfuture.h"

//Qt inculdes
#include <QObject>
#include <QQmlEngine>
#include <QDir>
#include <QUrl>
#include <QFuture>
#include <memory>

namespace QQuickGit {
class LfsStore;
class LfsPolicy;
class GitRepository : public QObject
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QDir directory READ directory WRITE setDirectory NOTIFY directoryChanged)
    Q_PROPERTY(int modifiedFileCount READ modifiedFileCount NOTIFY modifiedFileCountChanged)
    Q_PROPERTY(Account* account READ account WRITE setAccount NOTIFY accountChanged)
    Q_PROPERTY(QString headBranchName READ headBranchName NOTIFY headBranchNameChanged)
    Q_PROPERTY(QVector<GitRemoteInfo> remotes READ remotes NOTIFY remotesChanged)

public:
    enum class CheckoutMode {
        Safe,
        Force
    };
    Q_ENUM(CheckoutMode)

    enum class ResetMode {
        Soft,
        Mixed,
        Hard
    };
    Q_ENUM(ResetMode)

    class MergeResult {
        friend GitRepository;

    public:
        enum State {
            UnknownState, //0
            AlreadyUpToDate, //1
            FastForward, //2
            MergeCommitCreated, //3
            MergeConflicts //4
        };

        MergeResult() = default;

        State state() const { return mState; }

    private:
        MergeResult(State state) :
            mState(state)
        {}

        State mState = UnknownState;
    };

    typedef QFuture<Monad::ResultBase> GitFuture;
    typedef QFuture<Monad::Result<GitRepository::MergeResult>> MergeFuture;

    GitRepository(QObject* parent = nullptr);
    ~GitRepository();

    void setDirectory(const QDir& dir);
    QDir directory();

    Account* account() const;
    void setAccount(Account* account);

    void initRepository();
    void setLfsPolicy(const LfsPolicy& policy);
    std::shared_ptr<LfsStore> lfsStore() const;

    Q_INVOKABLE QString addRemote(const QString& name, const QUrl& url) noexcept;
    QUrl remoteUrl(QString name = QString()) const;
    QVector<GitRemoteInfo> remotes() const;

    Q_INVOKABLE static QFuture<QString> testRemoteConnection(const QUrl& url);

    static QString repositoryNameFromUrl(const QUrl& url);

    int modifiedFileCount() const;
    bool hasCommits() const;

    Q_INVOKABLE void checkStatus();

    Q_INVOKABLE void commitAll(const QString& subject,
                               const QString& description);

    Q_INVOKABLE GitRepository::GitFuture push(QString refSpec = QString(), QString remote = QString());
    Q_INVOKABLE GitRepository::MergeFuture pull(const QString& remote = QString());
    Q_INVOKABLE GitRepository::GitFuture pullPush(const QString& refSpec = QString(), const QString& remote = QString());

    Q_INVOKABLE GitRepository::GitFuture fetch(const QString& remote = QString());
    MergeResult merge(const QStringList& refSpecs);

    Q_INVOKABLE void createBranch(const QString& branchName,
                                  const QString &refSpec = QString(),
                                  bool checkout = true);
    void deleteBranch(const QString& branchName);
    Q_INVOKABLE GitRepository::GitFuture deleteBranchRemote(const QString& branchName);

    bool remoteBranchExists(const QString& refSpec) const;

    Q_INVOKABLE GitFuture checkout(const QString& refSpec,
                                   CheckoutMode mode = CheckoutMode::Safe);
    Q_INVOKABLE GitFuture reset(const QString& refSpec,
                                ResetMode mode = ResetMode::Hard);

    QString headBranchName() const;

    static void initGitEngine();
    static void shutdownGitEngine();

    Q_INVOKABLE GitFuture clone(const QUrl& url);

    static bool isRepository(const QDir &dir);

signals:
    void directoryChanged();
    void modifiedFileCountChanged();
    void accountChanged();
    void headBranchNameChanged();
    void remotesChanged();


private:

    //This template magic is from
    //https://stackoverflow.com/questions/27879815/c11-get-type-of-first-second-etc-argument-similar-to-result-of
    // primary template.
    template<class T>
    struct function_traits : function_traits<decltype(&T::operator())> {
    };

    // partial specialization for function pointer
    template<class R, class... Args>
    struct function_traits<R (*)(Args...)> {
        using result_type = R;
        using argument_types = std::tuple<Args...>;
    };

    template<class T>
    using first_argument_type = typename std::tuple_element<0, typename function_traits<T>::argument_types>::type;

    template<typename T, typename FreeFunc>
    class ScopedPtr {
    public:

        ScopedPtr(FreeFunc freeFunc) :
            mFreeFunction(freeFunc)
        {}

        ~ScopedPtr() {
            mFreeFunction(mPtr);
            mPtr = nullptr;
        }

        //This is really T** becaues T is a point
        T* operator&() {
            return &mPtr;
        }

        //This is really T* because T is a pointer
        T data() const {
            return mPtr;
        }

        //This is really T* because T is a pointer
        operator T() {
            return mPtr;
        }

        void operator =(T ptr) {
            Q_ASSERT(mPtr == nullptr);
            mPtr = ptr;
        }

    private:
        FreeFunc mFreeFunction;
        T mPtr = nullptr;

        static_assert (std::is_pointer<T>(), "T isn't a pointer");
    };

    template<typename FreeFunc>
    static ScopedPtr<first_argument_type<FreeFunc>, FreeFunc> makeScopedPtr(FreeFunc func) {
         return ScopedPtr<first_argument_type<FreeFunc>, FreeFunc>(func);
    }

    template<typename ProgressInterface, typename Future>
    auto observeGitFuture(ProgressInterface progressInterface, Future future) {
        AsyncFuture::observe(future).context(this, [progressInterface, future, this]() mutable {
            if(future.result().hasError()) {
                decltype(future.result()) errorResult(future.result().errorMessage(), future.result().errorCode());
                progressInterface.reportResult(std::move(errorResult));
            } else {
                progressInterface.reportResult(future.result());
            }
            progressInterface.reportFinished();
        });
    }

    template<typename T>
    auto makeFutureInterface() {
        QFutureInterface<T> progressInterface;
        progressInterface.setProgressRange(0, 1);
        progressInterface.reportStarted();
        return progressInterface;
    };

    template<typename T, typename F>
    auto progressFuture(F runFunc) {
        auto interface = makeFutureInterface<T>();
        auto future = runFunc(interface);
        observeGitFuture(interface, future);
        return interface.future();
    }

    void setModifiedFileCount(int count);
    static void check(int error);

    static QString fixUpRemote(const QString& remote);

    void addRemoteHelper(const QString& name, const QUrl& url);
    void ensureLfsAttributes();

    GitRepositoryData* d;
};
}

Q_DECLARE_METATYPE(QFuture<Monad::Result<QQuickGit::GitRepository::MergeResult>>)

#endif // GITREPOSITORY_H
