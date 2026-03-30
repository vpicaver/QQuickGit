//Our includes
#include "GitGraphModel.h"
#include "GitRepository.h"
#include "GitLanes.h"

//Qt includes
#include <QtConcurrent>
#include <QDir>

//libgit2
#include "git2.h"

using namespace QQuickGit;

namespace GitGraphModelPrivate {

struct IndexPassResult
{
    QVector<QByteArray> oids;
    QVector<GitRowGraph> graph;
    QHash<QString, QStringList> refMap;
};

} // namespace GitGraphModelPrivate

Q_DECLARE_METATYPE(GitGraphModelPrivate::IndexPassResult)

using namespace GitGraphModelPrivate;

namespace {

QByteArray oidToBytes(const git_oid* oid)
{
    return QByteArray(reinterpret_cast<const char*>(oid->id), GIT_OID_SHA1_SIZE);
}

git_oid bytesToOid(const QByteArray& bytes)
{
    git_oid oid;
    memset(&oid, 0, sizeof(oid));
    if (bytes.size() >= GIT_OID_SHA1_SIZE)
        memcpy(oid.id, bytes.constData(), GIT_OID_SHA1_SIZE);
    return oid;
}

QString oidToString(const git_oid* oid)
{
    char buffer[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(buffer, sizeof(buffer), oid);
    return QString::fromLatin1(buffer);
}

QHash<QString, QStringList> buildRefMap(git_repository* repo)
{
    QHash<QString, QStringList> refMap;

    git_reference_iterator* iter = nullptr;
    if (git_reference_iterator_new(&iter, repo) != GIT_OK || !iter)
        return refMap;

    std::unique_ptr<git_reference_iterator, decltype(&git_reference_iterator_free)>
        iterHolder(iter, &git_reference_iterator_free);

    git_reference* ref = nullptr;
    while (git_reference_next(&ref, iter) == GIT_OK)
    {
        std::unique_ptr<git_reference, decltype(&git_reference_free)>
            refHolder(ref, &git_reference_free);

        const char* name = git_reference_name(ref);
        if (!name)
            continue;

        QString refName = QString::fromUtf8(name);

        QString shortName;
        if (refName.startsWith(QStringLiteral("refs/heads/")))
            shortName = refName.mid(11);
        else if (refName.startsWith(QStringLiteral("refs/remotes/")))
            shortName = refName.mid(13);
        else
            continue;

        git_reference* resolved = nullptr;
        if (git_reference_resolve(&resolved, ref) != GIT_OK)
            continue;

        std::unique_ptr<git_reference, decltype(&git_reference_free)>
            resolvedHolder(resolved, &git_reference_free);

        const git_oid* target = git_reference_target(resolved);
        if (!target)
            continue;

        QString sha = oidToString(target);
        refMap[sha].append(shortName);
    }

    return refMap;
}

IndexPassResult runIndexPass(const QString& repoPath)
{
    IndexPassResult result;

    git_repository* repo = nullptr;
    if (git_repository_open(&repo, repoPath.toLocal8Bit().constData()) != GIT_OK || !repo)
        return result;

    std::unique_ptr<git_repository, decltype(&git_repository_free)>
        repoHolder(repo, &git_repository_free);

    result.refMap = buildRefMap(repo);

    git_revwalk* walk = nullptr;
    if (git_revwalk_new(&walk, repo) != GIT_OK || !walk)
        return result;

    std::unique_ptr<git_revwalk, decltype(&git_revwalk_free)>
        walkHolder(walk, &git_revwalk_free);

    git_revwalk_sorting(walk, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);

    git_revwalk_push_glob(walk, "refs/heads/*");
    git_revwalk_push_glob(walk, "refs/remotes/*");

    GitLanes lanes;
    git_oid oid;
    bool firstCommit = true;

    while (git_revwalk_next(&oid, walk) == GIT_OK)
    {
        QString sha = oidToString(&oid);

        git_commit* commit = nullptr;
        if (git_commit_lookup(&commit, repo, &oid) != GIT_OK || !commit)
            continue;

        std::unique_ptr<git_commit, decltype(&git_commit_free)>
            commitHolder(commit, &git_commit_free);

        unsigned int parentCount = git_commit_parentcount(commit);

        QStringList parentShas;
        parentShas.reserve(parentCount);
        for (unsigned int i = 0; i < parentCount; i++)
        {
            const git_oid* parentOid = git_commit_parent_id(commit, i);
            parentShas.append(oidToString(parentOid));
        }

        if (firstCommit)
        {
            lanes.init(sha);
            firstCommit = false;
        }

        // Call order matters — follows GitQlient's calculateLanes + resetLanes
        bool isDiscontinuity = false;
        bool fork = lanes.isFork(sha, isDiscontinuity);

        if (isDiscontinuity)
            lanes.changeActiveLane(sha);

        if (fork)
            lanes.setFork(sha);

        if (parentCount > 1)
            lanes.setMerge(parentShas);

        if (parentCount == 0)
            lanes.setInitial();

        GitRowGraph rowGraph;
        rowGraph.sha = sha;
        rowGraph.lanes = lanes.getLanes();
        rowGraph.activeLane = lanes.activeLaneIndex();

        result.oids.append(oidToBytes(&oid));
        result.graph.append(std::move(rowGraph));

        QString nextSha = parentCount == 0 ? QString() : parentShas.first();
        lanes.nextParent(nextSha);

        if (parentCount > 1)
            lanes.afterMerge();
        if (fork)
            lanes.afterFork();
        if (lanes.isBranch())
            lanes.afterBranch();
    }

    return result;
}

} // anonymous namespace

GitGraphModel::GitGraphModel(QObject* parent)
    : QAbstractListModel(parent)
    , mRestarter(this)
{
    qRegisterMetaType<GitGraphModelPrivate::IndexPassResult>();
}

GitGraphModel::~GitGraphModel() = default;

void GitGraphModel::setRepository(GitRepository* repository)
{
    if (mRepository == repository)
        return;

    if (mRepository)
        disconnect(mRepository, nullptr, this, nullptr);

    mRepository = repository;

    if (mRepository)
    {
        connect(mRepository, &GitRepository::directoryChanged, this, &GitGraphModel::refresh);
        connect(mRepository, &GitRepository::remotesChanged, this, &GitGraphModel::refresh);
        connect(mRepository, &GitRepository::headBranchNameChanged, this, &GitGraphModel::refresh);
        refresh();
    }
    else
    {
        clearModel();
    }

    emit repositoryChanged();
}

int GitGraphModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid())
        return 0;

    return mOids.size();
}

QVariant GitGraphModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= mOids.size())
        return QVariant();

    const int row = index.row();

    switch (role)
    {
    case ShaRole:
        return mGraph.at(row).sha;

    case MessageRole:
        return fetchDetail(row).message;

    case AuthorRole:
        return fetchDetail(row).author;

    case TimestampRole:
        return fetchDetail(row).timestamp;

    case LanesRole: {
        const auto& lanes = mGraph.at(row).lanes;
        QList<int> laneTypes;
        laneTypes.reserve(lanes.size());
        for (const auto& lane : lanes)
            laneTypes.append(static_cast<int>(lane.type()));
        return QVariant::fromValue(laneTypes);
    }

    case ActiveLaneRole:
        return mGraph.at(row).activeLane;

    case RefsRole: {
        const QString& sha = mGraph.at(row).sha;
        return QVariant::fromValue(mRefMap.value(sha));
    }
    }

    return QVariant();
}

QHash<int, QByteArray> GitGraphModel::roleNames() const
{
    const static QHash<int, QByteArray> roles {
        {ShaRole, "sha"},
        {MessageRole, "message"},
        {AuthorRole, "author"},
        {TimestampRole, "timestamp"},
        {LanesRole, "lanes"},
        {ActiveLaneRole, "activeLane"},
        {RefsRole, "refs"}
    };

    return roles;
}

void GitGraphModel::refresh()
{
    if (!mRepository)
        return;

    QDir dir = mRepository->directory();
    if (!dir.exists())
        return;

    QString repoPath = dir.absolutePath();

    mRestarter.onFutureChanged([this]() {
        auto future = mRestarter.future();

        AsyncFuture::observe(future).context(this, [this, future]() {
            if (future.isCanceled())
                return;

            auto result = future.result().value<IndexPassResult>();

            clearModel();

            if (!result.oids.isEmpty())
            {
                beginInsertRows(QModelIndex(), 0, result.oids.size() - 1);
                mOids = std::move(result.oids);
                mGraph = std::move(result.graph);
                mRefMap = std::move(result.refMap);
                endInsertRows();
            }

            mLoading = false;
            emit loadingChanged();
        });
    });

    mLoading = true;
    emit loadingChanged();
    mCache.clear();

    mRestarter.restart([repoPath]() -> QFuture<QVariant> {
        return QtConcurrent::run([repoPath]() -> QVariant {
            auto result = runIndexPass(repoPath);
            return QVariant::fromValue(result);
        });
    });
}

void GitGraphModel::clearModel()
{
    if (!mOids.isEmpty())
    {
        beginRemoveRows(QModelIndex(), 0, mOids.size() - 1);
        mOids.clear();
        mGraph.clear();
        mRefMap.clear();
        mCache.clear();
        endRemoveRows();
    }
}

const GitCommitDetail& GitGraphModel::fetchDetail(int row) const
{
    auto it = mCache.constFind(row);
    if (it != mCache.constEnd())
        return it.value();

    GitCommitDetail detail;

    if (row >= 0 && row < mOids.size() && mRepository)
    {
        QDir dir = mRepository->directory();
        git_repository* repo = nullptr;
        if (git_repository_open(&repo, dir.absolutePath().toLocal8Bit().constData()) == GIT_OK && repo)
        {
            std::unique_ptr<git_repository, decltype(&git_repository_free)>
                repoHolder(repo, &git_repository_free);

            git_oid oid = bytesToOid(mOids[row]);
            git_commit* commit = nullptr;
            if (git_commit_lookup(&commit, repo, &oid) == GIT_OK && commit)
            {
                std::unique_ptr<git_commit, decltype(&git_commit_free)>
                    commitHolder(commit, &git_commit_free);

                const char* msg = git_commit_message(commit);
                if (msg)
                {
                    QString fullMessage = QString::fromUtf8(msg);
                    int newline = fullMessage.indexOf(QLatin1Char('\n'));
                    detail.message = newline >= 0 ? fullMessage.left(newline) : fullMessage;
                }

                const git_signature* author = git_commit_author(commit);
                if (author && author->name)
                    detail.author = QString::fromUtf8(author->name);

                git_time_t time = git_commit_time(commit);
                int offset = git_commit_time_offset(commit);
                detail.timestamp = QDateTime::fromSecsSinceEpoch(time, QTimeZone::fromSecondsAheadOfUtc(offset * 60));
            }
        }
    }

    mCache.insert(row, detail);
    return mCache[row];
}
