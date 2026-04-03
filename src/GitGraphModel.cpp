//Our includes
#include "GitGraphModel.h"
#include "GitOidUtils.h"
#include "GitRepository.h"
#include "GitLanes.h"
#include "GitConcurrent.h"

//Qt includes
#include <QDir>

//libgit2
#include "git2.h"

using namespace QQuickGit;

namespace {

// Build simplified lanes for the synthetic "Uncommitted Changes" row.
// Instead of copying HEAD's lane types verbatim (which includes merge curves
// and other topology-specific types), reduce each lane to Active, NotActive,
// or Empty so only straight pass-through lines are drawn.
QList<int> buildSyntheticLanes(const GitRowGraph& headGraph)
{
    using LaneType = GitLaneType::Type;
    QList<int> lanes;
    lanes.reserve(headGraph.lanes.size());
    for (int i = 0; i < headGraph.lanes.size(); ++i)
    {
        if (i == headGraph.activeLane)
        {
            lanes.append(static_cast<int>(LaneType::Active));
            continue;
        }

        // Types without a top line start at the HEAD commit and don't
        // extend upward into the synthetic row.
        LaneType type = headGraph.lanes[i].type();
        switch (type)
        {
        case LaneType::Empty:
        case LaneType::CrossEmpty:
        case LaneType::Head:
        case LaneType::HeadLeft:
        case LaneType::HeadRight:
        case LaneType::Branch:
            lanes.append(static_cast<int>(LaneType::Empty));
            break;
        default:
            lanes.append(static_cast<int>(LaneType::NotActive));
            break;
        }
    }
    return lanes;
}

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

        // Skip symbolic refs (e.g. origin/HEAD) — they duplicate the branch they point to
        if (git_reference_type(ref) == GIT_REFERENCE_SYMBOLIC)
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

    git_reference* headRef = nullptr;
    if (git_repository_head(&headRef, repo) == GIT_OK && headRef) {
        std::unique_ptr<git_reference, decltype(&git_reference_free)>
            headHolder(headRef, &git_reference_free);
        const git_oid* headOid = git_reference_target(headRef);
        if (headOid)
            result.headSha = oidToString(headOid);
    }

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

        bool wasBranchBeforeMerge = false;
        if (parentCount > 1)
        {
            wasBranchBeforeMerge = lanes.isBranch();
            lanes.setMerge(parentShas);
        }

        if (parentCount == 0)
            lanes.setInitial();

        GitRowGraph rowGraph;
        rowGraph.sha = sha;
        rowGraph.lanes = lanes.getLanes();
        rowGraph.activeLane = lanes.activeLaneIndex();

        // When a merge commit starts a new lane, setMerge() overwrites
        // Branch (no top line) with MergeFork (has top line), creating a
        // dangling line going up to nothing. Replace with Head type.
        if (wasBranchBeforeMerge)
        {
            int al = rowGraph.activeLane;
            if (al >= 0 && al < rowGraph.lanes.size())
            {
                auto type = rowGraph.lanes[al].type();
                if (type == GitLaneType::MergeFork)
                    rowGraph.lanes[al].setType(GitLaneType::Head);
                else if (type == GitLaneType::MergeForkLeft)
                    rowGraph.lanes[al].setType(GitLaneType::HeadLeft);
                else if (type == GitLaneType::MergeForkRight)
                    rowGraph.lanes[al].setType(GitLaneType::HeadRight);
            }
        }

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
        connect(mRepository, &GitRepository::refsChanged, this, &GitGraphModel::refresh);
        connect(mRepository, &GitRepository::modifiedFileCountChanged, this, &GitGraphModel::updateSyntheticRow);
        refresh();
    }
    else
    {
        if (mHasSyntheticRow)
            removeSyntheticRow();
        clearModel();
    }

    emit repositoryChanged();
}

int GitGraphModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid())
        return 0;

    return mOids.size() + syntheticOffset();
}

QVariant GitGraphModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount())
        return QVariant();

    const int row = index.row();

    // Synthetic "Uncommitted Changes" row at index 0
    if (mHasSyntheticRow && row == 0)
    {
        switch (role)
        {
        case ShaRole:
            return QString();
        case MessageRole:
            return QStringLiteral("Uncommitted Changes");
        case AuthorRole:
            return QString();
        case TimestampRole:
            return QDateTime::currentDateTime();
        case LanesRole:
            if (!mGraph.isEmpty())
                return QVariant::fromValue(buildSyntheticLanes(mGraph.at(0)));
            return QVariant::fromValue(QList<int>());
        case ActiveLaneRole:
            return mGraph.isEmpty() ? 0 : mGraph.at(0).activeLane;
        case RefsRole:
            return QVariant::fromValue(QStringList());
        case IsHeadRole:
            return false;
        }
        return QVariant();
    }

    // Real commit row — offset by synthetic row
    const int realRow = row - syntheticOffset();
    if (realRow < 0 || realRow >= mOids.size())
        return QVariant();

    switch (role)
    {
    case ShaRole:
        return mGraph.at(realRow).sha;

    case MessageRole:
        return fetchDetail(realRow).message;

    case AuthorRole:
        return fetchDetail(realRow).author;

    case TimestampRole:
        return fetchDetail(realRow).timestamp;

    case LanesRole:
        return QVariant::fromValue(lanesToIntList(mGraph.at(realRow).lanes));

    case ActiveLaneRole:
        return mGraph.at(realRow).activeLane;

    case RefsRole: {
        const QString& sha = mGraph.at(realRow).sha;
        return QVariant::fromValue(mRefMap.value(sha));
    }

    case IsHeadRole:
        return mGraph.at(realRow).sha == mHeadSha;
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
        {RefsRole, "refs"},
        {IsHeadRole, "isHead"}
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

            auto result = future.result();

            // Remove synthetic row before clearing real data
            if (mHasSyntheticRow)
                removeSyntheticRow();

            clearModel();

            mHeadSha = result.headSha;

            if (!result.oids.isEmpty())
            {
                const int offset = syntheticOffset();
                beginInsertRows(QModelIndex(), offset, offset + result.oids.size() - 1);
                mOids = std::move(result.oids);
                mGraph = std::move(result.graph);
                mRefMap = std::move(result.refMap);
                endInsertRows();
            }

            // Re-insert synthetic row if repo has uncommitted changes
            updateSyntheticRow();

            mLoading = false;
            emit loadingChanged();
        });
    });

    mLoading = true;
    emit loadingChanged();
    mCache.clear();

    mRestarter.restart([repoPath]() -> QFuture<IndexPassResult> {
        return GitConcurrent::run([repoPath]() -> IndexPassResult {
            return runIndexPass(repoPath);
        });
    });
}

void GitGraphModel::clearModel()
{
    if (!mOids.isEmpty())
    {
        const int offset = syntheticOffset();
        beginRemoveRows(QModelIndex(), offset, offset + mOids.size() - 1);
        mOids.clear();
        mGraph.clear();
        mRefMap.clear();
        mCache.clear();
        endRemoveRows();
    }
}

void GitGraphModel::updateSyntheticRow()
{
    if (!mRepository)
        return;

    bool shouldHaveSyntheticRow = mRepository->modifiedFileCount() > 0;

    if (shouldHaveSyntheticRow && !mHasSyntheticRow)
        insertSyntheticRow();
    else if (!shouldHaveSyntheticRow && mHasSyntheticRow)
        removeSyntheticRow();
}

void GitGraphModel::insertSyntheticRow()
{
    Q_ASSERT(!mHasSyntheticRow);
    beginInsertRows(QModelIndex(), 0, 0);
    mHasSyntheticRow = true;
    endInsertRows();
    emit hasUncommittedChangesChanged();
}

void GitGraphModel::removeSyntheticRow()
{
    Q_ASSERT(mHasSyntheticRow);
    beginRemoveRows(QModelIndex(), 0, 0);
    mHasSyntheticRow = false;
    endRemoveRows();
    emit hasUncommittedChangesChanged();
}

QList<int> GitGraphModel::lanesToIntList(const QVector<GitLane>& lanes)
{
    QList<int> laneTypes;
    laneTypes.reserve(lanes.size());
    for (const auto& lane : lanes)
        laneTypes.append(static_cast<int>(lane.type()));
    return laneTypes;
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
