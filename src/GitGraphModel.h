#ifndef GITGRAPHMODEL_H
#define GITGRAPHMODEL_H

//Our includes
#include "QQuickGitExport.h"
#include "GitRowGraph.h"
#include "GitLaneType.h"

//Async Future includes
#include "asyncfuture.h"

//Qt includes
#include <QAbstractListModel>
#include <QQmlEngine>
#include <QDateTime>
#include <QHash>
#include <QStringList>
#include <QByteArray>

namespace QQuickGit {

class GitRepository;

struct GitCommitDetail
{
    QString message;
    QString author;
    QDateTime timestamp;
};

struct IndexPassResult
{
    QVector<QByteArray> oids;
    QVector<GitRowGraph> graph;
    QHash<QString, QStringList> refMap;
    QString headSha;
};

class QQUICKGIT_EXPORT GitGraphModel : public QAbstractListModel
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QQuickGit::GitRepository* repository READ repository WRITE setRepository NOTIFY repositoryChanged)
    Q_PROPERTY(bool loading READ loading NOTIFY loadingChanged)
    Q_PROPERTY(bool hasUncommittedChanges READ hasUncommittedChanges NOTIFY hasUncommittedChangesChanged)

public:
    enum Roles
    {
        ShaRole = Qt::UserRole + 1,
        MessageRole,
        AuthorRole,
        TimestampRole,
        LanesRole,
        ActiveLaneRole,
        RefsRole,
        IsHeadRole
    };
    Q_ENUM(Roles)

    explicit GitGraphModel(QObject* parent = nullptr);
    ~GitGraphModel() override;

    GitRepository* repository() const;
    void setRepository(GitRepository* repository);

    bool loading() const;
    bool hasUncommittedChanges() const;
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void refresh();

signals:
    void repositoryChanged();
    void loadingChanged();
    void hasUncommittedChangesChanged();

private:
    void clearModel();
    void updateSyntheticRow();
    void insertSyntheticRow();
    void removeSyntheticRow();
    int syntheticOffset() const;
    static QList<int> lanesToIntList(const QVector<GitLane>& lanes);
    const GitCommitDetail& fetchDetail(int row) const;

    GitRepository* mRepository = nullptr;
    QVector<QByteArray> mOids; //!< raw git_oid bytes (GIT_OID_MAX_SIZE each)
    QVector<GitRowGraph> mGraph;
    QHash<QString, QStringList> mRefMap; //!< sha -> list of ref names
    mutable QHash<int, GitCommitDetail> mCache;
    bool mLoading = false;
    bool mHasSyntheticRow = false;
    QString mHeadSha;

    AsyncFuture::Restarter<IndexPassResult> mRestarter;
};

inline GitRepository* GitGraphModel::repository() const {
    return mRepository;
}

inline bool GitGraphModel::loading() const {
    return mLoading;
}

inline bool GitGraphModel::hasUncommittedChanges() const {
    return mHasSyntheticRow;
}

inline int GitGraphModel::syntheticOffset() const {
    return mHasSyntheticRow ? 1 : 0;
}

}

#endif // GITGRAPHMODEL_H
