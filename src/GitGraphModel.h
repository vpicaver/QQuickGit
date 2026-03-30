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

class QQUICKGIT_EXPORT GitGraphModel : public QAbstractListModel
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QQuickGit::GitRepository* repository READ repository WRITE setRepository NOTIFY repositoryChanged)
    Q_PROPERTY(bool loading READ loading NOTIFY loadingChanged)

public:
    enum Roles
    {
        ShaRole = Qt::UserRole + 1,
        MessageRole,
        AuthorRole,
        TimestampRole,
        LanesRole,
        ActiveLaneRole,
        RefsRole
    };
    Q_ENUM(Roles)

    explicit GitGraphModel(QObject* parent = nullptr);
    ~GitGraphModel() override;

    GitRepository* repository() const;
    void setRepository(GitRepository* repository);

    bool loading() const;

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void refresh();

signals:
    void repositoryChanged();
    void loadingChanged();

private:
    void clearModel();
    const GitCommitDetail& fetchDetail(int row) const;

    GitRepository* mRepository = nullptr;
    QVector<QByteArray> mOids; //!< raw git_oid bytes (GIT_OID_MAX_SIZE each)
    QVector<GitRowGraph> mGraph;
    QHash<QString, QStringList> mRefMap; //!< sha -> list of ref names
    mutable QHash<int, GitCommitDetail> mCache;
    bool mLoading = false;

    AsyncFuture::Restarter<QVariant> mRestarter;
};

inline GitRepository* GitGraphModel::repository() const {
    return mRepository;
}

inline bool GitGraphModel::loading() const {
    return mLoading;
}

}

#endif // GITGRAPHMODEL_H
