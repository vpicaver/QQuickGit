#ifndef GITREMOTESMODEL_H
#define GITREMOTESMODEL_H

//Qt includes
#include <QAbstractListModel>
#include <QVector>

//Our includes
#include "GitRemoteInfo.h"

class GitRemotesModel : public QAbstractListModel
{
    Q_OBJECT

    Q_PROPERTY(QVector<GitRemoteInfo> remotes READ remotes WRITE setRemotes NOTIFY remotesChanged)
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    enum Roles {
        NameRole,
        UrlRole
    };
    Q_ENUM(Roles);

    explicit GitRemotesModel(QObject *parent = nullptr);

    QVector<GitRemoteInfo> remotes() const;
    void setRemotes(QVector<GitRemoteInfo> remotes);

    int count() const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role) const;
    QHash<int, QByteArray> roleNames() const;

signals:
    void remotesChanged();
    void countChanged();

private:
    QVector<GitRemoteInfo> mRemotes; //!<
};

inline QVector<GitRemoteInfo> GitRemotesModel::remotes() const {
    return mRemotes;
}

inline int GitRemotesModel::count() const {
    return mRemotes.size();
}

#endif // GITREMOTESMODEL_H
