#include "GitRemotesModel.h"

using namespace QQuickGit;

GitRemotesModel::GitRemotesModel(QObject *parent) : QAbstractListModel(parent)
{

}


int GitRemotesModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return mRemotes.size();
}

QVariant GitRemotesModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid()) {
        return QVariant();
    }

    const auto& remote = mRemotes.at(index.row());

    switch (role) {
    case NameRole:
        return remote.name();
    case UrlRole:
        return remote.url();
    }

    return QVariant();
}

QHash<int, QByteArray> GitRemotesModel::roleNames() const
{
    const static QHash<int, QByteArray> roles {
        {NameRole, QByteArrayLiteral("nameRole")},
        {UrlRole, QByteArrayLiteral("urlRole")}
    };
    return roles;
}

void GitRemotesModel::setRemotes(QVector<GitRemoteInfo> remotes) {
    if(mRemotes != remotes) {
        beginResetModel();
        mRemotes = remotes;
        endResetModel();
        emit remotesChanged();
        emit countChanged();
    }
}
