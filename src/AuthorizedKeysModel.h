#ifndef AUTHORIZEDKEYSMODEL_H
#define AUTHORIZEDKEYSMODEL_H

#include <QAbstractListModel>
#include <QObject>
#include <QDebug>
class QFileDevice;

//Our includes
#include "SshUser.h"

namespace QQuickGit {

class Account;

class AuthorizedKeysModel : public QAbstractListModel
{
    Q_OBJECT

    Q_PROPERTY(QString filename READ filename WRITE setFilename NOTIFY filenameChanged)
    Q_PROPERTY(QVector<SshUser> users READ users WRITE setUsers NOTIFY usersChanged)

public:

    enum Roles {
        NameRole,
        EmailRole,
        CommentRole,
        KeyRole,
        UserRole
    };
    Q_ENUM(Roles)

    explicit AuthorizedKeysModel(QObject *parent = nullptr);

    Q_INVOKABLE int rowCount(const QModelIndex &parent = QModelIndex()) const;
    Q_INVOKABLE QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role);
    QHash<int, QByteArray> roleNames() const;

    void addRow(const SshUser& row);
    void removeRow(const QString &key);

    void setUsers(const QVector<SshUser> users);
    QVector<SshUser> users() const;

    void load();
    void save();

    QString filename() const;
    void setFilename(const QString& filename);

    Q_INVOKABLE static QVector<SshUser> toUsers(QString publicKeyData);

signals:
    void filenameChanged();
    void usersChanged();

private:

    QVector<SshUser> mRows;
    QString mFilename; //!<

    int indexOf(const QString& key) const;
    void throwError(const QFileDevice& file) const;
    void checkForFileError(const QFileDevice& file) const;


};


inline QString AuthorizedKeysModel::filename() const {
    return mFilename;
}
}

Q_DECLARE_METATYPE(QVector<QQuickGit::SshUser>)


#endif // AUTHORIZEDKEYSMODEL_H
