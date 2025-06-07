#include "Account.h"

Account::Account(QObject *parent) : Person(parent)
{
    mKeys.loadOrGenerate();

    connect(this, &Account::nameChanged, this, &Account::sshUserChanged);
    connect(this, &Account::emailChanged, this, &Account::sshUserChanged);
}

QByteArray Account::publicKey() const
{
    return mKeys.publicKey();
}



SshUser Account::sshUser() const
{
    auto users = AuthorizedKeysModel::toUsers(publicKey());
    if(!users.isEmpty() && users.first().isValid()) {
        auto user = users.first();
        return SshUser(name(), email(), user.comment(), user.key());
    } else {
        return SshUser();
    }
}
