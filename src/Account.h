#ifndef ACCOUNT_H
#define ACCOUNT_H

#include "Person.h"
#include "RSAKeyGenerator.h"
#include "AuthorizedKeysModel.h"

namespace QQuickGit {

class Account : public Person
{
    Q_OBJECT

    Q_PROPERTY(QByteArray publicKey READ publicKey CONSTANT)    
    Q_PROPERTY(SshUser sshUser READ sshUser NOTIFY sshUserChanged)

public:
    explicit Account(QObject *parent = nullptr);

    QByteArray publicKey() const;

    SshUser sshUser() const;

signals:
    void sshUserChanged();


private:
    RSAKeyGenerator mKeys;
};

}

#endif // ACCOUNT_H
