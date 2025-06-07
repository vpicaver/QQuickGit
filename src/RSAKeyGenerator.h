#ifndef RSAKEYGENERATOR_H
#define RSAKEYGENERATOR_H

//Qt includes
#include <QString>
#include <QList>
#include <QDir>

class RSAKeyGenerator
{
public:
    RSAKeyGenerator();

    void loadOrGenerate();
    void generate(); //Will replace application keys

    QString publicKeyPath() const { return mPublicKeyPath; }
    QString privateKeyPath() const { return mPrivateKeyPath; }

    QString knownHostsPath() const;

    QByteArray publicKey() const;

    static QByteArray defaultPublicKeyFilename() { return QByteArrayLiteral("id_rsa.pub"); }
    static QByteArray defaultPublicKeyPEMFilename() { return QByteArrayLiteral("id_rsa.pem"); }
    static QByteArray defaultPrivateKeyFilename() { return QByteArrayLiteral("id_rsa"); }

    static QDir homeKeyDirectory();
    static QDir appKeyDirectory();

private:
    QString mPublicKeyPath;
    QString mPrivateKeyPath;


};

#endif // RSAKEYGENERATOR_H
