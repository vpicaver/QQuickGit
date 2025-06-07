#ifndef SSHUSER_H
#define SSHUSER_H

//Qt includes
#include <QString>
#include <QObject>

class SshUser {
    Q_GADGET

    Q_PROPERTY(QString name READ name WRITE setName)
    Q_PROPERTY(QString email READ email WRITE setEmail)
    Q_PROPERTY(QString key READ key WRITE setKey)
    Q_PROPERTY(QString comment READ comment WRITE setComment)

public:
    SshUser() = default;
    SshUser(const QString& key) :
        mKey(key)
    {
    }

    SshUser(const QString& name,
            const QString& email,
            const QString& comment,
            const QString& key) :
        mName(name),
        mEmail(email),
        mComment(comment),
        mKey(key)
    {
    }

    QString name() const { return mName; }
    QString email() const { return mEmail; }
    QString comment() const { return mComment; }
    QString key() const { return mKey; }

    void setName(const QString& name) {
        mName = name;
    }

    void setEmail(const QString& email) {
        mEmail = email;
    }

    void setComment(const QString& comment) {
        mComment = comment;
    }

    void setKey(const QString& key) {
        mKey = key;
    }

    Q_INVOKABLE bool isValid() const {
        return keyValid();
    }

    static bool keyValid(const QString& key);
    bool keyValid() const {
        return keyValid(key());
    }

    bool operator==(const SshUser& other) const {
        return mKey == other.key();
    }

    bool operator!=(const SshUser& other) const {
        return !operator==(other);
    }

    static QString nameKey() { return QStringLiteral("name"); }
    static QString emailKey() { return QStringLiteral("email"); }

    Q_INVOKABLE QString toString() const;


private:
    QString mName;
    QString mEmail;
    QString mComment;
    QString mKey;
};

Q_DECLARE_METATYPE(SshUser);

#endif // SSHUSER_H
