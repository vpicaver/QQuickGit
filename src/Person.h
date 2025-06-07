#ifndef PERSON_H
#define PERSON_H

//Qt includes
#include <QObject>
#include <QUrl>

class Person : public QObject
{
    Q_OBJECT

    Q_PROPERTY(QUrl image READ image WRITE setImage NOTIFY imageChanged)
    Q_PROPERTY(QString name READ name WRITE setName NOTIFY nameChanged)
    Q_PROPERTY(QString email READ email WRITE setEmail NOTIFY emailChanged)
    Q_PROPERTY(bool isValid READ isValid NOTIFY isValidChanged)

public:
    Person(QObject* parent = nullptr);

    QUrl image() const;
    void setImage(QUrl image);

    QString name() const;
    void setName(QString name);

    QString email() const;
    void setEmail(const QString email);

    bool isValid() const;

    Q_INVOKABLE static bool isEmailValid(const QString& email);


signals:
    void imageChanged(); //!< Called when the image's value changes
    void nameChanged(); //!< Called when the name's value changes
    void isValidChanged(); //!< Called when the isValid's value changes
    void emailChanged();

private:
    QUrl mImage; //!<
    QString mName; //!<
    QString mEmail;
};

inline QString Person::name() const {
    return mName;
}

inline QUrl Person::image() const {
    return mImage;
}

inline QString Person::email() const {
    return mEmail;
}

inline bool Person::isValid() const {
    return !name().isEmpty() && isEmailValid(email());
}

#endif // PERSON_H
