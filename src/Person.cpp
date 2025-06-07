#include "Person.h"

//Qt includes
#include <QRegularExpression>

Person::Person(QObject *parent) :
    QObject(parent)
{

}

void Person::setImage(QUrl image) {
    if(mImage != image) {
        mImage = image;
        emit imageChanged();
    }
}

void Person::setName(QString name) {
    if(mName != name) {
        mName = name;
        emit nameChanged();
        emit isValidChanged();
    }
}

void Person::setEmail(QString email)
{
    if(mEmail != email) {
        mEmail = email;
        emit emailChanged();
        emit isValidChanged();
    }
}

bool Person::isEmailValid(const QString &email)
{
    //Regex from stackoverflow: https://stackoverflow.com/questions/201323/how-to-validate-an-email-address-using-a-regular-expression
    QRegularExpression expression("(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])");
    return expression.match(email).hasMatch();
}
