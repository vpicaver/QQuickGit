#ifndef ACCOUNTSETTINGWATCHER_H
#define ACCOUNTSETTINGWATCHER_H

//Qt includes
#include <QObject>
#include <QPointer>

//Our includes
class Person;

class AccountSettingWatcher : public QObject
{
    Q_OBJECT

    Q_PROPERTY(Person* person READ person WRITE setPerson NOTIFY personChanged)

public:
    explicit AccountSettingWatcher(QObject *parent = nullptr);

    void setPerson(Person* person);
    Person* person() const;

signals:
    void personChanged();

private:
    QPointer<Person> mPerson;

};

#endif // ACCOUNTSETTINGWATCHER_H
