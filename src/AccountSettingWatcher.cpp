//Our includes
#include "AccountSettingWatcher.h"
#include "Person.h"

//Qt includes
#include <QSettings>
#include <QDebug>
#include <QCoreApplication>
#include <QStandardPaths>
#include <QDir>
#include <QFileInfo>

using namespace QQuickGit;

static QString AccountGroup = QStringLiteral("account");
static QString PhotoUrlKey = QStringLiteral("photo");
static QString NameKey = QStringLiteral("name");
static QString EmailKey = QStringLiteral("email");

AccountSettingWatcher::AccountSettingWatcher(QObject *parent) : QObject(parent)
{
    Q_ASSERT(!QCoreApplication::applicationName().isEmpty());
    Q_ASSERT(!QCoreApplication::organizationDomain().isEmpty());
    Q_ASSERT(!QCoreApplication::organizationName().isEmpty());
}

void AccountSettingWatcher::setPerson(Person *person)
{
    if(mPerson != person) {
        if(!mPerson.isNull()) {
            disconnect(mPerson, nullptr, this, nullptr);
        }

        mPerson = person;

        class AccountSettings : public QSettings {
        public:
            AccountSettings() :
                QSettings(QSettings::UserScope)
            {
                beginGroup(AccountGroup);
            }
            ~AccountSettings() {
                endGroup();
            }
        };

        if(!mPerson.isNull()) {
            AccountSettings settings;
            mPerson->setImage(settings.value(PhotoUrlKey, "qrc:/icons/photoAccount.svg").toUrl());
            mPerson->setName(settings.value(NameKey, QString()).toString());
            mPerson->setEmail(settings.value(EmailKey, QString()).toString());

            connect(mPerson, &Person::imageChanged, this, [this]() {
                AccountSettings settings;
                if(settings.value(PhotoUrlKey).toUrl() != mPerson->image()) {

                    QUrl url = mPerson->image();

                    //Try to copy the image into the app configuration directory
                    if(url.isLocalFile() || url.scheme() == QStringLiteral("qrc")) {
                        QDir appConfigDir(QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation));
                        appConfigDir.mkpath(AccountGroup);
                        appConfigDir.cd(AccountGroup);

                        auto localFilename = [url](){
                            if(url.isLocalFile()) {
                                return url.toLocalFile();
                            } else {
                                Q_ASSERT(url.scheme() == QStringLiteral("qrc"));
                                return url.toString().remove(0, 3); //Remove qrc
                            }
                        }();

                        QFileInfo info(localFilename);
                        Q_ASSERT(info.exists());
                        auto configFilename = appConfigDir.absoluteFilePath(info.fileName());

                        QFile::copy(localFilename, configFilename);
                        url = QUrl::fromLocalFile(configFilename);
                    }

                    settings.setValue(PhotoUrlKey, url);
                    mPerson->setImage(url);
                }
            });

            connect(mPerson, &Person::nameChanged, this, [this]() {
                AccountSettings settings;
                settings.setValue(NameKey, mPerson->name());
            });

            connect(mPerson, &Person::emailChanged, this, [this]() {
                AccountSettings settings;
                settings.setValue(EmailKey, mPerson->email());
            });
        }

        emit personChanged();
    }
}

Person *AccountSettingWatcher::person() const
{
    return mPerson;
}
