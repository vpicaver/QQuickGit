#ifndef GITUTILITIES_H
#define GITUTILITIES_H

//Qt includes
#include <QObject>
#include <QString>
#include <QUrl>

namespace QQuickGit {
class GitUtilities : public QObject
{
    Q_OBJECT

public:
    explicit GitUtilities(QObject *parent = nullptr);

    Q_INVOKABLE static QUrl fixGitUrl(const QString& sshUrl);
    Q_INVOKABLE static QUrl lfsEndpointFromRemoteUrl(const QString& remoteUrl);
    Q_INVOKABLE static bool isRemoteNameValid(const QString& remoteName);

signals:

};
};

#endif // GITUTILITIES_H
