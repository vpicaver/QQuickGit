#ifndef GITUTILITIES_H
#define GITUTILITIES_H

//Qt includes
#include "QQuickGitExport.h"
#include <QObject>
#include <QString>
#include <QUrl>

namespace QQuickGit {
class QQUICKGIT_EXPORT GitUtilities : public QObject
{
    Q_OBJECT

public:
    explicit GitUtilities(QObject *parent = nullptr);

    Q_INVOKABLE static QUrl fixGitUrl(const QString& sshUrl);
    Q_INVOKABLE static QUrl lfsEndpointFromRemoteUrl(const QString& remoteUrl);
    Q_INVOKABLE static bool isRemoteNameValid(const QString& remoteName);
    Q_INVOKABLE static void copyToClipboard(const QString& text);

signals:

};
};

#endif // GITUTILITIES_H
