#include "GitUtilities.h"
#include "git2.h"

using namespace QQuickGit;

GitUtilities::GitUtilities(QObject *parent) : QObject(parent)
{

}

//This will try to fix the URL. Url from github and gitlab
//have ssh urls git@github.com:Cavewhere/cavewhere.git
//This isn't a valid QUrl and should be converted into ssh://git@github.com/Cavewhere/cavewhere.git
QUrl GitUtilities::fixGitUrl(const QString &sshUrl)
{
    QUrl url(sshUrl);

    if(url.isValid() && !url.scheme().isEmpty()) {
        return url;
    }

    auto parts = sshUrl.split(':');
    if(parts.size() == 2) {
        auto newUrl = QStringLiteral("ssh://") + parts.at(0) + "/" + parts.at(1);
        url = QUrl(newUrl);
    }

    return url;
}

QUrl GitUtilities::lfsEndpointFromRemoteUrl(const QString& remoteUrl)
{
    QUrl url = fixGitUrl(remoteUrl.trimmed());
    if (!url.isValid() || url.scheme().isEmpty()) {
        return QUrl();
    }

    const QString scheme = url.scheme().toLower();
    if (scheme == QStringLiteral("ssh") || scheme == QStringLiteral("git")) {
        QUrl httpsUrl(url);
        httpsUrl.setScheme(QStringLiteral("https"));
        httpsUrl.setUserName(QString());
        httpsUrl.setPassword(QString());
        url = httpsUrl;
    }

    const QString normalizedScheme = url.scheme().toLower();
    if (normalizedScheme != QStringLiteral("http") && normalizedScheme != QStringLiteral("https")) {
        return QUrl();
    }

    QString path = url.path();
    while (path.endsWith('/')) {
        path.chop(1);
    }
    path += QStringLiteral("/info/lfs");
    url.setPath(path);

    return url;
}

bool GitUtilities::isRemoteNameValid(const QString &remoteName)
{
    return git_remote_is_valid_name(remoteName.toLocal8Bit());
}
