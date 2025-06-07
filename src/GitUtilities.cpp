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

    if(url.isValid()) {
        return url;
    }

    auto parts = sshUrl.split(':');
    if(parts.size() == 2) {
        auto newUrl = QStringLiteral("ssh://") + parts.at(0) + "/" + parts.at(1);
        url = QUrl(newUrl);
    }

    return url;
}

bool GitUtilities::isRemoteNameValid(const QString &remoteName)
{
    return git_remote_is_valid_name(remoteName.toLocal8Bit());
}
