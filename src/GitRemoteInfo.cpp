#include "GitRemoteInfo.h"

using namespace QQuickGit;

GitRemoteInfo::GitRemoteInfo()
{

}

GitRemoteInfo::GitRemoteInfo(QString name, QUrl url) :
    mName(name),
    mUrl(url)
{

}
