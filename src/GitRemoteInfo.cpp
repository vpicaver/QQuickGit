#include "GitRemoteInfo.h"

GitRemoteInfo::GitRemoteInfo()
{

}

GitRemoteInfo::GitRemoteInfo(QString name, QUrl url) :
    mName(name),
    mUrl(url)
{

}
