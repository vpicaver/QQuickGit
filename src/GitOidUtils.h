#ifndef GITOIDUTILS_H
#define GITOIDUTILS_H

//Qt includes
#include <QString>

//libgit2
#include "git2.h"

namespace QQuickGit {

inline QString oidToString(const git_oid* oid)
{
    if (!oid)
    {
        return QString();
    }
    char buffer[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(buffer, sizeof(buffer), oid);
    return QString::fromLatin1(buffer);
}

} // namespace QQuickGit

#endif // GITOIDUTILS_H
