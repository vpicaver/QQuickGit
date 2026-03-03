#ifndef LFSFILTER_H
#define LFSFILTER_H

#include "QQuickGitExport.h"

namespace QQuickGit {

class QQUICKGIT_EXPORT LfsFilter
{
public:
    static int registerFilter();
    static void unregisterFilter();
};

} // namespace QQuickGit

#endif // LFSFILTER_H
