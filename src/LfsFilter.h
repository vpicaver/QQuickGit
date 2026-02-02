#ifndef LFSFILTER_H
#define LFSFILTER_H

namespace QQuickGit {

class LfsFilter
{
public:
    static int registerFilter();
    static void unregisterFilter();
};

} // namespace QQuickGit

#endif // LFSFILTER_H
