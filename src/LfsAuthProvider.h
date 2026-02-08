#ifndef LFSAUTHPROVIDER_H
#define LFSAUTHPROVIDER_H

#include <QByteArray>
#include <QUrl>

namespace QQuickGit {

class LfsAuthProvider
{
public:
    virtual ~LfsAuthProvider() = default;
    virtual QByteArray authorizationHeader(const QUrl& url) const = 0;
};

} // namespace QQuickGit

#endif // LFSAUTHPROVIDER_H
