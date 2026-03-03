#ifndef SSHLFSAUTHENTICATOR_H
#define SSHLFSAUTHENTICATOR_H

#include "QQuickGitExport.h"

#include <QMap>
#include <QFuture>
#include <QUrl>

#include "Monad/Result.h"

namespace QQuickGit {

class QQUICKGIT_EXPORT SshLfsAuthenticator
{
public:
    enum class Operation {
        Download,
        Upload
    };

    struct AuthResult {
        QUrl href;
        QMap<QByteArray, QByteArray> headers;
    };

    static QFuture<Monad::Result<AuthResult>> authenticate(const QString& remoteUrl, Operation operation);
};

} // namespace QQuickGit

#endif // SSHLFSAUTHENTICATOR_H
