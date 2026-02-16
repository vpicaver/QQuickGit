#include "LfsAuthFailureNotifier.h"

namespace QQuickGit {

LfsAuthFailureNotifier* LfsAuthFailureNotifier::instance()
{
    static LfsAuthFailureNotifier notifier;
    return &notifier;
}

void LfsAuthFailureNotifier::publish(const QUrl& url, int httpStatus, const QString& message)
{
    emit authenticationFailed(url, httpStatus, message);
}

} // namespace QQuickGit
