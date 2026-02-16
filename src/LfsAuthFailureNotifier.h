#ifndef LFSAUTHFAILURENOTIFIER_H
#define LFSAUTHFAILURENOTIFIER_H

#include <QObject>
#include <QUrl>
#include <QString>

namespace QQuickGit {

class LfsAuthFailureNotifier : public QObject
{
    Q_OBJECT

public:
    static LfsAuthFailureNotifier* instance();

public slots:
    void publish(const QUrl& url, int httpStatus, const QString& message);

signals:
    void authenticationFailed(const QUrl& url, int httpStatus, const QString& message);
};

} // namespace QQuickGit

#endif // LFSAUTHFAILURENOTIFIER_H
