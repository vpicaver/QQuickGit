#ifndef GITTESTCONNECTION_H
#define GITTESTCONNECTION_H

#include "QQuickGitExport.h"
#include <QObject>
#include <QQmlEngine>
#include <QUrl>
#include <QFuture>

namespace QQuickGit {

class QQUICKGIT_EXPORT GitTestConnection : public QObject
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QUrl url READ url WRITE setUrl NOTIFY urlChanged)
    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY errorMessageChanged)

public:
    enum State {
        Ready,
        Testing
    };
    Q_ENUM(State);

    GitTestConnection(QObject* parent = nullptr);

    QUrl url() const;
    void setUrl(QUrl url);

    State state() const;

    QString errorMessage() const;

    Q_INVOKABLE void test();

signals:
    void urlChanged();
    void stateChanged();
    void errorMessageChanged();
    void finished();

private:
    QUrl mUrl; //!<
    State mState = Ready; //!<
    QString mErrorMessage; //!<

};

inline QUrl GitTestConnection::url() const {
    return mUrl;
}

inline GitTestConnection::State GitTestConnection::state() const {
    return mState;
}

/**
* @brief GitTestConnection::errorMessage
* @return
*/
inline QString GitTestConnection::errorMessage() const {
    return mErrorMessage;
}
}

#endif // GITTESTCONNECTION_H
