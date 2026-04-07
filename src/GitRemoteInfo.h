#ifndef GITREMOTEINFO_H
#define GITREMOTEINFO_H

#include "QQuickGitExport.h"
#include <QObject>
#include <QQmlEngine>
#include <QUrl>

namespace QQuickGit {
class QQUICKGIT_EXPORT GitRemoteInfo
{
    Q_GADGET
    QML_VALUE_TYPE(gitRemoteInfo)

    Q_PROPERTY(QString name READ name)
    Q_PROPERTY(QUrl url READ url)

public:
    GitRemoteInfo();
    GitRemoteInfo(QString name, QUrl url);

    QString name() const;
    QUrl url() const;

    bool operator==(const GitRemoteInfo& other) const {
        return mName == other.mName
                && mUrl == other.mUrl;
    }

    bool operator!=(const GitRemoteInfo& other) const {
        return !operator==(other);
    }

private:
    QString mName; //!<
    QUrl mUrl; //!<
};


inline QString GitRemoteInfo::name() const {
    return mName;
}

inline QUrl GitRemoteInfo::url() const {
    return mUrl;
}
}

Q_DECLARE_METATYPE(QQuickGit::GitRemoteInfo)


#endif // GITREMOTEINFO_H
