#ifndef GITLANETYPE_H
#define GITLANETYPE_H

//Qt includes
#include <QObject>
#include <QQmlEngine>

//Our includes
#include "QQuickGitExport.h"

namespace QQuickGit {

class QQUICKGIT_EXPORT GitLaneType
{
    Q_GADGET
    QML_ELEMENT

public:
    enum Type
    {
        Empty,
        Active,
        NotActive,
        MergeFork,
        MergeForkRight,
        MergeForkLeft,
        Join,
        JoinRight,
        JoinLeft,
        Head,
        HeadRight,
        HeadLeft,
        Tail,
        TailRight,
        TailLeft,
        Cross,
        CrossEmpty,
        Initial,
        Branch
    };
    Q_ENUM(Type)
};

}

#endif // GITLANETYPE_H
