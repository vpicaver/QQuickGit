#ifndef GITROWGRAPH_H
#define GITROWGRAPH_H

//Our includes
#include "QQuickGitExport.h"
#include "GitLane.h"

//Qt includes
#include <QString>
#include <QVector>

namespace QQuickGit {

struct QQUICKGIT_EXPORT GitRowGraph
{
    QString sha;
    QVector<GitLane> lanes;
    int activeLane = 0;
};

}

#endif // GITROWGRAPH_H
