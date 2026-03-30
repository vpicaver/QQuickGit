#ifndef GITLANES_H
#define GITLANES_H

//Our includes
#include "QQuickGitExport.h"
#include "GitLaneType.h"
#include "GitLane.h"

//Qt includes
#include <QString>
#include <QVector>

namespace QQuickGit {

/**
 * At any given time, the GitLanes class represents a single revision (row)
 * of the history graph. It contains a vector of the sha1 hashes of the next
 * commit to appear in each lane (column) and a vector of lane types used to
 * decide which glyph to draw.
 *
 * For each revision (from recent to ancient), the GitLanes class is updated
 * and the current row of glyphs is saved via getLanes().
 *
 * Ported from GitQlient's Lanes class (Marco Costalba, 2005-2007).
 */
class QQUICKGIT_EXPORT GitLanes
{
public:
    GitLanes() = default;

    bool isEmpty() const;
    void init(const QString& expectedSha);
    void clear();
    bool isFork(const QString& sha, bool& isDiscontinuity);
    void setFork(const QString& sha);
    void setMerge(const QStringList& parents);
    void setInitial();
    void changeActiveLane(const QString& sha);
    void afterMerge();
    void afterFork();
    bool isBranch() const;
    void afterBranch();
    void nextParent(const QString& sha);

    QVector<GitLane> getLanes() const;

    int activeLaneIndex() const;

private:
    int findNextSha(const QString& next, int pos) const;
    int findType(GitLaneType::Type type, int pos) const;
    int add(GitLaneType::Type type, const QString& next, int pos);
    bool isNode(const GitLane& lane) const;

    int mActiveLane = 0;
    QVector<GitLane> mTypeVec;
    QVector<QString> mNextShaVec;
    GitLaneType::Type mNode = GitLaneType::MergeFork;
    GitLaneType::Type mNodeRight = GitLaneType::MergeForkRight;
    GitLaneType::Type mNodeLeft = GitLaneType::MergeForkLeft;
};

inline bool GitLanes::isEmpty() const {
    return mTypeVec.empty();
}

inline QVector<GitLane> GitLanes::getLanes() const {
    return mTypeVec;
}

inline int GitLanes::activeLaneIndex() const {
    return mActiveLane;
}

}

#endif // GITLANES_H
