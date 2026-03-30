#ifndef GITLANE_H
#define GITLANE_H

//Our includes
#include "QQuickGitExport.h"
#include "GitLaneType.h"

namespace QQuickGit {

class QQUICKGIT_EXPORT GitLane
{
public:
    GitLane() = default;
    GitLane(GitLaneType::Type type);

    bool operator==(const GitLane& other) const;
    bool operator!=(const GitLane& other) const;

    bool isHead() const;
    bool isTail() const;
    bool isJoin() const;
    bool isFreeLane() const;
    bool isMerge() const;
    bool isActive() const;
    bool equals(GitLaneType::Type type) const;

    GitLaneType::Type type() const;
    void setType(GitLaneType::Type type);

private:
    GitLaneType::Type mType = GitLaneType::Empty;
};

inline bool GitLane::operator==(const GitLane& other) const {
    return mType == other.mType;
}

inline bool GitLane::operator!=(const GitLane& other) const {
    return mType != other.mType;
}

inline bool GitLane::equals(GitLaneType::Type type) const {
    return mType == type;
}

inline GitLaneType::Type GitLane::type() const {
    return mType;
}

inline void GitLane::setType(GitLaneType::Type type) {
    mType = type;
}

}

#endif // GITLANE_H
