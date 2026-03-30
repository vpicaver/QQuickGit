//Our includes
#include "GitLane.h"

using namespace QQuickGit;

GitLane::GitLane(GitLaneType::Type type)
    : mType(type)
{
}

bool GitLane::isHead() const
{
    return mType == GitLaneType::Head
        || mType == GitLaneType::HeadRight
        || mType == GitLaneType::HeadLeft;
}

bool GitLane::isTail() const
{
    return mType == GitLaneType::Tail
        || mType == GitLaneType::TailRight
        || mType == GitLaneType::TailLeft;
}

bool GitLane::isJoin() const
{
    return mType == GitLaneType::Join
        || mType == GitLaneType::JoinRight
        || mType == GitLaneType::JoinLeft;
}

bool GitLane::isFreeLane() const
{
    return mType == GitLaneType::NotActive
        || mType == GitLaneType::Cross
        || isJoin();
}

bool GitLane::isMerge() const
{
    return mType == GitLaneType::MergeFork
        || mType == GitLaneType::MergeForkRight
        || mType == GitLaneType::MergeForkLeft;
}

bool GitLane::isActive() const
{
    return mType == GitLaneType::Active
        || mType == GitLaneType::Initial
        || mType == GitLaneType::Branch
        || isMerge();
}
