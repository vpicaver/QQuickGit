//Our includes
#include "GitLanes.h"

//Qt includes
#include <QStringList>

using namespace QQuickGit;

void GitLanes::init(const QString& expectedSha)
{
    clear();
    mActiveLane = 0;
    add(GitLaneType::Branch, expectedSha, mActiveLane);
}

void GitLanes::clear()
{
    mTypeVec.clear();
    mTypeVec.squeeze();
    mNextShaVec.clear();
    mNextShaVec.squeeze();
}

bool GitLanes::isFork(const QString& sha, bool& isDiscontinuity)
{
    int pos = findNextSha(sha, 0);
    isDiscontinuity = mActiveLane != pos;

    return pos == -1 ? false : findNextSha(sha, pos + 1) != -1;
}

void GitLanes::setFork(const QString& sha)
{
    auto rangeEnd = 0;
    auto idx = 0;
    auto rangeStart = rangeEnd = idx = findNextSha(sha, 0);

    while (idx != -1)
    {
        rangeEnd = idx;
        mTypeVec[idx].setType(GitLaneType::Tail);
        idx = findNextSha(sha, idx + 1);
    }

    mTypeVec[mActiveLane].setType(mNode);

    auto& startT = mTypeVec[rangeStart];
    auto& endT = mTypeVec[rangeEnd];

    if (startT.equals(mNode))
        startT.setType(mNodeLeft);

    if (endT.equals(mNode))
        endT.setType(mNodeRight);

    if (startT.equals(GitLaneType::Tail))
        startT.setType(GitLaneType::TailLeft);

    if (endT.equals(GitLaneType::Tail))
        endT.setType(GitLaneType::TailRight);

    for (int i = rangeStart + 1; i < rangeEnd; ++i)
    {
        auto& t = mTypeVec[i];
        switch (t.type())
        {
        case GitLaneType::NotActive:
            t.setType(GitLaneType::Cross);
            break;
        case GitLaneType::Empty:
            t.setType(GitLaneType::CrossEmpty);
            break;
        default:
            break;
        }
    }
}

void GitLanes::setMerge(const QStringList& parents)
{
    auto& t = mTypeVec[mActiveLane];
    auto wasFork = t.equals(mNode);
    auto wasForkLeft = t.equals(mNodeLeft);
    auto wasForkRight = t.equals(mNodeRight);
    auto startJoinWasACross = false;
    auto endJoinWasACross = false;

    t.setType(mNode);

    auto rangeStart = mActiveLane;
    auto rangeEnd = mActiveLane;
    QStringList::const_iterator it(parents.constBegin());

    for (++it; it != parents.constEnd(); ++it)
    {
        // skip first parent
        int idx = findNextSha(*it, 0);

        if (idx != -1)
        {
            if (idx > rangeEnd)
            {
                rangeEnd = idx;
                endJoinWasACross = mTypeVec[idx].equals(GitLaneType::Cross);
            }

            if (idx < rangeStart)
            {
                rangeStart = idx;
                startJoinWasACross = mTypeVec[idx].equals(GitLaneType::Cross);
            }

            mTypeVec[idx].setType(GitLaneType::Join);
        }
        else
        {
            rangeEnd = add(GitLaneType::Head, *it, rangeEnd + 1);
        }
    }

    auto& startT = mTypeVec[rangeStart];
    auto& endT = mTypeVec[rangeEnd];

    if (startT.equals(mNode) && !wasFork && !wasForkRight)
        startT.setType(mNodeLeft);

    if (endT.equals(mNode) && !wasFork && !wasForkLeft)
        endT.setType(mNodeRight);

    if (startT.equals(GitLaneType::Join) && !startJoinWasACross)
        startT.setType(GitLaneType::JoinLeft);

    if (endT.equals(GitLaneType::Join) && !endJoinWasACross)
        endT.setType(GitLaneType::JoinRight);

    if (startT.equals(GitLaneType::Head))
        startT.setType(GitLaneType::HeadLeft);

    if (endT.equals(GitLaneType::Head))
        endT.setType(GitLaneType::HeadRight);

    for (int i = rangeStart + 1; i < rangeEnd; i++)
    {
        auto& innerT = mTypeVec[i];

        if (innerT.equals(GitLaneType::NotActive))
            innerT.setType(GitLaneType::Cross);
        else if (innerT.equals(GitLaneType::Empty))
            innerT.setType(GitLaneType::CrossEmpty);
        else if (innerT.equals(GitLaneType::TailRight) || innerT.equals(GitLaneType::TailLeft))
            innerT.setType(GitLaneType::Tail);
    }
}

void GitLanes::setInitial()
{
    mTypeVec[mActiveLane].setType(GitLaneType::Initial);
}

void GitLanes::changeActiveLane(const QString& sha)
{
    auto& t = mTypeVec[mActiveLane];

    if (t.equals(GitLaneType::Initial))
        t.setType(GitLaneType::Empty);
    else
        t.setType(GitLaneType::NotActive);

    int idx = findNextSha(sha, 0);
    if (idx != -1)
        mTypeVec[idx].setType(GitLaneType::Active);
    else
        idx = add(GitLaneType::Branch, sha, mActiveLane);

    mActiveLane = idx;
}

void GitLanes::afterMerge()
{
    for (int i = 0; i < mTypeVec.count(); i++)
    {
        auto& t = mTypeVec[i];

        if (t.isHead() || t.isJoin() || t.equals(GitLaneType::Cross))
            t.setType(GitLaneType::NotActive);
        else if (t.equals(GitLaneType::CrossEmpty))
            t.setType(GitLaneType::Empty);
        else if (isNode(t))
            t.setType(GitLaneType::Active);
    }
}

void GitLanes::afterFork()
{
    for (int i = 0; i < mTypeVec.count(); i++)
    {
        auto& t = mTypeVec[i];

        if (t.equals(GitLaneType::Cross))
            t.setType(GitLaneType::NotActive);
        else if (t.isTail() || t.equals(GitLaneType::CrossEmpty))
            t.setType(GitLaneType::Empty);

        if (isNode(t))
            t.setType(GitLaneType::Active);
    }

    while (mTypeVec.last().equals(GitLaneType::Empty))
    {
        mTypeVec.pop_back();
        mNextShaVec.pop_back();
    }
}

bool GitLanes::isBranch() const
{
    if (mTypeVec.count() > mActiveLane)
        return mTypeVec.at(mActiveLane).equals(GitLaneType::Branch);

    return false;
}

void GitLanes::afterBranch()
{
    mTypeVec[mActiveLane].setType(GitLaneType::Active);
}

void GitLanes::nextParent(const QString& sha)
{
    mNextShaVec[mActiveLane] = sha;
}

int GitLanes::findNextSha(const QString& next, int pos) const
{
    for (int i = pos; i < mNextShaVec.count(); i++)
    {
        if (mNextShaVec[i] == next)
            return i;
    }

    return -1;
}

int GitLanes::findType(GitLaneType::Type type, int pos) const
{
    const auto typeVecCount = mTypeVec.count();

    for (int i = pos; i < typeVecCount; i++)
    {
        if (mTypeVec[i].equals(type))
            return i;
    }

    return -1;
}

int GitLanes::add(GitLaneType::Type type, const QString& next, int pos)
{
    if (pos < mTypeVec.count())
    {
        pos = findType(GitLaneType::Empty, pos);
        if (pos != -1)
        {
            mTypeVec[pos].setType(type);
            mNextShaVec[pos] = next;
            return pos;
        }
    }

    mTypeVec.append(GitLane(type));
    mNextShaVec.append(next);
    return mTypeVec.count() - 1;
}

bool GitLanes::isNode(const GitLane& lane) const
{
    return lane.equals(mNode) || lane.equals(mNodeRight) || lane.equals(mNodeLeft);
}
