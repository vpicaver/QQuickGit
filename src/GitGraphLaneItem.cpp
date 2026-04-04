//Our includes
#include "GitGraphLaneItem.h"
#include "GitLaneType.h"

//Qt includes
#include <QCanvasPainterItemRenderer>
#include <QCanvasPainter>

using namespace QQuickGit;

namespace {

using LT = GitLaneType::Type;

bool hasTopLine(int type)
{
    switch (type)
    {
    case LT::Active:
    case LT::NotActive:
    case LT::MergeFork:
    case LT::MergeForkLeft:
    case LT::MergeForkRight:
    case LT::Tail:
    case LT::TailLeft:
    case LT::TailRight:
    case LT::Join:
    case LT::JoinLeft:
    case LT::JoinRight:
    case LT::Cross:
    case LT::Initial:
        return true;
    default:
        return false;
    }
}

bool hasBottomLine(int type)
{
    switch (type)
    {
    case LT::Active:
    case LT::NotActive:
    case LT::MergeFork:
    case LT::MergeForkLeft:
    case LT::MergeForkRight:
    case LT::Head:
    case LT::HeadLeft:
    case LT::HeadRight:
    case LT::Join:
    case LT::JoinLeft:
    case LT::JoinRight:
    case LT::Cross:
    case LT::Branch:
        return true;
    default:
        return false;
    }
}

bool isHeadType(int type)
{
    return type == LT::Head || type == LT::HeadLeft || type == LT::HeadRight;
}

bool isTailType(int type)
{
    return type == LT::Tail || type == LT::TailLeft || type == LT::TailRight;
}

bool isJoinType(int type)
{
    return type == LT::Join || type == LT::JoinLeft || type == LT::JoinRight;
}

bool isMergeForkSide(int type)
{
    return type == LT::MergeForkLeft || type == LT::MergeForkRight;
}

} // anonymous namespace

class GitGraphLaneRenderer : public QCanvasPainterItemRenderer
{
public:
    void synchronize(QCanvasPainterItem* item) override;
    void paint(QCanvasPainter* painter) override;

private:
    QList<int> mLanes;
    int mActiveLane = 0;
    QList<QColor> mColors;
    float mLaneWidth = 12.0f;
    float mNodeRadius = 4.0f;
    float mLineWidth = 2.0f;
    GitGraphLaneItem::RowPosition mRowPosition = GitGraphLaneItem::Middle;
};

static const char* laneTypeName(int type)
{
    using LaneType = GitLaneType::Type;
    switch (type)
    {
    case LaneType::Empty:          return "Empty";
    case LaneType::Active:         return "Active";
    case LaneType::NotActive:      return "NotActive";
    case LaneType::MergeFork:      return "MergeFork";
    case LaneType::MergeForkRight: return "MergeForkRight";
    case LaneType::MergeForkLeft:  return "MergeForkLeft";
    case LaneType::Join:           return "Join";
    case LaneType::JoinRight:      return "JoinRight";
    case LaneType::JoinLeft:       return "JoinLeft";
    case LaneType::Head:           return "Head";
    case LaneType::HeadRight:      return "HeadRight";
    case LaneType::HeadLeft:       return "HeadLeft";
    case LaneType::Tail:           return "Tail";
    case LaneType::TailRight:      return "TailRight";
    case LaneType::TailLeft:       return "TailLeft";
    case LaneType::Cross:          return "Cross";
    case LaneType::CrossEmpty:     return "CrossEmpty";
    case LaneType::Initial:        return "Initial";
    case LaneType::Branch:         return "Branch";
    default:                       return "Unknown";
    }
}

void GitGraphLaneRenderer::synchronize(QCanvasPainterItem* item)
{
    auto* laneItem = static_cast<GitGraphLaneItem*>(item);
    mLanes = laneItem->lanes();
    mActiveLane = laneItem->activeLane();
    mColors = laneItem->colors();
    mLaneWidth = static_cast<float>(laneItem->laneWidth());
    mNodeRadius = static_cast<float>(laneItem->nodeRadius());
    mLineWidth = static_cast<float>(laneItem->lineWidth());
    mRowPosition = laneItem->rowPosition();

    QStringList laneNames;
    for (int l : mLanes)
        laneNames << laneTypeName(l);
    qDebug() << "LaneRenderer activeLane=" << mActiveLane
             << "rowPos=" << static_cast<int>(mRowPosition)
             << "laneWidth=" << mLaneWidth
             << "lanes=" << laneNames.join(", ");
}

void GitGraphLaneRenderer::paint(QCanvasPainter* painter)
{
    const float h = height();
    const float midY = h / 2.0f;
    const float lw = mLaneWidth;
    const int laneCount = mLanes.size();

    painter->clearRect(0, 0, width(), h);

    if (laneCount == 0 || mColors.isEmpty())
        return;

    painter->setRenderHint(QCanvasPainter::RenderHint::Antialiasing);
    painter->setLineWidth(mLineWidth);

    const float activeCX = mActiveLane * lw + lw / 2.0f;
    const int colorCount = mColors.size();

    using RP = GitGraphLaneItem::RowPosition;
    const bool suppressTop = (mRowPosition == RP::First || mRowPosition == RP::Only);
    const bool suppressBottom = (mRowPosition == RP::Last || mRowPosition == RP::Only);

    for (int i = 0; i < laneCount; ++i)
    {
        const int type = mLanes[i];
        if (type == LT::Empty || type == LT::CrossEmpty)
            continue;

        const float cx = i * lw + lw / 2.0f;
        const QColor color = mColors[i % colorCount];

        painter->setStrokeStyle(color);

        const bool isCurvedLane = (i != mActiveLane) &&
            (isHeadType(type) || isTailType(type) || isJoinType(type));

        if (isCurvedLane)
        {
            if (isHeadType(type))
            {
                // Head lanes: S-curve downward from the commit dot to
                // this lane. No straight segments — the curve IS the line.
                if (!suppressBottom)
                {
                    painter->beginPath();
                    painter->moveTo(activeCX, midY);
                    painter->bezierCurveTo(activeCX, h, cx, midY, cx, h);
                    painter->stroke();
                }
            }
            else if (isJoinType(type))
            {
                // Join lanes: the lane continues both above and below the dot.
                // Draw straight pass-through lines plus a curve branching to the dot.

                // Straight top line
                if (!suppressTop)
                {
                    painter->beginPath();
                    painter->moveTo(cx, 0);
                    painter->lineTo(cx, midY);
                    painter->stroke();
                }

                // Curve from the bottom of the lane up to the dot
                if (!suppressBottom)
                {
                    // painter->setFillStyle(Qt::red);
                    // painter->beginPath();
                    // painter->circle(cx, h, mNodeRadius+1.0);
                    // painter->fill();

                    // painter->setFillStyle(Qt::green);
                    // painter->beginPath();
                    // painter->circle(activeCX, midY, mNodeRadius+1.0);
                    // painter->fill();

                    // painter->setFillStyle(Qt::blue);
                    // painter->beginPath();
                    // painter->circle(cx, midY, mNodeRadius+1.0);
                    // painter->fill();

                    painter->beginPath();
                    painter->moveTo(cx, h);
                    painter->bezierCurveTo(cx, midY, activeCX, h, activeCX, midY);
                    painter->stroke();
                }

                // Straight bottom line (lane continues below)
                if (!suppressBottom)
                {
                    painter->beginPath();
                    painter->moveTo(cx, midY);
                    painter->lineTo(cx, h);
                    painter->stroke();
                }
            }
            else // isTailType
            {
                // Tail lanes: the lane only comes from above and terminates here.
                // Draw a top line plus a curve from the top down to the dot.

                // // Straight top line
                // if (!suppressTop)
                // {
                //     painter->beginPath();
                //     painter->moveTo(cx, 0);
                //     painter->lineTo(cx, midY);
                //     painter->stroke();
                // }

                // Curve from the top of the lane down to the dot
                if (!suppressTop)
                {
                    // painter->setFillStyle(QColor(180, 0, 0)); // dark red
                    // painter->beginPath();
                    // painter->circle(cx, 0, mNodeRadius+1.0);
                    // painter->fill();

                    // painter->setFillStyle(QColor(0, 180, 0)); // dark green
                    // painter->beginPath();
                    // painter->circle(activeCX, midY, mNodeRadius+1.0);
                    // painter->fill();

                    // painter->setFillStyle(QColor(0, 0, 180)); // dark blue
                    // painter->beginPath();
                    // painter->circle(cx, midY, mNodeRadius+1.0);
                    // painter->fill();

                    painter->beginPath();
                    painter->moveTo(cx, 0);
                    painter->bezierCurveTo(cx, midY, activeCX, 0, activeCX, midY);
                    painter->stroke();
                }
            }
        }
        else
        {
            if (hasTopLine(type) && !suppressTop)
            {
                painter->beginPath();
                painter->moveTo(cx, 0);
                painter->lineTo(cx, midY);
                painter->stroke();
            }

            if (hasBottomLine(type) && !suppressBottom)
            {
                painter->beginPath();
                painter->moveTo(cx, midY);
                painter->lineTo(cx, h);
                painter->stroke();
            }

            // MergeFork side lanes draw a horizontal connection to the active lane
            if (isMergeForkSide(type) && i != mActiveLane)
            {
                painter->beginPath();
                painter->moveTo(cx, midY);
                painter->lineTo(activeCX, midY);
                painter->stroke();
            }
        }
    }

    // Draw commit node at the active lane
    if (mActiveLane >= 0 && mActiveLane < laneCount)
    {
        const QColor activeColor = mColors[mActiveLane % mColors.size()];

        // Outer filled circle
        painter->setFillStyle(activeColor);
        painter->beginPath();
        painter->circle(activeCX, midY, mNodeRadius);
        painter->fill();

        // Inner highlight for depth
        painter->setFillStyle(QColor(255, 255, 255));
        painter->beginPath();
        painter->circle(activeCX, midY, mNodeRadius * 0.4f);
        painter->fill();
    }
}

// --- GitGraphLaneItem implementation ---

GitGraphLaneItem::GitGraphLaneItem(QQuickItem* parent)
    : QCanvasPainterItem(parent)
{
    setFillColor(Qt::transparent);
    setAlphaBlending(true);
}

void GitGraphLaneItem::setLanes(const QList<int>& lanes)
{
    if (mLanes == lanes)
        return;
    mLanes = lanes;
    emit lanesChanged();
    update();
}

void GitGraphLaneItem::setActiveLane(int activeLane)
{
    if (mActiveLane == activeLane)
        return;
    mActiveLane = activeLane;
    emit activeLaneChanged();
    update();
}

void GitGraphLaneItem::setColors(const QList<QColor>& colors)
{
    if (mColors == colors)
        return;
    mColors = colors;
    emit colorsChanged();
    update();
}

void GitGraphLaneItem::setLaneWidth(qreal width)
{
    if (qFuzzyCompare(mLaneWidth, width))
        return;
    mLaneWidth = width;
    emit laneWidthChanged();
    update();
}

void GitGraphLaneItem::setNodeRadius(qreal radius)
{
    if (qFuzzyCompare(mNodeRadius, radius))
        return;
    mNodeRadius = radius;
    emit nodeRadiusChanged();
    update();
}

void GitGraphLaneItem::setLineWidth(qreal width)
{
    if (qFuzzyCompare(mLineWidth, width))
        return;
    mLineWidth = width;
    emit lineWidthChanged();
    update();
}

void GitGraphLaneItem::setRowPosition(RowPosition position)
{
    if (mRowPosition == position)
        return;
    mRowPosition = position;
    emit rowPositionChanged();
    update();
}

QCanvasPainterItemRenderer* GitGraphLaneItem::createItemRenderer() const
{
    return new GitGraphLaneRenderer();
}
