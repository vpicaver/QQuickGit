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
    case LT::Branch:
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
};

void GitGraphLaneRenderer::synchronize(QCanvasPainterItem* item)
{
    auto* laneItem = static_cast<GitGraphLaneItem*>(item);
    mLanes = laneItem->lanes();
    mActiveLane = laneItem->activeLane();
    mColors = laneItem->colors();
    mLaneWidth = static_cast<float>(laneItem->laneWidth());
    mNodeRadius = static_cast<float>(laneItem->nodeRadius());
    mLineWidth = static_cast<float>(laneItem->lineWidth());
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
            // Smooth S-curve connecting this lane to the active lane.
            // Skip the straight vertical segments — the curve covers them.
            painter->beginPath();
            if (isHeadType(type))
            {
                painter->moveTo(activeCX, midY);
                painter->quadraticCurveTo(cx, midY, cx, h);
            }
            else // isTailType || isJoinType
            {
                painter->moveTo(cx, 0);
                painter->quadraticCurveTo(cx, midY, activeCX, midY);
            }
            painter->stroke();

            // Join lanes also continue below the commit row — draw that segment.
            if (isJoinType(type))
            {
                painter->beginPath();
                painter->moveTo(cx, midY);
                painter->lineTo(cx, h);
                painter->stroke();
            }
        }
        else
        {
            if (hasTopLine(type))
            {
                painter->beginPath();
                painter->moveTo(cx, 0);
                painter->lineTo(cx, midY);
                painter->stroke();
            }

            if (hasBottomLine(type))
            {
                painter->beginPath();
                painter->moveTo(cx, midY);
                painter->lineTo(cx, h);
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

QCanvasPainterItemRenderer* GitGraphLaneItem::createItemRenderer() const
{
    return new GitGraphLaneRenderer();
}
