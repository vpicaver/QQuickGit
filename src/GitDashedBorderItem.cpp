//Our includes
#include "GitDashedBorderItem.h"

//Qt includes
#include <QCanvasPainterItemRenderer>
#include <QCanvasPainter>

#include <algorithm>
#include <cmath>

using namespace QQuickGit;

class GitDashedBorderRenderer : public QCanvasPainterItemRenderer
{
public:
    void synchronize(QCanvasPainterItem* item) override;
    void paint(QCanvasPainter* painter) override;

private:
    void appendDashedLine(QCanvasPainter* painter, float x0, float y0, float x1, float y1);

    QColor mBorderColor;
    float mRadius = 3.0f;
    float mDashLength = 4.0f;
    float mGapLength = 3.0f;
};

void GitDashedBorderRenderer::synchronize(QCanvasPainterItem* item)
{
    auto* borderItem = static_cast<GitDashedBorderItem*>(item);
    mBorderColor = borderItem->borderColor();
    mRadius = static_cast<float>(borderItem->radius());
    mDashLength = static_cast<float>(borderItem->dashLength());
    mGapLength = static_cast<float>(borderItem->gapLength());
}

void GitDashedBorderRenderer::appendDashedLine(QCanvasPainter* painter,
                                               float x0, float y0,
                                               float x1, float y1)
{
    float dx = x1 - x0;
    float dy = y1 - y0;
    float length = std::sqrt(dx * dx + dy * dy);
    if (length < 1.0f)
        return;

    float ux = dx / length;
    float uy = dy / length;
    float pattern = mDashLength + mGapLength;
    float pos = 0.0f;

    while (pos < length)
    {
        float dashEnd = std::min(pos + mDashLength, length);
        painter->moveTo(x0 + ux * pos, y0 + uy * pos);
        painter->lineTo(x0 + ux * dashEnd, y0 + uy * dashEnd);
        pos += pattern;
    }
}

void GitDashedBorderRenderer::paint(QCanvasPainter* painter)
{
    const float w = width();
    const float h = height();

    if (w <= 0 || h <= 0)
        return;

    painter->clearRect(0, 0, w, h);
    painter->setRenderHint(QCanvasPainter::RenderHint::Antialiasing);
    painter->setStrokeStyle(mBorderColor);
    painter->setLineWidth(1.0f);

    const float inset = 0.5f;
    const float r = mRadius;
    const float left = inset;
    const float top = inset;
    const float right = w - inset;
    const float bottom = h - inset;

    // Corner arcs in a single path
    painter->beginPath();
    painter->arc(left + r, top + r, r, static_cast<float>(M_PI), static_cast<float>(M_PI * 1.5));
    painter->arc(right - r, top + r, r, static_cast<float>(M_PI * 1.5), static_cast<float>(M_PI * 2.0));
    painter->arc(right - r, bottom - r, r, 0.0f, static_cast<float>(M_PI * 0.5));
    painter->arc(left + r, bottom - r, r, static_cast<float>(M_PI * 0.5), static_cast<float>(M_PI));
    painter->stroke();

    // All dashed edges in a single path
    painter->beginPath();
    appendDashedLine(painter, left + r, top, right - r, top);       // top
    appendDashedLine(painter, right, top + r, right, bottom - r);   // right
    appendDashedLine(painter, right - r, bottom, left + r, bottom); // bottom
    appendDashedLine(painter, left, bottom - r, left, top + r);     // left
    painter->stroke();
}

// --- GitDashedBorderItem implementation ---

GitDashedBorderItem::GitDashedBorderItem(QQuickItem* parent)
    : QCanvasPainterItem(parent)
{
    setFillColor(Qt::transparent);
    setAlphaBlending(true);
}

void GitDashedBorderItem::setBorderColor(const QColor& color)
{
    if (mBorderColor == color)
        return;
    mBorderColor = color;
    emit borderColorChanged();
    update();
}

void GitDashedBorderItem::setRadius(qreal radius)
{
    if (qFuzzyCompare(mRadius, radius))
        return;
    mRadius = radius;
    emit radiusChanged();
    update();
}

void GitDashedBorderItem::setDashLength(qreal length)
{
    if (qFuzzyCompare(mDashLength, length))
        return;
    mDashLength = length;
    emit dashLengthChanged();
    update();
}

void GitDashedBorderItem::setGapLength(qreal length)
{
    if (qFuzzyCompare(mGapLength, length))
        return;
    mGapLength = length;
    emit gapLengthChanged();
    update();
}

QCanvasPainterItemRenderer* GitDashedBorderItem::createItemRenderer() const
{
    return new GitDashedBorderRenderer();
}
