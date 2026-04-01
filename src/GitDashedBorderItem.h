#ifndef GITDASHEDBORDERITEM_H
#define GITDASHEDBORDERITEM_H

//Our includes
#include "QQuickGitExport.h"

//Qt includes
#include <QCanvasPainterItem>
#include <QQmlEngine>

namespace QQuickGit {

class QQUICKGIT_EXPORT GitDashedBorderItem : public QCanvasPainterItem
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QColor borderColor READ borderColor WRITE setBorderColor NOTIFY borderColorChanged)
    Q_PROPERTY(qreal radius READ radius WRITE setRadius NOTIFY radiusChanged)
    Q_PROPERTY(qreal dashLength READ dashLength WRITE setDashLength NOTIFY dashLengthChanged)
    Q_PROPERTY(qreal gapLength READ gapLength WRITE setGapLength NOTIFY gapLengthChanged)

public:
    explicit GitDashedBorderItem(QQuickItem* parent = nullptr);

    QColor borderColor() const;
    void setBorderColor(const QColor& color);

    qreal radius() const;
    void setRadius(qreal radius);

    qreal dashLength() const;
    void setDashLength(qreal length);

    qreal gapLength() const;
    void setGapLength(qreal length);

protected:
    QCanvasPainterItemRenderer* createItemRenderer() const override;

signals:
    void borderColorChanged();
    void radiusChanged();
    void dashLengthChanged();
    void gapLengthChanged();

private:
    QColor mBorderColor = QColor(128, 128, 128);
    qreal mRadius = 3.0;
    qreal mDashLength = 4.0;
    qreal mGapLength = 3.0;
};

inline QColor GitDashedBorderItem::borderColor() const {
    return mBorderColor;
}

inline qreal GitDashedBorderItem::radius() const {
    return mRadius;
}

inline qreal GitDashedBorderItem::dashLength() const {
    return mDashLength;
}

inline qreal GitDashedBorderItem::gapLength() const {
    return mGapLength;
}

}

#endif // GITDASHEDBORDERITEM_H
