#ifndef GITGRAPHLANEITEM_H
#define GITGRAPHLANEITEM_H

//Our includes
#include "QQuickGitExport.h"

//Qt includes
#include <QCanvasPainterItem>
#include <QQmlEngine>

namespace QQuickGit {

class QQUICKGIT_EXPORT GitGraphLaneItem : public QCanvasPainterItem
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QList<int> lanes READ lanes WRITE setLanes NOTIFY lanesChanged)
    Q_PROPERTY(int activeLane READ activeLane WRITE setActiveLane NOTIFY activeLaneChanged)
    Q_PROPERTY(QList<QColor> colors READ colors WRITE setColors NOTIFY colorsChanged)
    Q_PROPERTY(qreal laneWidth READ laneWidth WRITE setLaneWidth NOTIFY laneWidthChanged)
    Q_PROPERTY(qreal nodeRadius READ nodeRadius WRITE setNodeRadius NOTIFY nodeRadiusChanged)
    Q_PROPERTY(qreal lineWidth READ lineWidth WRITE setLineWidth NOTIFY lineWidthChanged)
    Q_PROPERTY(bool isFirstRow READ isFirstRow WRITE setIsFirstRow NOTIFY isFirstRowChanged)
    Q_PROPERTY(bool isLastRow READ isLastRow WRITE setIsLastRow NOTIFY isLastRowChanged)

public:
    explicit GitGraphLaneItem(QQuickItem* parent = nullptr);

    QList<int> lanes() const;
    void setLanes(const QList<int>& lanes);

    int activeLane() const;
    void setActiveLane(int activeLane);

    QList<QColor> colors() const;
    void setColors(const QList<QColor>& colors);

    qreal laneWidth() const;
    void setLaneWidth(qreal width);

    qreal nodeRadius() const;
    void setNodeRadius(qreal radius);

    qreal lineWidth() const;
    void setLineWidth(qreal width);

    bool isFirstRow() const;
    void setIsFirstRow(bool isFirstRow);

    bool isLastRow() const;
    void setIsLastRow(bool isLastRow);

protected:
    QCanvasPainterItemRenderer* createItemRenderer() const override;

signals:
    void lanesChanged();
    void activeLaneChanged();
    void colorsChanged();
    void laneWidthChanged();
    void nodeRadiusChanged();
    void lineWidthChanged();
    void isFirstRowChanged();
    void isLastRowChanged();

private:
    QList<int> mLanes;
    int mActiveLane = 0;
    QList<QColor> mColors;
    qreal mLaneWidth = 20.0;
    qreal mNodeRadius = 4.0;
    qreal mLineWidth = 2.0;
    bool mIsFirstRow = false;
    bool mIsLastRow = false;
};

inline QList<int> GitGraphLaneItem::lanes() const {
    return mLanes;
}

inline int GitGraphLaneItem::activeLane() const {
    return mActiveLane;
}

inline QList<QColor> GitGraphLaneItem::colors() const {
    return mColors;
}

inline qreal GitGraphLaneItem::laneWidth() const {
    return mLaneWidth;
}

inline qreal GitGraphLaneItem::nodeRadius() const {
    return mNodeRadius;
}

inline qreal GitGraphLaneItem::lineWidth() const {
    return mLineWidth;
}

inline bool GitGraphLaneItem::isFirstRow() const {
    return mIsFirstRow;
}

inline bool GitGraphLaneItem::isLastRow() const {
    return mIsLastRow;
}

}

#endif // GITGRAPHLANEITEM_H
