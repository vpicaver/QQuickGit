//Our includes
#include "ProgressState.h"

//Qt includes
#include <QJsonDocument>

static const QString textKey = QStringLiteral("text");
static const QString currentKey = QStringLiteral("current");
static const QString totalKey = QStringLiteral("total");

using namespace QQuickGit;

ProgressState::ProgressState(QString text, size_t current, size_t total) :
    mText(text),
    mCurrent(current),
    mTotal(total)
{
}

double ProgressState::progress() const
{
    if(mTotal == 0) {
        return 0.0;
    }
    return mCurrent / static_cast<double>(mTotal);
}

QVariantMap ProgressState::data() const
{
    return {
        {textKey, text()},
        {currentKey, static_cast<unsigned long long>(current())},
        {totalKey, static_cast<unsigned long long>(total())}
    };
}

QString ProgressState::toJsonString() const
{
    auto doc = QJsonDocument::fromVariant(data());
    return doc.toJson(QJsonDocument::Compact);
}

ProgressState ProgressState::fromJson(const QString &json)
{
    auto doc = QJsonDocument::fromJson(json.toLocal8Bit());
    auto map = doc.toVariant().toMap();
    return ProgressState(map.value(textKey).toString(),
                         map.value(currentKey).toULongLong(),
                         map.value(totalKey).toULongLong());
}
