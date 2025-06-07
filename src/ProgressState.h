#ifndef PROGRESSSTATE_H
#define PROGRESSSTATE_H

//QString includes
#include <QString>
#include <QVariantMap>

namespace QQuickGit {
class ProgressState
{
public:
    ProgressState() = default;
    ProgressState(QString text, size_t current, size_t total);

    QString text() const { return mText; }
    size_t current() const { return mCurrent; }
    size_t total() const { return mTotal; }

    double progress() const;

    QVariantMap data() const;
    QString toJsonString() const;
    static ProgressState fromJson(const QString& json);

private:
    QString mText;
    size_t mCurrent = 0;
    size_t mTotal = 0;

};
};

#endif // PROGRESSSTATE_H
