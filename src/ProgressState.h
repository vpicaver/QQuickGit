#ifndef PROGRESSSTATE_H
#define PROGRESSSTATE_H

//QString includes
#include "QQuickGitExport.h"
#include <QString>
#include <QVariantMap>

namespace QQuickGit {
class QQUICKGIT_EXPORT ProgressState
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

template<typename ProgressInterface>
void setProgress(ProgressInterface* progressInterface, const QString& text) {
    if(!text.isEmpty()) {
        //We have to increment the progress by one to signal that the text changes
        progressInterface->setProgressValueAndText(progressInterface->progressValue()+1, text);
    }
}

template<typename ProgressInterface>
void setProgress(ProgressInterface* progressInterface, const ProgressState& progress) {
    //We have to increment the progress by one to signal that the text changes
    progressInterface->setProgressRange(0, progress.total());
    setProgress(progressInterface, progress.toJsonString());
}

};

#endif // PROGRESSSTATE_H
