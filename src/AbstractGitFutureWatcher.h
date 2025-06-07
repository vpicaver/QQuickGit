#ifndef ABSTRACTGITFUTUREWATCHER_H
#define ABSTRACTGITFUTUREWATCHER_H

//Our inculdes
#include "AbstractResultFutureWatcher.h"
#include "ProgressState.h"
#include "Monad/Result.h"

//Qt includes
#include <QObject>

class AbstractGitFutureWatcher : public AbstractResultFutureWatcher
{
    Q_OBJECT

    Q_PROPERTY(double progress READ progress NOTIFY progressChanged)
    Q_PROPERTY(QString progressText READ progressText NOTIFY progressTextChanged)

    Q_PROPERTY(QString initialProgressText READ initialProgressText WRITE setInitialProgressText NOTIFY initialProgressTextChanged)

public:
    explicit AbstractGitFutureWatcher(QObject *parent = nullptr);

    double progress() const;
    QString progressText() const;

    QString initialProgressText() const;
    void setInitialProgressText(QString initialProgressText);

signals:
    void progressChanged();
    void progressTextChanged();
    void futureChanged();
    void initialProgressTextChanged();

private:
    ProgressState mProgressState;
    QString mInitialProgressText = QStringLiteral("Started"); //!<

    void setProgress(double progress);
    void setState(State state);
    void setErrorMessage(QString message);

protected:
    void setProgress(const ProgressState& newState);

protected:
    template<typename Future>
    void watchProgress(Future future) {
        watchProgress(future, [=]() {
            watchFuture(future,
                        [this](const Monad::ResultBase& result)
            {
                Q_UNUSED(result)
                setProgress(ProgressState("Done", 1, 1));
            }
            );
        });
    }

    template<typename Future, typename WatchFunc>
    void watchProgress(Future future, WatchFunc watch) {
        watch();

        auto updateProgress = [this, future]() {
            setProgress(ProgressState::fromJson(future.progressText()));
        };

        setProgress(ProgressState(initialProgressText(), 0, 1));

        AsyncFuture::observe(future)
                .onProgress(updateProgress);
    }
};

inline QString AbstractGitFutureWatcher::initialProgressText() const {
    return mInitialProgressText;
}


#endif // ABSTRACTGITFUTUREWATCHER_H
