#ifndef ABSTRACTRESULTFUTUREWATCHER_H
#define ABSTRACTRESULTFUTUREWATCHER_H

//Qt includes
#include <QObject>
#include <QFuture>

//Std includes
#include <functional>

//Async includes
#include "asyncfuture.h"

class AbstractResultFutureWatcher : public QObject
{
    Q_OBJECT

    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY errorMessageChanged)
    Q_PROPERTY(bool hasError READ hasError NOTIFY hasErrorChanged)

public:
    enum State {
        Ready,
        Loading
    };
    Q_ENUM(State)

    explicit AbstractResultFutureWatcher(QObject *parent = nullptr);

    QFuture<void> finalFuture() const {
        return mFuture;
    }

    State state() const;
    QString errorMessage() const;
    bool hasError() const;

signals:
    void stateChanged();
    void errorMessageChanged();
    void hasErrorChanged();

protected:
    template <typename T, typename F>
    void watchFuture(QFuture<T> future,
                     F completed
                     ) {
        if(mFuture.isRunning()) {
            mFuture.cancel();
        }

        setState(Loading);
        setErrorMessage(QString());

        mFuture = AsyncFuture::observe(future)
                .context(this, [future, completed, this]()->void
        {

            auto result = future.result();
            setErrorMessage(result.errorMessage());
            completed(result);
            setState(Ready);
        }).future();
    }

    void setErrorMessage(QString message);

private:
    QFuture<void> mFuture; //!<
    QString mErrorMessage;
    State mState = Ready; //!<

    void setState(State state);
};

inline AbstractResultFutureWatcher::State AbstractResultFutureWatcher::state() const {
    return mState;
}

inline QString AbstractResultFutureWatcher::errorMessage() const {
    return mErrorMessage;
}

inline bool AbstractResultFutureWatcher::hasError() const {
    return !errorMessage().isEmpty();
}

#endif // ABSTRACTRESULTFUTUREWATCHER_H
