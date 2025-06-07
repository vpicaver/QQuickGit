#include "AbstractResultFutureWatcher.h"

//Async includes
#include "asyncfuture.h"

AbstractResultFutureWatcher::AbstractResultFutureWatcher(QObject *parent) : QObject(parent)
{

}

void AbstractResultFutureWatcher::setErrorMessage(QString message)
{
    if(mErrorMessage != message) {
        mErrorMessage = std::move(message);
        emit errorMessageChanged();
        emit hasErrorChanged();
    }
}

void AbstractResultFutureWatcher::setState(State state)
{
    if(mState != state) {
        mState = std::move(state);
        emit stateChanged();
    }
}
