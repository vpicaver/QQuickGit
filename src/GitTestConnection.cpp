//Our includes
#include "GitTestConnection.h"
#include "GitRepository.h"

#include "asyncfuture.h"

GitTestConnection::GitTestConnection(QObject *parent) : QObject(parent)
{

}

void GitTestConnection::setUrl(QUrl url) {
    if(mUrl != url && mState == Ready) {
        mUrl = url;
        emit urlChanged();
    }
}

void GitTestConnection::test()
{
    if(state() == Testing) {
        return;
    }

    mState = Testing;
    emit stateChanged();

    mErrorMessage.clear();
    emit errorMessageChanged();

    auto errorMessageFuture = GitRepository::testRemoteConnection(url());

    AsyncFuture::observe(errorMessageFuture).context(this,
                [this, errorMessageFuture]()
    {
        mState = Ready;
        mErrorMessage = errorMessageFuture.result();
        emit errorMessageChanged();
        emit stateChanged();
        emit finished();
    });
}
