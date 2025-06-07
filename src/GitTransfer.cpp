#include "GitTransfer.h"

using namespace QQuickGit;

GitTransfer::GitTransfer(QObject *parent) : QObject(parent)
{

}


void GitTransfer::setState(State state) {
    if(mState != state) {
        mState = state;
        emit stateChanged();
    }
}


void GitTransfer::setError(QString error) {
    if(mError != error) {
        mError = error;
        emit errorChanged();
    }
}

void GitTransfer::setDirectory(QDir directory) {
    if(mDirectory != directory) {
        mDirectory = directory;
        emit directoryChanged();
    }
}

void GitTransfer::pullPush(QString remote)
{

}

void GitTransfer::pull(QString remote)
{

}

void GitTransfer::push(QString refSpec, QString remote)
{

}

void GitTransfer::clone(const QUrl &url)
{

}
