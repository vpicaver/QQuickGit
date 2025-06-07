#ifndef GITTRANSFER_H
#define GITTRANSFER_H

//Qt includes
#include <QObject>
#include <QDir>

class GitTransfer : public QObject
{
    Q_OBJECT

    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(QString error READ error NOTIFY errorChanged)
    Q_PROPERTY(QDir directory READ directory WRITE setDirectory NOTIFY directoryChanged)
    Q_PROPERTY(double progress READ progress NOTIFY progressChanged)


public:
    enum State {
        Ready,
        Pushing,
        Pulling,
        Cloning
    };
    Q_ENUMS(State);

    explicit GitTransfer(QObject *parent = nullptr);

    QString error() const;
    State state() const;

    QDir directory() const;
    void setDirectory(QDir directory);

    double progress() const;

    Q_INVOKABLE void pullPush(QString remote = QString());
    Q_INVOKABLE void pull(QString remote = QString());
    Q_INVOKABLE void push(QString refSpec = QString(), QString remote = QString());
    Q_INVOKABLE void clone(const QUrl& url);

signals:
    void stateChanged();
    void errorChanged();
    void directoryChanged();
    void progressChanged();

private:
    State mState; //!<
    QString mError; //!<
    QDir mDirectory; //!<
    double mProgress; //!<

    void setState(State state);
    void setError(QString error);
};

inline GitTransfer::State GitTransfer::state() const {
    return mState;
}

inline QString GitTransfer::error() const {
    return mError;
}

inline QDir GitTransfer::directory() const {
    return mDirectory;
}

inline double GitTransfer::progress() const {
    return mProgress;
}
#endif // GITTRANSFER_H
