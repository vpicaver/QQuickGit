#ifndef GITCOMMITINFO_H
#define GITCOMMITINFO_H

//Our includes
#include "QQuickGitExport.h"
#include "GitRepository.h"

//Async Future includes
#include "asyncfuture.h"

//Qt includes
#include <QObject>
#include <QQmlEngine>
#include <QDateTime>
#include <QStringList>
#include <QVector>

namespace QQuickGit {

struct QQUICKGIT_EXPORT CommitLoadResult
{
    // Metadata
    QString author;
    QString authorEmail;
    QDateTime timestamp;
    QString subject;
    QString body;
    QStringList parentShas;
    QStringList parentSubjects;

    // File list
    struct FileEntry {
        QString filePath;
        QString oldFilePath;
        int status = 0;
        QString statusText;
        bool isBinary = false;
        bool isImage = false;
    };
    QVector<FileEntry> files;

    QString errorMessage;
};

class QQUICKGIT_EXPORT GitCommitInfo : public QObject
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QQuickGit::GitRepository* repository READ repository WRITE setRepository NOTIFY repositoryChanged)
    Q_PROPERTY(QString commitSha READ commitSha WRITE setCommitSha NOTIFY commitShaChanged)
    Q_PROPERTY(int parentIndex READ parentIndex WRITE setParentIndex NOTIFY parentIndexChanged)
    Q_PROPERTY(QString author READ author NOTIFY metadataChanged)
    Q_PROPERTY(QString authorEmail READ authorEmail NOTIFY metadataChanged)
    Q_PROPERTY(QDateTime timestamp READ timestamp NOTIFY metadataChanged)
    Q_PROPERTY(QString subject READ subject NOTIFY metadataChanged)
    Q_PROPERTY(QString body READ body NOTIFY metadataChanged)
    Q_PROPERTY(QStringList parentShas READ parentShas NOTIFY metadataChanged)
    Q_PROPERTY(QStringList parentSubjects READ parentSubjects NOTIFY metadataChanged)
    Q_PROPERTY(bool isMergeCommit READ isMergeCommit NOTIFY metadataChanged)
    Q_PROPERTY(bool loading READ loading NOTIFY loadingChanged)
    Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY errorMessageChanged)

public:
    explicit GitCommitInfo(QObject* parent = nullptr);
    ~GitCommitInfo() override;

    GitRepository* repository() const;
    void setRepository(GitRepository* repository);

    QString commitSha() const;
    void setCommitSha(const QString& sha);

    int parentIndex() const;
    void setParentIndex(int index);

    QString author() const;
    QString authorEmail() const;
    QDateTime timestamp() const;
    QString subject() const;
    QString body() const;
    QStringList parentShas() const;
    QStringList parentSubjects() const;
    bool isMergeCommit() const;

    bool loading() const;
    QString errorMessage() const;

signals:
    void repositoryChanged();
    void commitShaChanged();
    void parentIndexChanged();
    void metadataChanged();
    void loadingChanged();
    void errorMessageChanged();
    void fileListReady(const QVector<CommitLoadResult::FileEntry>& files);

private:
    void load();
    void applyResult(const CommitLoadResult& result);
    void clearMetadata();

    GitRepository* mRepository = nullptr;
    QString mCommitSha;
    int mParentIndex = 0;

    // Metadata
    QString mAuthor;
    QString mAuthorEmail;
    QDateTime mTimestamp;
    QString mSubject;
    QString mBody;
    QStringList mParentShas;
    QStringList mParentSubjects;

    bool mLoading = false;
    QString mErrorMessage;

    AsyncFuture::Restarter<CommitLoadResult> mRestarter;
};

inline GitRepository* GitCommitInfo::repository() const { return mRepository; }
inline QString GitCommitInfo::commitSha() const { return mCommitSha; }
inline int GitCommitInfo::parentIndex() const { return mParentIndex; }
inline QString GitCommitInfo::author() const { return mAuthor; }
inline QString GitCommitInfo::authorEmail() const { return mAuthorEmail; }
inline QDateTime GitCommitInfo::timestamp() const { return mTimestamp; }
inline QString GitCommitInfo::subject() const { return mSubject; }
inline QString GitCommitInfo::body() const { return mBody; }
inline QStringList GitCommitInfo::parentShas() const { return mParentShas; }
inline QStringList GitCommitInfo::parentSubjects() const { return mParentSubjects; }
inline bool GitCommitInfo::isMergeCommit() const { return mParentShas.size() > 1; }
inline bool GitCommitInfo::loading() const { return mLoading; }
inline QString GitCommitInfo::errorMessage() const { return mErrorMessage; }

} // namespace QQuickGit

Q_DECLARE_METATYPE(QQuickGit::CommitLoadResult)
Q_DECLARE_METATYPE(QVector<QQuickGit::CommitLoadResult::FileEntry>)

#endif // GITCOMMITINFO_H
