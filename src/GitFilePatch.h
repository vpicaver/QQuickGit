#ifndef GITFILEPATCH_H
#define GITFILEPATCH_H

//Our includes
#include "QQuickGitExport.h"
#include "GitRepository.h"

//Async Future includes
#include "asyncfuture.h"

//Qt includes
#include <QAbstractListModel>
#include <QQmlEngine>

namespace QQuickGit {

struct FilePatchResult
{
    struct DiffLine {
        QString text;
        char origin = ' '; // '+', '-', ' ', 'H' (mapped from libgit2 origins)
        int oldLineNo = -1;
        int newLineNo = -1;
    };
    QVector<DiffLine> lines;
    bool tooLarge = false;
    bool isBinary = false;
    bool isLfsPointer = false;
    QString errorMessage;
};

class QQUICKGIT_EXPORT GitFilePatch : public QAbstractListModel
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QQuickGit::GitRepository* repository READ repository WRITE setRepository NOTIFY repositoryChanged)
    Q_PROPERTY(QString commitSha READ commitSha WRITE setCommitSha NOTIFY commitShaChanged)
    Q_PROPERTY(int parentIndex READ parentIndex WRITE setParentIndex NOTIFY parentIndexChanged)
    Q_PROPERTY(QString filePath READ filePath WRITE setFilePath NOTIFY filePathChanged)
    Q_PROPERTY(int maxDiffLines READ maxDiffLines WRITE setMaxDiffLines NOTIFY maxDiffLinesChanged)
    Q_PROPERTY(bool workingTree READ workingTree WRITE setWorkingTree NOTIFY workingTreeChanged)
    Q_PROPERTY(bool loading READ loading NOTIFY loadingChanged)
    Q_PROPERTY(bool tooLarge READ tooLarge NOTIFY tooLargeChanged)
    Q_PROPERTY(bool isBinary READ isBinary NOTIFY isBinaryChanged)
    Q_PROPERTY(bool isLfsPointer READ isLfsPointer NOTIFY isLfsPointerChanged)
    Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY errorMessageChanged)

public:
    enum Roles {
        TextRole = Qt::UserRole + 1,
        OriginRole,
        OldLineNoRole,
        NewLineNoRole
    };
    Q_ENUM(Roles)

    explicit GitFilePatch(QObject* parent = nullptr);
    ~GitFilePatch() override;

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    GitRepository* repository() const;
    void setRepository(GitRepository* repository);

    QString commitSha() const;
    void setCommitSha(const QString& sha);

    int parentIndex() const;
    void setParentIndex(int index);

    QString filePath() const;
    void setFilePath(const QString& path);

    int maxDiffLines() const;
    void setMaxDiffLines(int max);

    bool workingTree() const;
    void setWorkingTree(bool workingTree);

    bool loading() const;
    bool tooLarge() const;
    bool isBinary() const;
    bool isLfsPointer() const;
    QString errorMessage() const;

signals:
    void repositoryChanged();
    void commitShaChanged();
    void parentIndexChanged();
    void filePathChanged();
    void maxDiffLinesChanged();
    void workingTreeChanged();
    void loadingChanged();
    void tooLargeChanged();
    void isBinaryChanged();
    void isLfsPointerChanged();
    void errorMessageChanged();

private:
    void load();
    void applyResult(const FilePatchResult& result);
    void clear();

    GitRepository* mRepository = nullptr;
    QString mCommitSha;
    int mParentIndex = 0;
    QString mFilePath;
    int mMaxDiffLines = 5000;
    bool mWorkingTree = false;

    QVector<FilePatchResult::DiffLine> mLines;
    bool mLoading = false;
    bool mTooLarge = false;
    bool mIsBinary = false;
    bool mIsLfsPointer = false;
    QString mErrorMessage;

    AsyncFuture::Restarter<FilePatchResult> mRestarter;
};

inline GitRepository* GitFilePatch::repository() const { return mRepository; }
inline QString GitFilePatch::commitSha() const { return mCommitSha; }
inline int GitFilePatch::parentIndex() const { return mParentIndex; }
inline QString GitFilePatch::filePath() const { return mFilePath; }
inline int GitFilePatch::maxDiffLines() const { return mMaxDiffLines; }
inline bool GitFilePatch::workingTree() const { return mWorkingTree; }
inline bool GitFilePatch::loading() const { return mLoading; }
inline bool GitFilePatch::tooLarge() const { return mTooLarge; }
inline bool GitFilePatch::isBinary() const { return mIsBinary; }
inline bool GitFilePatch::isLfsPointer() const { return mIsLfsPointer; }
inline QString GitFilePatch::errorMessage() const { return mErrorMessage; }

} // namespace QQuickGit

Q_DECLARE_METATYPE(QQuickGit::FilePatchResult)

#endif // GITFILEPATCH_H
