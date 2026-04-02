#ifndef GITWORKINGTREEMODEL_H
#define GITWORKINGTREEMODEL_H

//Our includes
#include "QQuickGitExport.h"

//Async Future includes
#include "asyncfuture.h"

//Qt includes
#include <QAbstractListModel>
#include <QQmlEngine>
#include <QVector>
#include <QFuture>

namespace QQuickGit {

class GitRepository;

struct WorkingTreeResult
{
    struct FileEntry {
        QString filePath;
        QString oldFilePath;
        int status = 0;
        bool isBinary = false;
        bool isImage = false;
    };
    QVector<FileEntry> files;
    QString errorMessage;
};

struct LineStatsResult
{
    int addedLines = -1;
    int deletedLines = -1;
    QString errorMessage;
};

class QQUICKGIT_EXPORT GitWorkingTreeModel : public QAbstractListModel
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QQuickGit::GitRepository* repository READ repository WRITE setRepository NOTIFY repositoryChanged)
    Q_PROPERTY(int count READ count NOTIFY countChanged)
    Q_PROPERTY(bool loading READ loading NOTIFY loadingChanged)
    Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY errorMessageChanged)

public:
    enum Roles
    {
        FilePathRole = Qt::UserRole + 1,
        OldFilePathRole,
        StatusRole,
        StatusTextRole,
        IsBinaryRole,
        IsImageRole,
        AddedLinesRole,
        DeletedLinesRole,
        LineStatsFetchedRole
    };
    Q_ENUM(Roles)

    explicit GitWorkingTreeModel(QObject* parent = nullptr);
    ~GitWorkingTreeModel() override;

    GitRepository* repository() const;
    void setRepository(GitRepository* repository);

    int count() const;
    bool loading() const;
    QString errorMessage() const;

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void fetchLineStats(int row);

signals:
    void repositoryChanged();
    void countChanged();
    void loadingChanged();
    void errorMessageChanged();

private:
    struct RowData {
        WorkingTreeResult::FileEntry entry;
        int addedLines = -1;
        int deletedLines = -1;
        bool lineStatsFetched = false;
    };

    void refresh();
    void cancelLineStatsFutures();

    GitRepository* mRepository = nullptr;
    QVector<RowData> mRows;
    bool mLoading = false;
    QString mErrorMessage;

    AsyncFuture::Restarter<WorkingTreeResult> mRestarter;
    QVector<QFuture<LineStatsResult>> mLineStatsFutures;
};

inline GitRepository* GitWorkingTreeModel::repository() const {
    return mRepository;
}

inline int GitWorkingTreeModel::count() const {
    return mRows.size();
}

inline bool GitWorkingTreeModel::loading() const {
    return mLoading;
}

inline QString GitWorkingTreeModel::errorMessage() const {
    return mErrorMessage;
}

}

#endif // GITWORKINGTREEMODEL_H
