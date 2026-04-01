#ifndef GITCOMMITFILEMODEL_H
#define GITCOMMITFILEMODEL_H

//Our includes
#include "QQuickGitExport.h"
#include "GitCommitInfo.h"

//Qt includes
#include <QAbstractListModel>
#include <QQmlEngine>
#include <QHash>
#include <QFuture>

namespace QQuickGit {

class QQUICKGIT_EXPORT GitCommitFileModel : public QAbstractListModel
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QQuickGit::GitCommitInfo* commitInfo READ commitInfo WRITE setCommitInfo NOTIFY commitInfoChanged)
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

    explicit GitCommitFileModel(QObject* parent = nullptr);
    ~GitCommitFileModel() override;

    GitCommitInfo* commitInfo() const;
    void setCommitInfo(GitCommitInfo* info);

    bool loading() const;
    QString errorMessage() const;

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void fetchLineStats(int row);

signals:
    void commitInfoChanged();
    void loadingChanged();
    void errorMessageChanged();

private:
    struct LineStats {
        int added = -1;
        int deleted = -1;
    };

    void onFileListReady(const QVector<CommitLoadResult::FileEntry>& files);
    void cancelAllLineStatFutures();

    GitCommitInfo* mCommitInfo = nullptr;
    QVector<CommitLoadResult::FileEntry> mFiles;

    QHash<int, LineStats> mLineStatsCache;
    QHash<int, QFuture<LineStats>> mLineStatFutures;
};

inline GitCommitInfo* GitCommitFileModel::commitInfo() const { return mCommitInfo; }

} // namespace QQuickGit

#endif // GITCOMMITFILEMODEL_H
