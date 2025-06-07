//Our includes
#include "AuthorizedKeysModel.h"

//Qt includes
#include <QRegularExpression>
#include <QFile>
#include <QSaveFile>
#include <QTextStream>
#include <QDebug>

//Std includes
#include <stdexcept>

//const auto nameKey = QStringLiteral("name");
//const auto emailKey = QStringLiteral("email");

using namespace QQuickGit;

AuthorizedKeysModel::AuthorizedKeysModel(QObject *parent) : QAbstractListModel(parent)
{

}

int AuthorizedKeysModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return mRows.size();
}

QVariant AuthorizedKeysModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid()) {
        return QVariant();
    }

    const auto& row = mRows.at(index.row());
    switch(role) {
    case NameRole:
        return row.name();
    case EmailRole:
        return row.email();
    case CommentRole:
        return row.comment();
    case KeyRole:
        return row.key();
    case UserRole:
        return QVariant::fromValue(row);
    }

    return QVariant();
}

bool AuthorizedKeysModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid()) {
        return false;
    }

    auto& row = mRows[index.row()];
    switch(role) {
    case NameRole:
        row.setName(value.toString());
        break;
    case EmailRole:
        row.setEmail(value.toString());
        break;
    case CommentRole:
        row.setComment(value.toString());
        break;
    case KeyRole: {
        auto newKey = value.toString();
        if(SshUser::keyValid(newKey)) {
            row.setKey(value.toString());
        } else {
            return false;
        }
        break;
    }
    default:
        return false;
    }

    emit dataChanged(index, index, {role});
    return true;
}

QHash<int, QByteArray> AuthorizedKeysModel::roleNames() const
{
    const static QHash<int, QByteArray> roles {
        {NameRole, "nameRole"},
        {EmailRole, "emailRole"},
        {CommentRole, "commentRole"},
        {KeyRole, "keyRole"},
        {UserRole, "userRole"}
    };

    return roles;
}

void AuthorizedKeysModel::addRow(const SshUser &row)
{
    auto contains = [this](const SshUser& row) {
        return indexOf(row.key()) >= 0;
    };

    if(row.isValid() && !contains(row)) {
        int last = mRows.size();
        beginInsertRows(QModelIndex(), last, last);
        mRows.append(row);
        endInsertRows();
    } else {
        if(!row.isValid()) {
            throw std::runtime_error("Can't add key because key is invalid");
        } else if(contains(row)) {
            throw std::runtime_error("Can't add key because key already exists");
        }
    }
}

int AuthorizedKeysModel::indexOf(const QString &key) const
{
    auto iter = std::find_if(mRows.begin(), mRows.end(), [key](const SshUser& row) {
        return row.key() == key;
    });
    if(iter != mRows.end()) {
        return std::distance(mRows.begin(), iter);
    }
    return -1;
}



void AuthorizedKeysModel::throwError(const QFileDevice &file) const
{
    throw std::runtime_error(QString("File error in \"%1\" %2")
                             .arg(mFilename)
                             .arg(file.errorString())
                             .toStdString());
}

void AuthorizedKeysModel::checkForFileError(const QFileDevice &file) const
{
    if(file.error() != QFile::NoError) {
        throwError(file);
    }
}

void AuthorizedKeysModel::removeRow(const QString &key)
{
    auto index = indexOf(key);

    if(index >= 0) {
        beginRemoveRows(QModelIndex(), index, index);
        mRows.removeAt(index);
        endRemoveRows();
    } else {
        throw std::runtime_error("Can't remove key because it doesn't exist");
    }

}

void AuthorizedKeysModel::setUsers(const QVector<SshUser> users)
{
    beginResetModel();
    mRows = users;
    endResetModel();
    emit usersChanged();
}

QVector<SshUser> AuthorizedKeysModel::users() const
{
    return mRows;
}

void AuthorizedKeysModel::load()
{
    QFile file(mFilename);

    bool success = file.open(QFile::ReadOnly);
    if(!success) {
        throwError(file);
    }

    QString fileContent = file.readAll();
    setUsers(toUsers(fileContent));
}

void AuthorizedKeysModel::save()
{
    QSaveFile file(mFilename);
    file.setDirectWriteFallback(true);
    bool success = file.open(QFile::WriteOnly);

    if(!success) {
        throwError(file);
    }

    QTextStream stream(&file);

    auto write = [&stream](const SshUser& row) {
        Q_ASSERT(row.isValid());
        stream << row.toString();
    };

    for(const auto& row : std::as_const(mRows)) {
        write(row);
        checkForFileError(file);
    }

    success = file.commit();
    if(!success) {
        throwError(file);
    }
}

void AuthorizedKeysModel::setFilename(const QString &filename) {
    if(mFilename != filename) {
        mFilename = std::move(filename);
        emit filenameChanged();
    }
}

QVector<SshUser> AuthorizedKeysModel::toUsers(QString publicKeyData)
{
    enum LineType {
        CommentLine,
        KeyLine,
        EmptyLine
    };

    enum PropertyType {
        Unknown,
        Name,
        Email,
    };

    struct Property {
        PropertyType key;
        QString value;
    };

    struct KeyComment {
        QString key;
        QString comment;
    };

    auto lineType = [](QString line) {
        QRegularExpression commentRegex(QStringLiteral("^\\s*#"));
        if(commentRegex.match(line).hasMatch()) {
            return CommentLine;
        } else if(line.trimmed().isEmpty()) {
            return EmptyLine;
        } else {
            return KeyLine;
        }
    };

    auto readProperty = [](QString line)->Property {
        QRegularExpression propertyRegex(QStringLiteral("^\\s*#(")
                                    + SshUser::nameKey()
                                    + QStringLiteral("|")
                                    + SshUser::emailKey()
                                    + QStringLiteral("):(.*?)\\s*$"));
        auto result = propertyRegex.match(line);

        if(result.hasMatch()) {
            const int propertyKeyIndex = 1;
            const int valueIndex = 2;

            if(result.captured(propertyKeyIndex) == SshUser::nameKey()) {
                return {Name, result.captured(valueIndex)};
            } else if(result.captured(propertyKeyIndex) == SshUser::emailKey()) {
                return {Email, result.captured(valueIndex)};
            }
        }
        return {Unknown, QString()};
    };

    auto parseKeyLine = [](QString line)->KeyComment {
        QRegularExpression keyRegex("^((?:\\w|-)+\\s+(?:.+?))\\s+(.*)$");

        auto result = keyRegex.match(line);
        if(result.hasMatch()) {
            //RSA key, comment
            return {result.captured(1), result.captured(2)};
        } else {
            return {QString(), QString()};
        }
    };

    auto addToRow = [lineType, readProperty, parseKeyLine](SshUser* row, const QString& line) {
        switch(lineType(line)) {

        case CommentLine: {
            auto property = readProperty(line);
            switch(property.key) {
            case Name:
                row->setName(property.value);
                break;
            case Email:
                row->setEmail(property.value);
                break;
            default:
                break;
            }
            break;
        }

        case KeyLine: {
            auto result = parseKeyLine(line);
            row->setKey(result.key);
            row->setComment(result.comment);
            break;
        }
        case EmptyLine:
            break;
        }
    };

    QVector<SshUser> users;
    SshUser row;
    QTextStream stream(&publicKeyData);
    while(!stream.atEnd()) {

        addToRow(&row, stream.readLine());

        if(row.isValid()) {
            users.append(row);
            row = SshUser(); //clear the row
        }
    }

    return users;
}

bool SshUser::keyValid(const QString &key) {
    return !key.isEmpty() && key.split(' ', Qt::SkipEmptyParts).size() == 2;
}


