//Our includes
#include "TestUtilities.h"
// #include "FieldModel.h"

//Qt includes
#include <QUuid>
#include <QJsonDocument>
#include <QDirIterator>

//Catch includes
#include <catch2/catch_test_macros.hpp>

TestUtilities::TestUtilities()
{

}

QDir TestUtilities::createUniqueTempDir()
{
    QDir tempDir = QDir::temp();
    auto tempDirId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    REQUIRE(tempDir.mkdir(tempDirId)); //If this fails the folder already exist, remove it, try again
    tempDir.cd(tempDirId);
    return tempDir;
}

QDir TestUtilities::moveToNewTempDirectory(const QDir &oldDirectory)
{
    auto newTemp = TestUtilities::createUniqueTempDir();

    QDir dir;
    REQUIRE(dir.rmdir(newTemp.absolutePath()));

    CHECK(oldDirectory.exists());
    CHECK(!newTemp.exists());
    INFO("Old direcotry:" << oldDirectory.absolutePath().toStdString());
    INFO("New directory:" << newTemp.absolutePath().toStdString());
    CHECK(dir.rename(oldDirectory.absolutePath(), newTemp.absolutePath()));
    CHECK(newTemp.exists());

    return newTemp;
}

std::ostream& operator<<(std::ostream& os, const QVariantMap& map)
{
    QJsonDocument doc = QJsonDocument::fromVariant(map);
    os << "\"" << doc.toJson(QJsonDocument::Compact).toStdString() << "\"";
    return os;
}

std::ostream& operator<<(std::ostream& os, const QModelIndex& index)
{
    os << "model:" << index.model() << " (" << index.row() << "," << index.column() << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, const QStringList& list) {
    for (int i = 0; i < list.size(); ++i) {
        os << list.at(i).toStdString();
        if (i != list.size() - 1)
            os << ", ";
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const QHash<int, QByteArray>& hash)
{
    os << "{ ";
    for(auto it = hash.begin(); it != hash.end(); ++it) {
        if(it != hash.begin()) {
            os << ", ";
        }
        os << it.key() << " : " << it.value().toStdString();
    }
    os << " }";
    return os;
}
