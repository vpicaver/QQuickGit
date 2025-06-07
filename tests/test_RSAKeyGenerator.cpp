//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "RSAKeyGenerator.h"

//Qt includes
#include <QFileInfo>

TEST_CASE("RSAKeyGenerator should generate keys", "[RSAKeyGenerator]") {
    RSAKeyGenerator key;

    CHECK(!QFileInfo::exists(key.publicKeyPath()));
    CHECK(key.publicKeyPath().isEmpty() == true);
    CHECK(!QFileInfo::exists(key.privateKeyPath()));
    CHECK(key.publicKey().isEmpty() == true);

    SECTION("Make sure generate works") {
        key.generate();

        INFO("Public key:" + key.publicKeyPath().toStdString());
        INFO("Private key:" + key.privateKeyPath().toStdString());

        CHECK(QFileInfo::exists(key.publicKeyPath()));
        CHECK(QFileInfo::exists(key.privateKeyPath()));

        auto publicKey = key.publicKey();

        CHECK(publicKey.isEmpty() == false);
        CHECK(publicKey.left(7) == "ssh-rsa");
    }

    SECTION("Make sure load works") {

        //Remove old application keys
        auto homePrivate = key.homeKeyDirectory().absoluteFilePath(key.defaultPrivateKeyFilename());
        auto homePublic = key.homeKeyDirectory().absoluteFilePath(key.defaultPublicKeyFilename());

        auto homeKeysExist = [=]() {
            return QFile::exists(homePrivate) && QFile::exists(homePublic);
        };

        SECTION("Keys exist in user home .ssh") {
            if(homeKeysExist()) {
                key.loadOrGenerate();
                CHECK(key.publicKeyPath().toStdString() == homePublic.toStdString());
                CHECK(key.privateKeyPath().toStdString() == homePrivate.toStdString());
            }
        }

        bool shouldRestoreHomeSSHKeys = false;
        QString oldHomePrivate;
        QString oldHomePublic;

        auto moveToOld = [](const QString& filename) {
            QFile file(filename);
            auto oldFilename = filename + ".old";
            REQUIRE(file.rename(oldFilename));
            return oldFilename;
        };

        auto restoreOriginal = [](const QString& filename, const QString& original) {
            QFile file(filename);
            REQUIRE(file.rename(original));
        };

        if(homeKeysExist()) {
            oldHomePrivate = moveToOld(homePrivate);
            oldHomePublic = moveToOld(homePublic);

            shouldRestoreHomeSSHKeys = true;
        }

        auto appPrivateKey = key.appKeyDirectory().absoluteFilePath(key.defaultPrivateKeyFilename());
        auto appPublicKey = key.appKeyDirectory().absoluteFilePath(key.defaultPublicKeyFilename());

        QFile::remove(appPrivateKey);
        QFile::remove(appPublicKey);

        SECTION("No keys exist in user home .ssh or app config") {
            //This shouldn't create keys in the home directory
            CHECK(homeKeysExist() == false);

            key.loadOrGenerate();
            CHECK(key.publicKeyPath() == appPublicKey);
            CHECK(key.privateKeyPath() == appPrivateKey);

            CHECK(homeKeysExist() == false);

            auto publicKeyData = key.publicKey();

            SECTION("Keys don't exist in user home but exist in app .ssh") {
                RSAKeyGenerator key2;
                key2.loadOrGenerate();

                CHECK(key2.publicKeyPath() == appPublicKey);
                CHECK(key2.privateKeyPath() == appPrivateKey);

                CHECK(publicKeyData == key2.publicKey());
            }
        }

        if(shouldRestoreHomeSSHKeys) {
            restoreOriginal(oldHomePrivate, homePrivate);
            restoreOriginal(oldHomePublic, homePublic);
        }
    }
}
