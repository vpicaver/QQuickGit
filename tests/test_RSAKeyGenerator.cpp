//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "RSAKeyGenerator.h"

//Qt includes
#include <QFileInfo>

using namespace QQuickGit;

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

        auto homeDir = key.homeKeyDirectory();
        auto homeKeysExist = [=]() {
            for(const auto& filename : RSAKeyGenerator::defaultPrivateKeyFilenames()) {
                if(QFile::exists(homeDir.absoluteFilePath(filename))) {
                    return true;
                }
            }
            return QFile::exists(homeDir.absoluteFilePath(key.defaultPrivateKeyFilename()));
        };

        SECTION("Keys exist in user home .ssh") {
            if(homeKeysExist()) {
                key.loadOrGenerate();
                CHECK(key.privateKeyPath().startsWith(homeDir.absolutePath()));
            }
        }

        auto appPrivateKey = key.appKeyDirectory().absoluteFilePath(key.defaultPrivateKeyFilename());
        auto appPublicKey = key.appKeyDirectory().absoluteFilePath(key.defaultPublicKeyFilename());

        QFile::remove(appPrivateKey);
        QFile::remove(appPublicKey);

        SECTION("No keys exist in user home .ssh or app config") {
            if(homeKeysExist()) {
                return;
            }
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
    }
}
