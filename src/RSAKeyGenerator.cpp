//Our includes
#include "RSAKeyGenerator.h"

//OpenSSL includes
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>

//Qt includes
#include <QtGlobal>

//Windows only?
#ifdef Q_OS_WINDOWS
#include <openssl/applink.c>
#endif

//Std includes
#include <cassert>
#include <memory>
using std::unique_ptr;

//Qt includes
#include <QStandardPaths>
#include <QFileInfo>
#include <QDebug>

static unsigned char pSshHeader[11] = { 0x00, 0x00, 0x00, 0x07, 0x73, 0x73, 0x68, 0x2D, 0x72, 0x73, 0x61};

static int SshEncodeBuffer(unsigned char *pEncoding, int bufferLen, unsigned char* pBuffer)
{
    int adjustedLen = bufferLen, index;
    if (*pBuffer & 0x80)
    {
        adjustedLen++;
        pEncoding[4] = 0;
        index = 5;
    }
    else
    {
        index = 4;
    }
    pEncoding[0] = (unsigned char) (adjustedLen >> 24);
    pEncoding[1] = (unsigned char) (adjustedLen >> 16);
    pEncoding[2] = (unsigned char) (adjustedLen >>  8);
    pEncoding[3] = (unsigned char) (adjustedLen      );
    memcpy(&pEncoding[index], pBuffer, bufferLen);
    return index + bufferLen;
}



//Some docs on this https://stackoverflow.com/questions/1011572/convert-pem-key-to-ssh-rsa-format
int pem_to_openssh(const char* pemPublicKey,  const char* description, const char* openSSHPublicKey)
{
    int iRet = 0;
    int nLen = 0, eLen = 0;
    int encodingLength = 0;
    int index = 0;
    unsigned char *nBytes = NULL, *eBytes = NULL;
    unsigned char* pEncoding = NULL;
    FILE* pFile = NULL;
    FILE* openSSHFile = NULL;
    EVP_PKEY *pPubKey = NULL;
    RSA* pRsa = NULL;
    BIO *bio, *b64;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    pFile = fopen(pemPublicKey, "rt");
    if (!pFile)
    {
        printf("Failed to open the given file\n");
        iRet = 2;
        goto error;
    }

    pPubKey = PEM_read_PUBKEY(pFile, NULL, NULL, NULL);
    if (!pPubKey)
    {
        printf("Unable to decode public key from the given file: %s\n", ERR_error_string(ERR_get_error(), NULL));
        iRet = 3;
        goto error;
    }

    if (EVP_PKEY_id(pPubKey) != EVP_PKEY_RSA)
    {
        printf("Only RSA public keys are currently supported\n");
        iRet = 4;
        goto error;
    }

    pRsa = EVP_PKEY_get1_RSA(pPubKey);
    if (!pRsa)
    {
        printf("Failed to get RSA public key : %s\n", ERR_error_string(ERR_get_error(), NULL));
        iRet = 5;
        goto error;
    }

    // reading the modulus
    const BIGNUM *n;
    const BIGNUM *e;
    RSA_get0_key(pRsa, &n, &e, NULL);
    nLen = BN_num_bytes(n);
    nBytes = (unsigned char*) malloc(nLen);
    BN_bn2bin(n, nBytes);

    // reading the public exponent
    eLen = BN_num_bytes(e);
    eBytes = (unsigned char*) malloc(eLen);
    BN_bn2bin(e, eBytes);

    encodingLength = 11 + 4 + eLen + 4 + nLen;
    // correct depending on the MSB of e and N
    if (eBytes[0] & 0x80)
        encodingLength++;
    if (nBytes[0] & 0x80)
        encodingLength++;

    pEncoding = (unsigned char*) malloc(encodingLength);
    memcpy(pEncoding, pSshHeader, 11);

    index = SshEncodeBuffer(&pEncoding[11], eLen, eBytes);
    index = SshEncodeBuffer(&pEncoding[11 + index], nLen, nBytes);

    openSSHFile = fopen(openSSHPublicKey, "w");

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_fp(openSSHFile, BIO_NOCLOSE);
    BIO_printf(bio, "ssh-rsa ");
    bio = BIO_push(b64, bio);
    BIO_write(bio, pEncoding, encodingLength);
    BIO_flush(bio);
    bio = BIO_pop(b64);
    BIO_printf(bio, " %s\n", description);
    BIO_flush(bio);
    BIO_free_all(bio);
    BIO_free(b64);

    fclose(openSSHFile);

error:
    if (pFile)
        fclose(pFile);
    if (pRsa)
        RSA_free(pRsa);
    if (pPubKey)
        EVP_PKEY_free(pPubKey);
    if (nBytes)
        free(nBytes);
    if (eBytes)
        free(eBytes);
    if (pEncoding)
        free(pEncoding);

    EVP_cleanup();
    ERR_free_strings();
    return iRet;
}


RSAKeyGenerator::RSAKeyGenerator()
{

}

//will load $HOME/.ssh/rsa_id.pub or application/.ssh keys or create new ones
void RSAKeyGenerator::loadOrGenerate()
{
    auto setKeyPaths = [this](const QDir& keyDir) {
        auto fullPrivateKeyPath = keyDir.absoluteFilePath(defaultPrivateKeyFilename());
        auto fullPublicKeyPath = keyDir.absoluteFilePath(defaultPublicKeyFilename());

        auto keysExist = [=]() {
            return QFile::exists(fullPrivateKeyPath)
                    && QFile::exists(fullPublicKeyPath);
        };

        if(keysExist()) {
            mPrivateKeyPath = fullPrivateKeyPath;
            mPublicKeyPath = fullPublicKeyPath;
            return true;
        } else {
            return false;
        }
    };

    if(setKeyPaths(homeKeyDirectory())) {
        return;
    } else if(setKeyPaths(appKeyDirectory())) {
        return;
    } else {
        generate();
    }
}

//Regenerates the keys and updates the public and private key path
//From https://stackoverflow.com/questions/5927164/how-to-generate-rsa-private-key-using-openssl
void RSAKeyGenerator::generate()
{
    int rc;

    using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
    using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
    using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
    using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

    auto dir = appKeyDirectory();
    dir.mkpath(".");

    QByteArray privateKeyFilename = dir.absoluteFilePath(defaultPrivateKeyFilename()).toLocal8Bit();
    QByteArray publicKeyPEMFilename = dir.absoluteFilePath(defaultPublicKeyPEMFilename()).toLocal8Bit();
    QByteArray publicKeyFilename = dir.absoluteFilePath(defaultPublicKeyFilename()).toLocal8Bit();

    { //Scoped here, because destroying the file handle flushes (writes) it to disk
        RSA_ptr rsa(RSA_new(), ::RSA_free);
        BN_ptr bn(BN_new(), ::BN_free);

        rc = BN_set_word(bn.get(), RSA_F4);
        assert(rc == 1);

        // Generate key
        rc = RSA_generate_key_ex(rsa.get(), 3072, bn.get(), NULL);
        assert(rc == 1);

        // Convert RSA to PKEY
        EVP_KEY_ptr pkey(EVP_PKEY_new(), ::EVP_PKEY_free);
        rc = EVP_PKEY_set1_RSA(pkey.get(), rsa.get());
        assert(rc == 1);


        BIO_FILE_ptr pem1(BIO_new_file(publicKeyPEMFilename, "w"), ::BIO_free);
        BIO_FILE_ptr pem5(BIO_new_file(privateKeyFilename, "w"), ::BIO_free);

        // Write public key in PKCS PEM
        rc = PEM_write_bio_PUBKEY(pem1.get(), pkey.get());
        assert(rc == 1);

        // Write private key in Traditional PEM
        rc = PEM_write_bio_RSAPrivateKey(pem5.get(), rsa.get(), NULL, NULL, 0, NULL, NULL);
        assert(rc == 1);
    }

    pem_to_openssh(publicKeyPEMFilename, "MapWhere", publicKeyFilename);

    mPublicKeyPath = publicKeyFilename;
    mPrivateKeyPath = privateKeyFilename;
}

QString RSAKeyGenerator::knownHostsPath() const
{
    return QFileInfo(publicKeyPath()).dir().absoluteFilePath("known_hosts");
}

QByteArray RSAKeyGenerator::publicKey() const
{
    if(publicKeyPath().isEmpty()) {
        return QByteArray();
    }

    QFile file(publicKeyPath());
    auto success = file.open(QFile::ReadOnly);
    if(success) {
        return file.readAll().trimmed();
    }

    return QByteArray();

}

QDir RSAKeyGenerator::homeKeyDirectory()
{
    return QDir(QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.ssh");
}

QDir RSAKeyGenerator::appKeyDirectory()
{
    return QDir(QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) + "/.ssh");
}

