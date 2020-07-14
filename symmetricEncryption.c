/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/openssl/pkcs7.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/err.h>
#else
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include "symmetricEncryption.h"
#include "logging.h"

bool symmetricDecrypt(unsigned char* ciphertext, unsigned int ciphertextLength, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext, unsigned int* plaintextLength){
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx){
        log_error("Unable to create decryption context");
        return false;
    }

    int result = EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv);
    if (result != 1) {
        log_error("Unable to initialize decryption context.");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    result = EVP_DecryptUpdate(ctx, plaintext, (int *)plaintextLength, ciphertext, ciphertextLength);
    if (result != 1){
        log_error("Unable to decrypt cyphertext");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int extraLength = 0;
    result = EVP_DecryptFinal(ctx, plaintext + *plaintextLength, &extraLength);
    if (result != 1){
        log_error("Unable to finalize decryption");
        char errBuf[120];
        unsigned long errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("Unable to finalize decryption: %s", errBuf);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    *plaintextLength += extraLength;
    plaintext[*plaintextLength] = '\0';

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool symmetricEncrypt(unsigned char* plaintext, unsigned int plaintextLength, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext, unsigned int* ciphertextLength){
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx){
        log_error("Unable to create encryption context");
        return false;
    }

    int result = EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);
    if (result != 1) {
        log_error("Unable to initialize encryption context.");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    result = EVP_EncryptUpdate(ctx, ciphertext, (int *)ciphertextLength, plaintext, plaintextLength);
    if (result != 1){
        log_error("Unable to encrypt plaintext");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int extraLength = 0;
    result = EVP_EncryptFinal(ctx, ciphertext + *ciphertextLength, &extraLength);
    if (result != 1){
        log_error("Unable to finalize encryption");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    *ciphertextLength += extraLength;
    ciphertext[*ciphertextLength] = '\0';

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool encryptKey(EVP_PKEY* key, unsigned char* aeskey, unsigned int keylen, unsigned char* outkey, unsigned int* outlen){
    RSA* rsa = EVP_PKEY_get1_RSA(key);
    int len = RSA_public_encrypt(keylen, aeskey, outkey, rsa, RSA_PKCS1_PADDING);
    *outlen = len;
    if(len == 0){
        char errBuf[120];
        unsigned long errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("Unable to encrypt key: %s", errBuf);
        return false;
    }
    outkey[len] = '\0';
    return true;
}


