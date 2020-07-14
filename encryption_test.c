/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include <stdio.h>
#include <string.h>
#include "encryption.h"
#include "utils.h"
#include "logging.h"
#include "csr.h"
#include "lib/base64.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/openssl/pkcs7.h>
#include <wolfssl/openssl/pem.h>
#else
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#endif

int main(){

    char* json;
    EVP_PKEY* keys = generate_keypair("RSA", 2048);
    char* originalText = "The lazy dog was jumped over by the quick brown fox";
    encrypt((unsigned char*)originalText, keys, &json);
    log_info(json);
    char* plaintext = malloc(2048);
    decrypt((unsigned char*)json, keys, &plaintext);
    log_info(plaintext);
    bool match = strcmp((const char*)originalText, (const char*)plaintext) == 0;
    log_info("Decrypted plaintext matches original plaintext: %s", match ? "true" : "false");
    free(json);
    free(plaintext);
    log_info("Encryption/decryption test 1 completed.");    

    struct encryptionContext* context = buildContext((unsigned char*)originalText, NULL);
    log_info("Beginning encryption");
    encryptContext(context);
    log_info("Serializing");
    json = encryptionContext_toJson(context);
    log_info("Deserializing: %s", json);
    struct encryptionContext* contextNew = encryptionContext_fromJson(json, context->keys);
    log_info("ciphertext comparison 1: %d %d", strlen((char*)context->ciphertext), strlen((char*)contextNew->ciphertext));
    log_info("ciphertext comparison 2: %d %d", context->ciphertextLength, contextNew->ciphertextLength);
 
    json = encryptionContext_toJson(contextNew);
    log_info("New context:...%s", json);
   
    freeContext(context, false);
    log_info("Beginning decryption");
    decryptContext(contextNew);

    log_info("Plaintext: declared length: %d string length: %d", contextNew->plaintextLength, strlen((const char*)contextNew->plaintext));
    log_info((const char*)contextNew->plaintext);
    match = strcmp((const char*)originalText, (const char*)contextNew->plaintext) == 0;
    log_info("Decrypted plaintext matches original plaintext: %s", match ? "true" : "false");
    freeContext(contextNew, true);
    log_info("Encryption/decryption test 2 completed");
}
