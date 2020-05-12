/*
* Copyright 2018, Certified Security Solutions
* All Rights Reserved.
* This is UNPUBLISHED PROPRIETARY SOURCE CODE of Certified Security Solutions;
* the contents of this file may not be disclosed to third parties, copied
* or duplicated in any form, in whole or in part, without the prior
* written permission of Certified Security Solutions.
*/

#include <stdio.h>
#include <string.h>
#include "symmetricEncryption.h"
#include "encryption.h"
#include "utils.h"
#include "logging.h"
#include "csr.h"
#include "lib/base64.h"
#include "lib/json.h"
#include "inventory.h"
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
#include <wolfssl/openssl/rand.h>
#else
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#endif

int main(int argc, char* argv[]){
    char* payloadPath = argv[1];
    char* keyPath = argv[2];
    char* outputPath = argv[3];

    FILE* cert = fopen(keyPath, "r");
    X509* x509 = PEM_read_X509(cert, NULL, NULL, NULL);
    EVP_PKEY* pkey = X509_get_pubkey(x509);

    FILE* payload = fopen(payloadPath, "r");
    fseek (payload, 0, SEEK_END);
    size_t length = ftell (payload);
    fseek (payload, 0, SEEK_SET);
    char* contents = malloc (length);
    fread (contents, 1, length, payload);
    fclose (payload);
    fclose (cert);

    unsigned char* key = malloc(32);
    unsigned char* iv = malloc(AES_IV_SIZE);
    int randomBytes = RAND_bytes(key, 32);
    if (randomBytes != 1){
        char errBuf[120];
        unsigned long errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("Unable to generate AES key: %s", errBuf);
        free(key);
        free(iv);
        return false;
    }
    randomBytes = RAND_bytes(iv, AES_IV_SIZE);
    if (randomBytes != 1){
        char errBuf[120];
        unsigned long errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("Unable to generate AES key: %s", errBuf);
        free(key);
	free(iv);
        return false;
    }
    unsigned char* encryptedKey = malloc(1024);
    size_t encLen = 0;
    encryptKey(pkey, key, 32, encryptedKey, (unsigned int*)&encLen);
    for(int i = 0; i < encLen; i++){
       // log_info("%d",encryptedKey[i]);
    }
    unsigned char* ciphertext = malloc(length+256);
    size_t ciphertextLength = 0;
    symmetricEncrypt((unsigned char*)contents, length, key, iv, ciphertext, (unsigned int*)&ciphertextLength);

    JsonNode* jsonRoot = json_mkobject();
    char* encoded = base64_encode(ciphertext, ciphertextLength, false, &length);

    json_append_member(jsonRoot, "Ciphertext", json_mkstring(encoded));
    free(encoded);
    encoded = base64_encode(iv, AES_IV_SIZE, false, &length);
    json_append_member(jsonRoot, "IV", json_mkstring(encoded));
    free(encoded);
    encoded = base64_encode(encryptedKey, encLen, false, &length);
    json_append_member(jsonRoot, "encryptedSessionKey", json_mkstring(encoded));
    free(encoded);
    json_append_member(jsonRoot, "AlgorithmOID", json_mkstring(AES_ALGORITHM_OID));
    json_append_member(jsonRoot, "filename", json_mkstring(payloadPath));
    char* jsonString = json_encode(jsonRoot);
    json_delete(jsonRoot);
    free(encryptedKey);
    free(ciphertext);
    
    FILE* output = fopen(outputPath, "w");
    fwrite(jsonString, sizeof(char), strlen(jsonString), output);
    fclose(output);
    free(contents);
    free(jsonString);
    free(key);
    free(iv);
    return 0;
}
