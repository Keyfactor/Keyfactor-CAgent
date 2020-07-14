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
#include "encryption.h"
#include "logging.h"
#include "csr.h"
#include "lib/json.h"
#include "lib/base64.h"

bool decrypt(unsigned char* json, EVP_PKEY* keys, char** plaintext){
    struct encryptionContext* context = encryptionContext_fromJson((char*)json, keys);
    if(!context){
        return false;
    }
    if(!decryptContext(context)){
        return false;
    }
    *plaintext = (char*)context->plaintext;
    freeContext(context, false);
    return true;
}

bool encrypt(unsigned char* plaintext, EVP_PKEY* keys, char** json){
    struct encryptionContext* context = buildContext(plaintext, keys);
    if(!context){
        return false;
    }
    if(!encryptContext(context)){
        return false;
    }
    *json = encryptionContext_toJson(context);
    freeContext(context, false);
    return true;
}

struct encryptionContext* buildContext(unsigned char* plaintext, EVP_PKEY* keys){
    struct encryptionContext* context = malloc(sizeof(struct encryptionContext));
    if(!context){
        log_error("encryption-buildContext-Could not allocate memory for encryption context");
        return NULL;
    }
    unsigned int len = strlen((const char*)plaintext);
    context->plaintext = malloc(len);
    if(plaintext) {
        strcpy((char*)context->plaintext, (const char*)plaintext);
    }
    context->plaintextLength = len;
    if(keys){
        context->keys = keys;
    } else {
        context->keys = generate_keypair("RSA", RSA_KEY_SIZE);
    }
    context->ciphertext = malloc(len+32);
    context->iv = malloc(AES_IV_SIZE);
    context->encryptedSessionKey = malloc((RSA_KEY_SIZE/8)+1);
    return context;
} 

void freeContext(struct encryptionContext* context, bool freeKeys){
    if(!context) return;
    // if(context->plaintext) free(context->plaintext); // Do not want for json encrypt/decrypt
    if(context->encryptedSessionKey) free(context->encryptedSessionKey);
    if(freeKeys && context->keys) free(context->keys);
    if(context->ciphertext) free(context->ciphertext);
    if(context->iv) free(context->iv);
    free(context);
}

char* encryptionContext_toJson(struct encryptionContext* context){
    if(!context) return NULL;
    if((!context->ciphertext) || context->ciphertextLength == 0){
        log_error("encryption-encryptionContext_toJson-No ciphertext provided, cannot serialize context");
        return NULL;
    }
    char* jsonString = NULL;

    JsonNode* jsonRoot = json_mkobject();
    size_t length;
    char* encoded = base64_encode(context->ciphertext, context->ciphertextLength, false, &length);
    json_append_member(jsonRoot, "Ciphertext", json_mkstring(encoded));
    encoded = base64_encode(context->iv, AES_IV_SIZE, false, &length);
    json_append_member(jsonRoot, "IV", json_mkstring(encoded));
    encoded = base64_encode(context->encryptedSessionKey, context->encryptedSessionKeyLength, false, &length);
    json_append_member(jsonRoot, "encryptedSessionKey", json_mkstring(encoded));
    json_append_member(jsonRoot, "AlgorithmOID", json_mkstring(AES_ALGORITHM_OID));
    jsonString = json_encode(jsonRoot);
    json_delete(jsonRoot);
    return jsonString;
}

struct encryptionContext* encryptionContext_fromJson(char* jsonString, EVP_PKEY* privateKey){
    struct encryptionContext* context = buildContext((unsigned char*)"", privateKey);
    context->keys = privateKey;
    JsonNode* jsonRoot = json_decode(jsonString);
    size_t length = 0;
    
    char* algorithmOID = json_get_member_string(jsonRoot, "AlgorithmOID");
    if (strcmp(algorithmOID, AES_ALGORITHM_OID)){
        log_info("encryption-encryptionContext_fromJson-Unexpected encryption algorithm encountered");
    }

    char* ciphertext = json_get_member_string(jsonRoot, "Ciphertext");
    context->ciphertext = (unsigned char*)base64_decode(ciphertext, strlen(ciphertext), &length);
    context->ciphertextLength = length;
    context->ciphertext[context->ciphertextLength] = '\0';
    context->plaintext = malloc(length);
    context->plaintextLength = length;
    
    char* iv = json_get_member_string(jsonRoot, "IV");
    context->iv = (unsigned char*)base64_decode(iv, strlen(iv), &length);
    
    char* encryptedSessionKey = json_get_member_string(jsonRoot, "encryptedSessionKey");
    context->encryptedSessionKey = (unsigned char*)base64_decode(encryptedSessionKey, strlen(encryptedSessionKey), &length);
    context->encryptedSessionKeyLength = length;

    json_delete(jsonRoot);
    return context;
}

bool decryptContext(struct encryptionContext* context){
    return _decrypt(context->keys, context->ciphertext, context->ciphertextLength, context->encryptedSessionKey, context->encryptedSessionKeyLength, context->iv, context->plaintext, &(context->plaintextLength));
}

bool encryptContext(struct encryptionContext* context){
    return _encrypt(&(context->keys), context->plaintext, context->plaintextLength, &(context->encryptedSessionKey), (int *)&(context->encryptedSessionKeyLength), context->iv, context->ciphertext, &(context->ciphertextLength));
}

bool _decrypt(EVP_PKEY* privateKey, unsigned char* ciphertext, unsigned int ciphertextLength, unsigned char* encryptedSessionKey, unsigned int encryptedSessionKeyLength, unsigned char* iv, unsigned char* plaintext, unsigned int* plaintextLength){
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx){
        log_error("encryption-_decrypt-Unable to create decryption context.");
        return false;
    }

    int result = EVP_OpenInit(ctx, EVP_aes_256_cbc(), encryptedSessionKey, encryptedSessionKeyLength, iv, privateKey);
    if (result != 1) {
        char errBuf[120];
        unsigned long errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("encryption-_decrypt-Unable to initialize decryption context: %s", errBuf);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    result = EVP_OpenUpdate(ctx, plaintext, (int*)plaintextLength, ciphertext, ciphertextLength);
    if (result != 1){
        char errBuf[120];
        unsigned long errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("encryption-_decrypt-Unable to decrypt cyphertext: %s", errBuf);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int extraLength = 0;
    result = EVP_OpenFinal(ctx, plaintext + *plaintextLength, &extraLength);
    if (result != 1){
        char errBuf[120];
        unsigned long errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("encryption-_decrypt-Unable to finalize decryption: %s", errBuf);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    *plaintextLength += extraLength;
    plaintext[*plaintextLength] = '\0';

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool _encrypt(EVP_PKEY** publicKey, unsigned char* plaintext, int plaintextLength, unsigned char** encryptedSessionKey, int* encryptedSessionKeyLength, unsigned char* iv, unsigned char* ciphertext, unsigned int* ciphertextLength){
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx){
        log_error("encryption-_encrypt-Unable to create encryption context");
        return false;
    }
    
    int result = EVP_SealInit(ctx, EVP_aes_256_cbc(), encryptedSessionKey, encryptedSessionKeyLength, iv, publicKey, 1);
    if (result != 1) {
        char errBuf[120];
        unsigned long errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("encryption-_encrypt-Unable to initialize encryption context: %s", errBuf);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
   
    result = EVP_SealUpdate(ctx, ciphertext, (int *)ciphertextLength, plaintext, plaintextLength);
    if (result != 1){
        char errBuf[120];
        unsigned long errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("encryption-_encrypt-Unable to encrypt plaintext: %s", errBuf);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int extraLength = 0;
    result = EVP_SealFinal(ctx, ciphertext + *ciphertextLength, &extraLength);
    if (result != 1){
        char errBuf[120];
        unsigned long errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("encryption-_encrypt-Unable to finalize encryption: %s", errBuf);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    *ciphertextLength += extraLength;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}
