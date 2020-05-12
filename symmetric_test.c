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
#include "encryption.h"
#include "utils.h"
#include "logging.h"
#include "csr.h"
#include "lib/base64.h"
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
#else
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#endif

int main(int argc, char* argv[]){
	unsigned char* key = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        int b64len = 0;
        FILE* rsakey = fopen("anothertest.pem", "r");
        EVP_PKEY* pkey = NULL;
        X509* x509 = NULL;
        
        x509 = PEM_read_X509(rsakey, NULL, NULL, NULL);
        
        pkey = X509_get_pubkey(x509);
        if(pkey == NULL) log_info("null");
	
        unsigned char* encryptedKey = malloc(1024);
        unsigned int encLen = 0;

        encryptKey(pkey, key, 32, encryptedKey, &encLen);
        log_info("%d", encLen);

        log_info(base64_encode(encryptedKey, encLen, false, &b64len));










        unsigned char* plaintext = "The reigning sheik's eight feisty neighbors, being neither foreign counterfeiters nor overweight atheists, never deigned to leisurely unveil their veiny heir's weird height as forfeit for either heifer's seismic protein seizures.";
	unsigned int plaintextLength = strlen(plaintext);
	unsigned char* iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        log_info(base64_encode(iv, 16, false, &b64len));
        unsigned char* ciphertext = malloc(1024);
        unsigned int ciphertextLength = 0;
	symmetricEncrypt(plaintext, plaintextLength, key, iv, ciphertext, &ciphertextLength);
        log_info(base64_encode(ciphertext, ciphertextLength, false, &b64len));

        unsigned char* newplain = malloc(1024);
        unsigned int newsize;

        symmetricDecrypt(ciphertext, ciphertextLength, key, iv, newplain, &newsize);

        log_info(newplain);
        bool match = strcmp((const char*)plaintext, (const char*)newplain) == 0;
        log_info("Decrypted plaintext matches original plaintext: %s", match ? "true" : "false");
	


        return 0;
}
