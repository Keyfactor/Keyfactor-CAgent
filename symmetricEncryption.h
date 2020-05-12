/*
* Copyright 2018, Certified Security Solutions
* All Rights Reserved.
* This is UNPUBLISHED PROPRIETARY SOURCE CODE of Certified Security Solutions;
* the contents of this file may not be disclosed to third parties, copied
* or duplicated in any form, in whole or in part, without the prior
* written permission of Certified Security Solutions.
*/

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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

bool symmetricDecrypt(unsigned char* ciphertext, unsigned int ciphertextLength, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext, unsigned int* plaintextLength);

bool symmetricEncrypt(unsigned char* plaintext, unsigned int plaintextLength, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext, unsigned int* ciphertextLength);

bool encryptKey(EVP_PKEY* key, unsigned char* aeskey, unsigned int keylen, unsigned char* outkey, unsigned int* outlen);
