/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#ifndef CSS_ECDH_H_
#define CSS_ECDH_H_

#include <stdbool.h>

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/evp.h>
#else
#include <openssl/evp.h>
#endif

bool encrypt_ecdh(unsigned char* plaintext, size_t plaintextLen, EVP_PKEY* recipientKey, char** json);

bool decrypt_ecdh(char* json, EVP_PKEY* recipientKey, unsigned char** plaintext, size_t* plaintextLen);

#endif
