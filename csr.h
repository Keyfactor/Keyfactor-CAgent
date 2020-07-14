/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#ifndef CSS_CSR_H_
#define CSS_CSR_H_

#include "dto.h"
#include "config.h"

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/x509.h>
#else
#include <openssl/evp.h>
#include <openssl/x509.h>
#endif

#define RSA_DEFAULT_EXP 65537

EVP_PKEY* generate_keypair(const char* keyType, int keySize);

X509_NAME* parse_subject(const char* subject);

char* generate_csr(EVP_PKEY* keyPair, X509_NAME* subject);

unsigned long save_cert_key(const char* storePath, const char* keyPath, const char* password, const char* cert, const EVP_PKEY* privKey, char** pMessage, enum AgentApiResultStatus* pStatus);
#endif /* CSR_H_ */
