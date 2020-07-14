/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#ifndef CSS_VERIFY_H
#define CSS_VERIFY_H

#include <stdbool.h>


#define EKU_CODE_SIGNING "1.3.6.1.5.5.7.3.3"

bool verify_detached_signature(const unsigned char* fileBytes, unsigned int fileSize, const unsigned char* sigBytes, unsigned int sigSize, const char* signingCertPath, bool verifyChain, const char* trustCertPath, const char* hashAlg);


bool verify_pkcs7_signature(const unsigned char* fileBytes, unsigned int fileSize, const unsigned char* sigBytes, unsigned int sigSize, const char* signingCertPath, bool verifyChain, const char* trustCertPath);

bool verify_timestamp(const unsigned char* sigBytes, unsigned int sigSize, const char* trustCertPath);

#endif
