/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file csr.h */
#ifndef __CSR_H__
#define __CSR_H__

#include "dto.h"
#include "config.h"

/**
 * Generate a new keypair by calling the correct function in the
 * SSL wrapper layer
 *
 * @param  - [Input] keyType: The type of key (ECC or RSA)
 * @param  - [Input] keySize: The size of the key (192, 256, etc.)
 * @return - success: true
 *           failure: false
 */
#if defined(__TPM__)
bool generate_keypair(const char* keyType, int keySize, const char* path);
#else
bool generate_keypair(const char* keyType, int keySize);
#endif

/**
 * Request the crypto layer to generate a new CSR using the subject provided.
 * This request expects an ASCII CSR to be returned.
 *
 * @param  - [Input]  : asciiSubject string with the subject line
 *                      e.g., CN=1234,OU=NA,O=Keyfactor,C=US
 * @param  - [Output] : csrLen the # of ASCII characters in the csr
 * @return - success : the CSR string minus the header and footer
 *           failure : NULL
 */
char* generate_csr(const char* asciiSubject, size_t* csrLen, \
	char** pMessage, enum AgentApiResultStatus* pStatus); // GM Specific

/**
 * Request the crypto layer to save the cert and key to the locations requested 
 * The crypto layer uses the temporary key it has generated to store into the
 * location requested.
 *
 * @param  - [Input] : storePath = the store location for the cert
 * @param  - [Input] : keyPath = the location to save the key, if NULL or blank, 
 *                               store the encoded key appended to the cert.
 * @param  - [Input] : password = the password for the private key
 * @param  - [Input] : cert = The cert in an ASCII encoded string
 * @param  - [Output]: pMessage = a string array containing any messages
 *                                we want to pass back to the calling function
 * @param  - [Output]: pStatus = The status code to report back to the API
 * @return - success : 0
 *           failure : an unsigned long error code
 */
unsigned long save_cert_key(const char* storePath, const char* keyPath, \
	const char* password, const char* cert, char** pMessage, \
	enum AgentApiResultStatus* pStatus);
#endif /* __CSR_H__ */
