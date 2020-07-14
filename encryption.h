/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#ifndef CSS_ENCRYPTION_H
#define CSS_ENCRYPTION_H

// Bit length of RSA keys to be generated when keys are not provided
#define RSA_KEY_SIZE 2048
// Initialization vector length. 16 for AES 256
#define AES_IV_SIZE 16
// OID for the AES 256 CBC mode algorithm used for symmetric key
#define AES_ALGORITHM_OID "2.16.840.1.101.3.4.1.42"

#include <stdbool.h>

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/evp.h>
#else
#include <openssl/evp.h>
#endif

// Internal context structure
struct encryptionContext{
    EVP_PKEY* keys;
    unsigned char* plaintext;
    unsigned int plaintextLength;
    unsigned char* ciphertext;
    unsigned int ciphertextLength;
    unsigned char* encryptedSessionKey;
    unsigned int encryptedSessionKeyLength;
    unsigned char* iv;
};


/////////////////// Public methods ////////////////////////////////////////////

/* Recover plaintext from json envelope created by encrypt call below when private key is supplied.
   json - Json object containing 4 strings:
              Ciphertext: Base64 representation of the original plaintext encrypted with the symmetric key.
              encryptedSessionKey: Base64 representation of the symmetric key encrypted with the asymmetric public key.
              IV: Base64 representation of the initialization vector generated for encryption.
              AlgorithmOID: Object ID of the symmetric algorithm used for encryption.
   keys - EVP_PKEY object containing the RSA private key (and optional public key) used for encryption.
   plaintext - Pointer which will be assigned to a string representation of the original plaintext after decryption.
               User is responsible for freeing this string.
   Returns - True if decryption is successful, false if not.
*/
bool decrypt(unsigned char* json, EVP_PKEY* keys, char** plaintext);

/* Encrypt given plaintext with given public key and write encryption context to json envelope.
   json - Pointer which will be assigned a string representing a json object containing 4 string fields:
              Ciphertext: Base64 representation of the original plaintext encrypted with the symmetric key.
              encryptedSessionKey: Base64 representation of the symmetric key encrypted with the asymmetric public key.
              IV: Base64 representation of the initialization vector generated for encryption.
              AlgorithmOID: Object ID of the symmetric algorithm used for encryption.
          User is responsible for freeing this string after usage.
   keys - EVP_PKEY object containing the RSA public key (and optional private key) used for encryption.
   plaintext - Text to be encrypted.
   Returns - True if encryption is successful, false if not.
*/
bool encrypt(unsigned char* plaintext, EVP_PKEY* keys, char** json);



/////////////////// Internal methods //////////////////////////////////////////

// Build encryption context for further processing, optionally generating an RSA keypair if one is not provided.
struct encryptionContext* buildContext(unsigned char* plaintext, EVP_PKEY* keypair);

// Free memory used by encryption context. DOES NOT FREE PLAINTEXT STRING.
void freeContext(struct encryptionContext* context, bool freeKeys);

// Encode encryption context to json string as described in encrypt/decrypt above.
char* encryptionContext_toJson(struct encryptionContext* context);

// Build encryption context from json string and given keypair.
struct encryptionContext* encryptionContext_fromJson(char* jsonString, EVP_PKEY* privateKey);

/* Recover plaintext from encryption context.
   context - Context structure with ciphertext and cryptographic elements populated.
             After successful execution, plaintext and plaintextLength will be populated based on decryption result.
   Returns - True if decryption is successful, false if not.
*/
bool decryptContext(struct encryptionContext* context);

/* Generate symmetric key and initialization vector, encrypt plaintext into ciphertext.
   context - Context structure with plaintext and public key populated.
             After successful execution, encryptedSessionKey and iv will be populated, and ciphertext will contain the encryption result.
   Returns - true if encryption is successful, false if not.
*/
bool encryptContext(struct encryptionContext* context);

// Decrypt from primitives without context structure.
bool _decrypt(EVP_PKEY* privateKey, unsigned char* ciphertext, unsigned int ciphertextLength, unsigned char* encryptedSessionKey, unsigned int encryptedSessionKeyLength, unsigned char* iv, unsigned char* plaintext, unsigned int* plaintextLength);

// Encrypt from primitives without context structure.
bool _encrypt(EVP_PKEY** publicKey, unsigned char* plaintext, int plaintextLength, unsigned char** encryptedSessionKey, int* encryptedSessionKeyLength, unsigned char* iv, unsigned char* ciphertext, unsigned int* ciphertextLength);

#endif
