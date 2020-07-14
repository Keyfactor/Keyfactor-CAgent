/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include "ecdh.h"

#include <stdio.h>

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/hmac.h>
#else
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif


#include "lib/base64.h"
#include "lib/json.h"
#include "logging.h"
#include "symmetricEncryption.h"

static void* KDF_SHA256_Append(const void* in, size_t inLen, void* out, size_t* outLen, const void* append, size_t appendLen)
{
	if(*outLen < SHA256_DIGEST_LENGTH)
	{
		return NULL;
	}

	size_t newInLen = inLen + appendLen;
	unsigned char* newIn = malloc(newInLen);

	/* Copy data to appended buffer */
	memcpy(newIn, in, inLen);
	memcpy(&newIn[inLen], append, appendLen);

	*outLen = SHA256_DIGEST_LENGTH;
	SHA256(newIn, newInLen, out);

	free(newIn);

	return out;
}

static void* KDF_SHA256_0001(const void* in, size_t inLen, void* out, size_t* outLen)
{
	char append[] = {0, 0, 0, 1};
	return KDF_SHA256_Append(in, inLen, out, outLen, append, 4);
}

static void* KDF_SHA256_0002(const void* in, size_t inLen, void* out, size_t* outLen)
{
	char append[] = {0, 0, 0, 2};
	return KDF_SHA256_Append(in, inLen, out, outLen, append, 4);
}

static EC_KEY* validate_unwrap_EC_KEY(EVP_PKEY* key)
{
	if(!key)
	{
		log_error("ecdh-validate_unwrap_EC_KEY-key is not specified");
		return NULL;
	}
	if(EVP_PKEY_type(key->type) != EVP_PKEY_EC)
	{
		log_error("ecdh-validate_unwrap_EC_KEY-key is not an ECC key");
		return NULL;
	}

	EC_KEY* otherEC = EVP_PKEY_get1_EC_KEY(key);

	int keyNID = EC_GROUP_get_curve_name(EC_KEY_get0_group(otherEC));
	if(keyNID != NID_X9_62_prime256v1 && keyNID != NID_secp384r1 && keyNID != NID_secp521r1)
	{
		log_error("ecdh-validate_unwrap_EC_KEY-key does not have a supported curve");
		EC_KEY_free(otherEC);
		otherEC = NULL;
	}

	return otherEC;
}

static EC_KEY* generate_ephemeral_key(EC_KEY* otherEC)
{
	EC_KEY* ephemeral = NULL;
	int keyNID = EC_GROUP_get_curve_name(EC_KEY_get0_group(otherEC));
	ephemeral = EC_KEY_new_by_curve_name(keyNID);
	EC_KEY_set_asn1_flag(ephemeral, OPENSSL_EC_NAMED_CURVE);
	EC_KEY_generate_key(ephemeral);

	return ephemeral;
}

static EC_KEY* ecdh_decode_public_key(char* b64Key)
{
	EC_KEY* key = NULL;
	EVP_PKEY* wrapKey = NULL;
	size_t decodedLen;
	unsigned char* decoded = base64_decode(b64Key, strlen(b64Key), &decodedLen);

	BIO* bio = BIO_new_mem_buf(decoded, (int)decodedLen);
	if(d2i_PUBKEY_bio(bio, &wrapKey))
	{
		key = validate_unwrap_EC_KEY(wrapKey);
	}
	else
	{
		log_error("ecdh-ecdh_decode_public_key-Unable to decode public key");
	}

	if(bio)
	{
		BIO_free(bio);
		bio = NULL;
	}
	if(decoded)
	{
		free(decoded);
		decoded = NULL;
	}
	if(wrapKey)
	{
		EVP_PKEY_free(wrapKey);
		wrapKey = NULL;
	}
	return key;
}

static char* ecdh_encode_public_key(EC_KEY* pubKey)
{
	char* encoded = NULL;
	BIO* bio = BIO_new(BIO_s_mem());
	EVP_PKEY* wrapKey = EVP_PKEY_new();

	if(EVP_PKEY_set1_EC_KEY(wrapKey, pubKey) && i2d_PUBKEY_bio(bio, wrapKey))
	{
		char* rawData;
		long rawDataLen = BIO_get_mem_data(bio, &rawData);
		encoded = base64_encode(rawData, (size_t)rawDataLen, false, NULL);
	}
	else
	{
		log_error("ecdh-ecdh_encode_public_key-Unable to encode public key");
	}

	if(wrapKey)
	{
		EVP_PKEY_free(wrapKey);
		wrapKey = NULL;
	}
	if(bio)
	{
		BIO_free(bio);
		bio = NULL;
	}

	return encoded;
}

static bool ecdh_json_decode(char* json, unsigned char** ciphertext, size_t* ciphertextLen, EC_KEY** senderKey, unsigned char** hmac, size_t* hmacLen)
{
	JsonNode* jsonRoot = NULL;
	char* rawSenderKey = NULL;
	char* rawHMAC = NULL;
	char* rawCipher = NULL;

	if(!json)
	{
		log_error("ecdh-ecdh_json_decode-JSON input is required");
		return false;
	}

	jsonRoot = json_decode(json); 
	if(jsonRoot)
	{
		rawSenderKey = json_get_member_string(jsonRoot, "PublicKey");
		rawHMAC = json_get_member_string(jsonRoot, "HMAC");
		rawCipher = json_get_member_string(jsonRoot, "Ciphertext");
	}
	else
	{
		log_error("ecdh-ecdh_json_decode-Unable to decode JSON input");
	}

	if(rawSenderKey)
	{
		*senderKey = ecdh_decode_public_key(rawSenderKey);
	}
	else
	{
		log_error("ecdh-ecdh_json_decode-Unable to decode sender key");
	}

	if(rawCipher)
	{
		*ciphertext = base64_decode(rawCipher, strlen(rawCipher), ciphertextLen);
	}
	else
	{
		log_error("ecdh-ecdh_json_decode-Unable to decode ciphertext");
	}

	if(rawHMAC && hmac)
	{
		*hmac = base64_decode(rawHMAC, strlen(rawHMAC), hmacLen);
	}

	if(jsonRoot)
	{
		json_delete(jsonRoot);
		jsonRoot = NULL;
	}
	if(rawSenderKey)
	{
		free(rawSenderKey);
		rawSenderKey = NULL;
	}
	if(rawHMAC)
	{
		free(rawHMAC);
		rawHMAC = NULL;
	}
	if(rawCipher)
	{
		free(rawCipher);
		rawCipher = NULL;
	}
	return *ciphertext && *senderKey;
}

static char* ecdh_json_encode(unsigned char* ciphertext, size_t ciphertextLen, EC_KEY* senderKey, unsigned char* hmac, size_t hmacLen)
{
	char* encodedKey = NULL;
	char* encodedCipher = NULL;
	char* encodedHMAC = NULL;
	JsonNode* jsonRoot = NULL;
	char* toReturn = NULL;

	if(!ciphertext)
	{
		log_error("ecdh-ecdh_json_encode-Ciphertext is required");
		return NULL;
	}
	if(!senderKey)
	{
		log_error("ecdh-ecdh_json_encode-Sender's public key is required");
		return NULL;
	}

	encodedKey = ecdh_encode_public_key(senderKey);
	encodedCipher = base64_encode(ciphertext, ciphertextLen, false, NULL);
	if(hmac)
	{
		encodedHMAC = base64_encode(hmac, hmacLen, false, NULL);
	}

	if(encodedKey && encodedCipher && (!hmac || encodedHMAC))
	{
		jsonRoot = json_mkobject();
		json_append_member(jsonRoot, "PublicKey", json_mkstring(encodedKey));
		json_append_member(jsonRoot, "Ciphertext", json_mkstring(encodedCipher));
		if(encodedHMAC)
		{
			json_append_member(jsonRoot, "HMAC", json_mkstring(encodedHMAC));
		}
	}

	if(jsonRoot)
	{
		toReturn = json_encode(jsonRoot);
	}

	if(jsonRoot)
	{
		json_delete(jsonRoot);
		jsonRoot = NULL;
	}
	if(encodedHMAC)
	{
		free(encodedHMAC);
		encodedHMAC = NULL;
	}
	if(encodedCipher)
	{
		free(encodedCipher);
		encodedCipher = NULL;
	}
	if(encodedKey)
	{
		free(encodedKey);
		encodedKey = NULL;
	}

	return toReturn;	
}

bool decrypt_ecdh(char* json, EVP_PKEY* recipientKey, unsigned char** plaintext, size_t* plaintextLen)
{
	bool hasError = false;
	EC_KEY* recipientEC = NULL;
	unsigned char* ciphertext = NULL;
	size_t ciphertextLen = 0;
	EC_KEY* senderKey = NULL;
	unsigned char* hmac = NULL;
	size_t hmacLen = 0;

	if(!plaintext || !recipientKey || !json)
	{
		log_error("ecdh-decrypt_ecdh-All parameters are required");
		hasError = true;
	}

	if(!hasError && !(recipientEC = validate_unwrap_EC_KEY(recipientKey)))
	{
		log_error("ecdh-decrypt_ecdh-recipientKey is not a valid ECC key");
		hasError = true;
	}

	if(!hasError && !ecdh_json_decode(json, &ciphertext, &ciphertextLen, &senderKey, &hmac, &hmacLen))
	{
		log_error("ecdh-decrypt_ecdh-Unable to decode JSON object");
		hasError = true;
	}

	// Allocate ample space for the keys
	unsigned char aesKey[100];
	unsigned char hmacKey[100];
	int aesKeyLen = 100;
	int hmacKeyLen = 100;

	*plaintext = malloc(ciphertextLen);

	unsigned int hmacBytesLen = EVP_MAX_MD_SIZE;
	unsigned char hmacBytes[EVP_MAX_MD_SIZE];

	if(!hasError && !(aesKeyLen = ECDH_compute_key(aesKey, aesKeyLen, EC_KEY_get0_public_key(senderKey), recipientEC, KDF_SHA256_0001)))
	{
		log_error("ecdh-decrypt_ecdh-Unable to compute AES key");
		hasError = true;
	}

	if(!hasError && !symmetricDecrypt(ciphertext, ciphertextLen, aesKey, NULL, *plaintext, (unsigned int*)plaintextLen))
	{
		log_error("ecdh-decrypt_ecdh-Unable to perform symmetric decryption");
		hasError = true;
	}

	if(hmac)
	{
		if(!hasError && !(hmacKeyLen = ECDH_compute_key(hmacKey, hmacKeyLen, EC_KEY_get0_public_key(senderKey), recipientEC, KDF_SHA256_0002)))
		{
			log_error("ecdh-decrypt_ecdh-Unable to compute HMAC key");
			hasError = true;
		}
		if(!hasError)
		{
			if(!HMAC(EVP_sha256(), hmacKey, hmacKeyLen, *plaintext, *plaintextLen, hmacBytes, &hmacBytesLen))
			{
				log_error("ecdh-decrypt_ecdh-Unable to perform HMAC");
				hasError = true;
			}
			else
			{
				char* hmacDebug = base64_encode(hmacBytes, hmacLen, false, NULL);
				log_verbose("ecdh-decrypt_ecdh-HMAC: %s", hmacDebug);
				free(hmacDebug);
			}
		}
		if(!hasError && (hmacLen != hmacBytesLen || memcmp(hmac, hmacBytes, hmacLen)!= 0))
		{
			log_error("ecdh-decrypt_ecdh-HMAC does not match");
			hasError = true;
		}
	}

	if(hasError && *plaintext) // Cleanup output parameters if we error out
	{
		free(*plaintext);
		*plaintext = 0;
		*plaintextLen = 0;
	}
	if(recipientEC)
	{
		EC_KEY_free(recipientEC);
		recipientEC = NULL;
	}
	if(ciphertext)
	{
		free(ciphertext);
		ciphertext = NULL;
	}
	if(senderKey)
	{
		EC_KEY_free(senderKey);
		senderKey = NULL;
	}
	if(hmac)
	{
		free(hmac);
		hmac = NULL;
	}
	return !hasError;
}

bool encrypt_ecdh(unsigned char* plaintext, size_t plaintextLen, EVP_PKEY* recipientKey, char** json)
{
	bool hasError = false;
	EC_KEY* recipientEC = NULL;
	EC_KEY* ephemeralEC = NULL;

	if(!plaintext || !recipientKey || !json)
	{
		log_error("ecdh-encrypt_ecdh-All parameters are required");
		hasError = true;
	}

	if(!hasError && !(recipientEC = validate_unwrap_EC_KEY(recipientKey)))
	{
		log_error("ecdh-encrypt_ecdh-recipientKey is not a valid ECC key");
		hasError = true;
	}
	if(!hasError && !(ephemeralEC = generate_ephemeral_key(recipientEC)))
	{
		log_error("ecdh-encrypt_ecdh-Unable to validate ephemeral key");
		hasError = true;
	}

	// Allocate ample space for the keys
	unsigned char aesKey[100];
	unsigned char hmacKey[100];
	int aesKeyLen = 100;
	int hmacKeyLen = 100;

	unsigned int ciphertextLen = plaintextLen + 100;
	unsigned char* ciphertext = malloc(ciphertextLen);

	unsigned int hmacLen = EVP_MAX_MD_SIZE;
	unsigned char hmacBytes[EVP_MAX_MD_SIZE];

	if(!hasError && !(aesKeyLen = ECDH_compute_key(aesKey, aesKeyLen, EC_KEY_get0_public_key(recipientEC), ephemeralEC, KDF_SHA256_0001)))
	{
		log_error("ecdh-encrypt_ecdh-Unable to compute AES key");
		hasError = true;
	}
	if(!hasError && !(hmacKeyLen = ECDH_compute_key(hmacKey, hmacKeyLen, EC_KEY_get0_public_key(recipientEC), ephemeralEC, KDF_SHA256_0002)))
	{
		log_error("ecdh-encrypt_ecdh-Unable to compute HMAC key");
		hasError = true;
	}

	if(!hasError)
	{
		if(!HMAC(EVP_sha256(), hmacKey, hmacKeyLen, plaintext, plaintextLen, hmacBytes, &hmacLen))
		{
			log_error("ecdh-encrypt_ecdh-Unable to perform HMAC");
			hasError = true;
		}
		else
		{
			char* hmacDebug = base64_encode(hmacBytes, hmacLen, false, NULL);
			log_verbose("HMAC: %s", hmacDebug);
			free(hmacDebug);
		}
	}

	if(!hasError && !symmetricEncrypt(plaintext, plaintextLen, aesKey, NULL, ciphertext, &ciphertextLen))
	{
		log_error("ecdh-encrypt_ecdh-Unable to perform symmetric encryption");
		hasError = true;
	}

	if(!hasError)
	{
		*json = ecdh_json_encode(ciphertext, ciphertextLen, ephemeralEC, hmacBytes, hmacLen);
	}

	if(ciphertext)
	{
		free(ciphertext);
		ciphertext = NULL;
	}
	if(recipientEC)
	{
		EC_KEY_free(recipientEC);
		recipientEC = NULL;
	}
	if(ephemeralEC)
	{
		EC_KEY_free(ephemeralEC);
		ephemeralEC = NULL;
	}

	return !hasError;
}

