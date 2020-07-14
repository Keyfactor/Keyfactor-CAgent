/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include "ecdh.h"
#include "logging.h"

#include <stdio.h>
#include <string.h>

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/pem.h>
#else
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif

static EC_KEY* read_private_key(char* filePath)
{
	EVP_PKEY* key = NULL;
	EC_KEY* ecKey = NULL;
	FILE* fpRead = fopen(filePath, "r");

	if(fpRead)
	{
		PEM_read_PrivateKey(fpRead, &key, NULL, NULL);
		log_verbose("EVP_PKEY pointer: %p", key);
	}
	if(key)
	{
		ecKey = EVP_PKEY_get1_EC_KEY(key);
	}

	if(fpRead)
	{
		fclose(fpRead);
		fpRead = NULL;
	}
	if(key)
	{
		EVP_PKEY_free(key);
		key = NULL;
	}

	return ecKey;
}

static EC_KEY* read_public_key_from_cert(char* filePath)
{
	X509* cert = NULL;
	EVP_PKEY* key = NULL;
	EC_KEY* ecKey = NULL;

	FILE* fpRead = fopen(filePath, "r");
	if(fpRead)
	{
		PEM_read_X509(fpRead, &cert, NULL, NULL);
		log_verbose("X509 pointer: %p", cert);
	}
	if(cert)
	{
		key = X509_get_pubkey(cert);
		log_verbose("EVP_PKEY pointer: %p", key);
	}
	if(key)
	{
		ecKey = EVP_PKEY_get1_EC_KEY(key);
	}

	if(fpRead)
	{
		fclose(fpRead);
		fpRead = NULL;
	}
	if(cert)
	{
		X509_free(cert);
		cert = NULL;
	}
	if(key)
	{
		EVP_PKEY_free(key);
		key = NULL;
	}
	return ecKey;
}

int main(int argc, char** argv)
{
	char* json = NULL;
	log_set_verbosity(true);

	EC_KEY* privKey = read_private_key("alice.key");
	printf("Private Key pointer: %p\n", privKey);
	
	EC_KEY* pubKey = read_public_key_from_cert("alice.cer");
	printf("Public Key pointer: %p\n", pubKey);

	EVP_PKEY* wrapPrivKey = EVP_PKEY_new();
	EVP_PKEY_assign_EC_KEY(wrapPrivKey, privKey);

	EVP_PKEY* wrapPubKey = EVP_PKEY_new();
	EVP_PKEY_assign_EC_KEY(wrapPubKey, pubKey);

	char* orig = "This is a test. This is only a test";
	log_verbose("Original plaintext: %s", orig);
	log_verbose("Encrypting...");
	encrypt_ecdh((unsigned char*)orig, strlen(orig), wrapPubKey, &json);
	log_verbose("JSON: %s", json);

	log_verbose("Decrypting...");
	unsigned char* plaintext;
	size_t plaintextLen;
	decrypt_ecdh(json, wrapPrivKey, &plaintext, &plaintextLen);
	log_verbose("Round-trip plaintext: %s", (char*)plaintext);

	json[strlen(json)-7]++;
	log_verbose("Modified JSON: %s", json);
	log_verbose("Decrypting with modified HMAC...");
	decrypt_ecdh(json, wrapPrivKey, &plaintext, &plaintextLen);
	log_verbose("Round-trip plaintext: %s", (char*)plaintext);
}
