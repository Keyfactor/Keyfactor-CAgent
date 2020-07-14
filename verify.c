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
#include <wolfssl/openssl/ts.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/obj_mac.h>
#else
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ts.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include "verify.h"
#include "logging.h"

static bool verify_timestamp_pkcs7(PKCS7* p7, const char* trustCertPath);
static PKCS7* get_timestamp_token(PKCS7_SIGNER_INFO* si);

static bool verify_cert_chain(X509* cert, const char* chainFile)
{
	X509_STORE* store = X509_STORE_new();
	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	bool valid = true;

	if(valid && X509_STORE_load_locations(store, chainFile, NULL) != 1)
	{
		log_error("Unable to load X509 store at %s", chainFile);
		valid = false;
	}

	if(valid && X509_STORE_CTX_init(ctx, store, cert, NULL) != 1)
	{
		log_error("Unable to initialize X509 store context");
		valid = false;
	}

	if(valid)
	{
		int ret = X509_verify_cert(ctx);
		if(ret == 1)
		{
			log_verbose("Certificate chain is valid. Checking EKU");
			EXTENDED_KEY_USAGE* data = (EXTENDED_KEY_USAGE*)X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
			if(data)
			{
				bool ekuValid = false;
				ASN1_OBJECT* eku;
				while((eku = sk_ASN1_OBJECT_pop(data)) != NULL)
				{
					char buf[1024];
					OBJ_obj2txt(buf, 1024, eku, 1);
					log_verbose("EKU: %s", buf);

					if(strcmp(buf, EKU_CODE_SIGNING) == 0)
					{
						log_verbose("Code signing EKU present");
						valid = true;
						ekuValid = true;
						break;
					}
				}
				if(!ekuValid)
				{
					log_verbose("EKU extension does not permit code signing");
					valid = false;
				}
			}
			else
			{
				log_verbose("EKU extension is not present. All usages are permitted");
				valid = true;
			}
		}
		else if(ret == 0)
		{
			log_verbose("Certificate did not validate successfully: %s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
			valid = false;
		}
		else
		{
			log_error("Unrecoverable error verifying certificate");
			valid = false;
		}
	}

	if(ctx)
	{
		X509_STORE_CTX_free(ctx);
	}

	if(store)
	{
		X509_STORE_free(store);
	}

	return valid;
}

static bool verify_detached_signature_cert(const unsigned char* fileBytes, unsigned int fileSize, const unsigned char* sigBytes, unsigned int sigSize, const char* hashAlg, X509* cert, bool verifyChain, const char* trustCertPath)
{
	bool sigVerified = false;
	bool hasError = false;

	EVP_PKEY* pubkey = X509_get_pubkey(cert);

	const EVP_MD* md;
	if(hashAlg)
	{
		md = EVP_get_digestbyname(hashAlg);
		if(!md)
		{
			log_error("Unknown message digest for name %s", hashAlg);
			hasError = false;
		}
	}
	else
	{
		int mdnid = X509_get_signature_nid(cert);
		log_verbose("Digest NID: %d", mdnid);

		md = EVP_get_digestbynid(mdnid);
		if(!md)
		{
			log_error("Unknown message digest for NID %d", mdnid);
			hasError = false;
		}
	}

	EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
	if(!hasError && EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pubkey) <= 0)
	{
		char errBuf[120];
		unsigned long errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error("Error initializing digest verification: %s", errBuf);
		hasError = true;
	}
	if(!hasError && EVP_DigestVerifyUpdate(mdctx, fileBytes, fileSize) <= 0)
	{
		char errBuf[120];
		unsigned long errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error("Error updating digest verification: %s", errBuf);
		hasError = true;
	}
	if(!hasError)
	{
		int dgstRes = EVP_DigestVerifyFinal(mdctx, sigBytes, sigSize);
		switch(dgstRes)
		{
			case 1:
				if(verifyChain)
				{
					sigVerified = verify_cert_chain(cert, trustCertPath);
				}
				else
				{
					sigVerified = true;
				}
				break;
			case 0:
				sigVerified = false;
				break;
			default:
				; // Initialization can't start a case
				char errBuf[120];
				unsigned long errNum = ERR_peek_last_error();
				ERR_error_string(errNum, errBuf);
				log_error("Error finalizing digest verification: %s", errBuf);
				hasError = true;
				break;

		}

	}

	EVP_MD_CTX_destroy(mdctx);

	OPENSSL_free(pubkey);

	return sigVerified;
}

bool verify_detached_signature(const unsigned char* fileBytes, unsigned int fileSize, const unsigned char* sigBytes, unsigned int sigSize, const char* signingCertPath, bool verifyChain, const char* trustCertPath, const char* hashAlg)
{
	bool sigVerified = false;

	FILE* fp = fopen(signingCertPath, "r");
	if(!fp)
	{
		char* errStr = strerror(errno);
		log_error("Unable to open store at %s: %s", signingCertPath, errStr);
	}
	else
	{
		char* name = NULL;
		char* header = NULL;
		unsigned char* data = NULL;
		long length = 0;

		while(!sigVerified && PEM_read(fp, &name, &header, &data, &length))
		{
			X509* cert = NULL;
			const unsigned char* tempData = data; // Don't lose the pointer so it can be freed

			if(strcmp(name, "CERTIFICATE") == 0 && d2i_X509(&cert, &tempData, length))
			{
				sigVerified = verify_detached_signature_cert(fileBytes, fileSize, sigBytes, sigSize, hashAlg, cert, verifyChain, trustCertPath);
			}
			OPENSSL_free(cert);
		}

		OPENSSL_free(name);
		OPENSSL_free(header);
		OPENSSL_free(data);
	}

	if(fp)
	{
		fclose(fp);
	}

	return sigVerified;
}

static STACK_OF(X509)* load_certs_from_file(const char* filePath)
{
	STACK_OF(X509)* certs = NULL;

	FILE* fp = fopen(filePath, "r");
	if(!fp)
	{
		char* errStr = strerror(errno);
		log_error("Unable to open store at %s: %s", filePath, errStr);
	}
	else
	{
		certs = sk_X509_new(NULL);
		char* name = NULL;
		char* header = NULL;
		unsigned char* data = NULL;
		long length = 0;

		while(PEM_read(fp, &name, &header, &data, &length))
		{
			X509* cert = NULL;
			const unsigned char* tempData = data; // Don't lose the pointer so it can be freed

			if(strcmp(name, "CERTIFICATE") == 0 && d2i_X509(&cert, &tempData, length))
			{
				sk_X509_push(certs, cert);
			}
		}

		OPENSSL_free(name);
		OPENSSL_free(header);
		OPENSSL_free(data);
	}

	if(fp)
	{
		fclose(fp);
	}

	return certs;
}

bool verify_pkcs7_signature(const unsigned char* fileBytes, unsigned int fileSize, const unsigned char* sigBytes, unsigned int sigSize, const char* signingCertPath, bool verifyChain, const char* trustCertPath)
{
	bool sigVerified = false;
	bool hasError = false;
	PKCS7* pkcs7 = NULL;
	BIO* inBio = NULL;
	STACK_OF(X509)* sigCerts = NULL;

	const unsigned char* tempBytes = sigBytes;
	if(!d2i_PKCS7(&pkcs7, &tempBytes, (long)sigSize))
	{
		char errBuf[120];
		unsigned long errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error("Error parsing PKCS7: %s", errBuf);
		hasError = true;
	}

	if(!hasError)
	{
		tempBytes = fileBytes;
		inBio = BIO_new_mem_buf(tempBytes, (long)fileSize);
		if(!inBio)
		{
			log_error("Unable to create input file buffer");
			hasError = true;
		}
	}

	if(!hasError && !(sigCerts = load_certs_from_file(signingCertPath)))
	{
		log_error("Unable to load signing certs at %s", signingCertPath);
		hasError = true;
	}

	if(PKCS7_verify(pkcs7, sigCerts, NULL, inBio, NULL, PKCS7_NOVERIFY/*Verify chain afterward to check code signing EKU*/))
	{
		log_verbose("PKCS7 signature verified successfully");

		if(verifyChain)
		{
			STACK_OF(X509)* signers = PKCS7_get0_signers(pkcs7, sigCerts, 0);
			sigVerified = verify_cert_chain(sk_X509_pop(signers), trustCertPath);
		}
		else
		{
			sigVerified = true;
		}
	}
	else
	{
		sigVerified = false;
		log_verbose("PKCS7 signature verification failed");
		char errBuf[120];
		unsigned long errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error("Error verifying PKCS7: %s", errBuf);
	}

	if(pkcs7)
	{
		PKCS7_free(pkcs7);
	}
	if(inBio)
	{
		BIO_free(inBio);
	}
	if(sigCerts)
	{
		sk_X509_pop_free(sigCerts, &X509_free);
	}

	return sigVerified;
}

bool verify_timestamp(const unsigned char* sigBytes, unsigned int sigSize, const char* trustCertPath)
{
	bool hasError = false;
	bool tsVerified = false;
	PKCS7* pkcs7 = NULL;

	if(!d2i_PKCS7(&pkcs7, &sigBytes, (long)sigSize))
	{
		char errBuf[120];
		unsigned long errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error("Error parsing PKCS7 for Timestamp: %s", errBuf);
		hasError = true;
	}
	
	if(!hasError)
	{
		log_info("Attempting to verify timestamp.");
		if(verify_timestamp_pkcs7(pkcs7, trustCertPath))
		{
			tsVerified = true;
		}
		else
		{
			tsVerified = false;
			log_verbose("Timestamp verification failed.");
			char errBuf[120];
			int errNum;
			while((errNum = ERR_get_error())!=0)
			{
				ERR_error_string(errNum, errBuf);
			}
			log_error("Error verifying Timestamp: %s", errBuf);
		}
	}

	if(pkcs7)
	{
		PKCS7_free(pkcs7);
	}

	return tsVerified;
}

static bool verify_timestamp_pkcs7(PKCS7* p7, const char* trustCertPath)
{
	bool hasError = false;
	bool validCounterSignature = false;

	PKCS7_SIGNER_INFO* signature_info = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7),0);
	PKCS7* time_stamp_token; // free later

	log_info("Looking for timestamp token.");
	if(!(time_stamp_token = get_timestamp_token(signature_info)))
	{
		log_verbose("No timestamp token was present.");
		hasError = true;
	}
		
	PKCS7_SIGNER_INFO* ts_info;
	if(!hasError && !(ts_info = sk_PKCS7_SIGNER_INFO_value(time_stamp_token->d.sign->signer_info, 0)))
	{
		log_verbose("SignerInfo was not present on the Time Stamp Token.");
		hasError = true;
	}

	TS_VERIFY_CTX* verify_ctx = NULL;
	if (!hasError)
	{
		verify_ctx = TS_VERIFY_CTX_new();
		int vfy_flags = TS_VFY_VERSION | TS_VFY_SIGNER | TS_VFY_SIGNATURE;

		TS_VERIFY_CTS_set_certs(verify_ctx, time_stamp_token->d.sign->cert);
		
		X509_STORE* store = X509_STORE_new();
		if(X509_STORE_load_locations(store, trustCertPath, NULL) != 1)
		{
			log_error("Unable to load X509 store at %s", trustCertPath);
		}

		TS_VERIFY_CTX_set_store(verify_ctx, store);
	
		TS_VERIFY_CTX_add_flags(verify_ctx, vfy_flags);

		validCounterSignature = TS_RESP_verify_token(verify_ctx, time_stamp_token);

		if(!validCounterSignature)
		{
			char errBuf[120];
			int errNum;
			while((errNum = ERR_get_error())!=0)
			{
				ERR_error_string(errNum, errBuf);
			}
			log_error("Error verifying Timestamp: %s", errBuf);
		}
	}

	if(verify_ctx)
	{
		TS_VERIFY_CTX_free(verify_ctx);
	}

	if(time_stamp_token)
	{
		time_stamp_token->d.sign->cert = NULL; // This was already freed in verify_ctx
		PKCS7_free(time_stamp_token);
	}
	
	return validCounterSignature;
}

static PKCS7* get_timestamp_token(PKCS7_SIGNER_INFO* si)
{
	ASN1_TYPE* unsig_attr = PKCS7_get_attribute(si, NID_id_smime_aa_timeStampToken);
	PKCS7* time_stamp_token = NULL;
	
	if(unsig_attr)
	{
		ASN1_STRING* bit_str = unsig_attr->value.sequence;
		const unsigned char* p = bit_str->data;
		time_stamp_token = d2i_PKCS7(NULL, &p, bit_str->length);
	}

	if(!(time_stamp_token))
	{
		log_verbose("Failed to unpack TimeStamp Token from the unsigned attributes.");
	}

	return time_stamp_token;
}

