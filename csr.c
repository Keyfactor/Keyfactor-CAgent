/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include <string.h>
#include "csr.h"
#include "utils.h"
#include "logging.h"
#include "lib/base64.h"

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/asn1.h> // openSSL includes automatically, wolf doesn't
#ifndef NID_X9_62_prime256v1
#define NID_X9_62_prime256v1 415 // not in wolfSSL
#endif // NID_X9_62_prime256v1
#ifndef NID_secp384r1
#define NID_secp384r1 715        // not in wolfSSL
#endif // NID_secp384r1
#ifndef NID_secp521r1
#define NID_secp521r1 716        // not in wolfSSL
#endif // NID_secp521r1
#else // __WOLF_SSL__
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#ifndef SLL_SUCCESS
#define SSL_SUCCESS 1
#endif // SLL_SUCCESS
#endif // __WOLF_SSL__

#include "global.h"

#ifdef __TPM__
//TODO: What if the WOLF switch is turned on?
#include <openssl/engine.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <tpm2-tss-engine.h>
#endif

#define MODULE "csr-"
#define MAX_CSR_SIZE 1024 // shouldn't get longer than this

#ifdef __TPM__
/***************************************************************************//**
  Generate an RSA key using the TPM module

  This function calls out to generate an RSA key using the TPM.
  @param exp exponent for key
	@param rsa the rsa key structure
	@param keySize the size of the keyBIO
	@param tpm2Data a pointer to the tpm2Data structure
  @retval EVP_PKEY * for use with the SSL engine
	@retval NULL if an error is encountered
 */
/******************************************************************************/
static EVP_PKEY* genkey_rsa_using_TPM( BIGNUM *exp,  RSA *rsa,
									   int keySize, TPM2_DATA *tpm2Data )
{
	  #undef FUNCTION
		#define FUNCTION "genkey_rsa_using_TPM-"
    log_verbose("%s%sGenerating RSA key using TPM", MODULE, FUNCTION);
		char *password = "";
		TPM2_HANDLE parent = 0;

		log_trace("%s%sCalling tpm2tss_rsa_genkey", MODULE, FUNCTION);
    if ( !tpm2tss_rsa_genkey(rsa, keySize, exp, password, parent) )
    {
        log_error("%s%sError: RSA key generation failed", MODULE, FUNCTION);
        return NULL;
    }

    /* export the encrypted BLOB into a tpm2Data structure */
		log_trace("%s%sCopy rsa into tpm2Data format", MODULE, FUNCTION);
    memcpy(tpm2Data, RSA_get_app_data(rsa), sizeof(*tpm2Data));

		log_verbose("%s%sKey generated...converting BLOB to openSSL format",
																														MODULE, FUNCTION);
		/* convert the encrypted BLOB into something the openSSL engine can use */
		EVP_PKEY *keyPair = NULL;
		log_trace("%s%sCalling tpm2tss_rsa_makekey", MODULE, FUNCTION);
    keyPair = tpm2tss_rsa_makekey( tpm2Data ); // documentation wrong this is **
    if ( NULL == keyPair )
    {
        log_error("%s%sError: tpm2tss_rsa_makekey.", MODULE, FUNCTION);
        return NULL;
    }
    log_verbose("%s%sSuccessfully created openSSL compatible keyPair in memory."
												,MODULE, FUNCTION);

    return keyPair;
} //genkey_rsa
#endif

EVP_PKEY* generate_keypair(const char* keyType, int keySize)
{
	#undef FUNCTION
	#define FUNCTION "generate_keypair-"
	log_verbose("%s%s-Generating key pair with type %s and length %d",
				MODULE, FUNCTION, keyType, keySize);
	EVP_PKEY* keyPair = NULL;

	if(strcasecmp(keyType, "RSA") == 0)
	{
		BIGNUM* exp = BN_new();
		if (!exp)
    {
        log_error("%s%sout of memory when creating exponent in genkey_rsa",
											MODULE, FUNCTION);
        return NULL;
    }
		BN_set_word(exp, RSA_DEFAULT_EXP);
		RSA* newRsa = RSA_new();
		if (!newRsa)
    {
        log_error("%s%sout of memory when creating RSA variable in genkey_rsa",
											MODULE, FUNCTION);
        return NULL;
    }
#ifdef __TPM__
		/***************************************************************************
		 * Create RSA keypair using TPM
		 **************************************************************************/
		 TPM2_DATA *tpm2Data = calloc(1, sizeof(*tpm2Data));
     if ( NULL == tpm2Data )
     {
         log_error("%s%sout of memory for tpm2Data", MODULE, FUNCTION);
         return NULL;
     }
		 keyPair = genkey_rsa_using_TPM( exp, newRsa, keySize, tpm2Data );
		 if ( NULL == keyPair )
		 {
			 char errBuf[120];
			 unsigned long errNum = ERR_peek_last_error();
 			 ERR_error_string(errNum, errBuf);
 			 log_error("%s%s-Unable to generate key pair: %s",
 						MODULE, FUNCTION, errBuf);
			 return NULL;
		 }
		 log_verbose("%s%sWrite encrypted BLOB to disk - /home/pi/temp.blob",
	 								MODULE, FUNCTION);
			if ( !tpm2tss_tpm2data_write(tpm2Data, "/home/pi/temp.blob") )
	    {
	        log_error("%s%sError writing file %s",
													MODULE, FUNCTION, "/home/pi/temp.blob");
	        return NULL;
	    }
			log_verbose("%s%sSuccessfully wrote BLOB to disk", MODULE, FUNCTION);
		 /**************************************************************************
 		 * END Create RSA keypair using TPM
 		 **************************************************************************/
#else // __TPM__ not defined, so use standard engine
		/***************************************************************************
		 * Create keypair using standard openSSL engine
		 **************************************************************************/
		if(RSA_generate_key_ex(newRsa, keySize, exp, NULL))
		{
			keyPair = EVP_PKEY_new();
			EVP_PKEY_assign_RSA(keyPair, newRsa);
		}
		else
		{
			char errBuf[120];
			unsigned long errNum = ERR_peek_last_error();
			ERR_error_string(errNum, errBuf);
			log_error("%s%s-Unable to generate key pair: %s",
						MODULE, FUNCTION, errBuf);
		}
		/***************************************************************************
		 * END RSA keypair using standard openSSL engine
		 **************************************************************************/
#endif
	}
	else if(strcasecmp(keyType, "ECC") == 0)
	{
		int eccNid;
		switch(keySize)
		{
		case 256:
			eccNid = NID_X9_62_prime256v1;
			break;
		case 384:
			eccNid = NID_secp384r1;
			break;
		case 521:
			eccNid = NID_secp521r1;
			break;
		default:
		log_error("%s%s-Invalid ECC key length: %d. Falling back to default curve",
						MODULE, FUNCTION, keySize);
			eccNid = NID_X9_62_prime256v1;
			break;
		}

#ifdef __TPM__
		/***************************************************************************
		 * Create ECC keypair using TPM
		 **************************************************************************/
		  //TODO: Write the ECC keypair using TPM function(s)
			TPM2_DATA *tpm2Data = calloc(1, sizeof(*tpm2Data));
      if ( NULL == tpm2Data )
      {
          log_error("%s%sout of memory for tpm2Data", MODULE, FUNCTION);
          return NULL;
      }
			keyPair = NULL; // SLB9670 doesn't have ECC capabilities
		 /**************************************************************************
 		 * END Create RSA keypair using TPM
 		 **************************************************************************/
#else // __TPM__ not defined
		/***************************************************************************
		 * Create keypair using standard openSSL engine
		 **************************************************************************/

		EC_KEY* newEcc = EC_KEY_new_by_curve_name(eccNid);
		EC_KEY_set_asn1_flag(newEcc, OPENSSL_EC_NAMED_CURVE);
		if(EC_KEY_generate_key(newEcc))
		{
			keyPair = EVP_PKEY_new();
			EVP_PKEY_assign_EC_KEY(keyPair, newEcc);
		}
		else
		{
			char errBuf[120];
			unsigned long errNum = ERR_peek_last_error();
			ERR_error_string(errNum, errBuf);
			log_error("%s%s-Unable to generate key pair: %s",
					MODULE, FUNCTION, errBuf);
		}
		/***************************************************************************
		 * END Create keypair using standard openSSL engine
		 **************************************************************************/
#endif // __TPM__ not defined
	}
	else
	{
		log_error("%s%s-Invalid key type %s", MODULE, FUNCTION, keyType);
	}
	return keyPair;
} // generate_keypair

static int read_subject_value(const char* subject, char* buf)
{
	#undef FUNCTION
	#define FUNCTION "read_subject_value"
	int subjLen = strlen(subject);
	int subInd = 0;
	int bufInd = 0;

	bool done = false;
	bool hasError = false;

	while(!done && !hasError && subInd < subjLen)
	{
		char c = subject[subInd];
		switch(c)
		{
		case '\\':
			;
			char escaped[1];
			unsigned int hexHi, hexLo;
			if(sscanf(&subject[subInd], "\\%1[\" #+,;<=>\\]", escaped) == 1)
			{
				if(buf)
				{
					buf[bufInd++] = escaped[0];
				}
				subInd += 2;
			}
			else if(sscanf(&subject[subInd], "\\%1x%1x", &hexHi, &hexLo) == 2)
			{
				if(buf)
				{
					buf[bufInd++] = (char)((hexHi << 4) | hexLo);
				}
				subInd += 3;
			}
			else
			{
				hasError = true;
			}
			break;
		case ',':
			done = true;
			break;
		default:
			if(buf)
			{
				buf[bufInd++] = c;
			}
			++subInd;
			break;
		}
	}

	if(buf)
	{
		buf[bufInd] = '\0';
	}

	return hasError ? -1 : subInd;
}

X509_NAME* parse_subject(const char* subject)
{
	#undef FUNCTION
	#define FUNCTION "parse_subject"
	X509_NAME* subjName = NULL;
	int subjLen = strlen(subject);
	int cur = 0;

	bool hasError = false;

	X509_NAME_ENTRY* rdnArr[20]; // 20 RDNs should be plenty
	int rdnCount = 0;

	while(!hasError && cur < subjLen)
	{
		int keyLen = strcspn(&subject[cur], "=");
		char keyBytes[keyLen+1];
		strncpy(keyBytes, &subject[cur], keyLen);
		keyBytes[keyLen] = '\0';
		cur += (keyLen + 1);
		log_verbose("%s%s-Key: %s", MODULE, FUNCTION, keyBytes);

		if(cur < subjLen)
		{
			int valLen = read_subject_value(&subject[cur], NULL);
			if(valLen >= 0)
			{
				char valBytes[valLen+1];
				read_subject_value(&subject[cur], valBytes);
				cur += (valLen + 1);
				log_verbose("%s%s-Value: %s", MODULE, FUNCTION, valBytes);
/*
 * //TODO: Determine why the include from asn1.h is not defined here
 */
#ifdef __WOLF_SSL__
#ifndef MBSTRING_UTF8
#define MBSTRING_UTF8 0x1000 // even though asn1.h was included, wolfssl isn't recognizing this
#endif
#endif
				rdnArr[rdnCount] = X509_NAME_ENTRY_create_by_txt(NULL, keyBytes, MBSTRING_UTF8, (unsigned char*)valBytes, -1);
				rdnCount++;


				if(subject[cur-1] != '\0') // Don't try to advance if we just advanced past the null-terminator
				{
					cur += strspn(&subject[cur], "\t\r\n "); // Whitespace between RDNs should be ignored
				}
			}
			else
			{
				log_error("%s%s-Input string '%s' is not a valid X500 name", MODULE, FUNCTION, subject);
				hasError = true;
			}
		}
		else
		{
			log_error("%s%s-Input string '%s' is not a valid X500 name", MODULE, FUNCTION, subject);
			hasError = true;
		}
	}

	if(!hasError)
	{
		subjName = X509_NAME_new();
		for(int rdnIndex = rdnCount - 1; rdnIndex >= 0; rdnIndex--)
		{
			X509_NAME_add_entry(subjName, rdnArr[rdnIndex], -1, 0);
		}
	}

	// Cleanup
	for(int rdnIndex = rdnCount - 1; rdnIndex >= 0; rdnIndex--)
	{
		X509_NAME_ENTRY_free(rdnArr[rdnIndex]);
	}

	return subjName;
}

char* generate_csr(EVP_PKEY* keyPair, X509_NAME* subject)
{
	#undef FUNCTION
	#define FUNCTION "generate_csr"
	X509_REQ* req = NULL;
	unsigned char* reqBytes = NULL;
	char* csrString = NULL;
	int result = SSL_SUCCESS;

	/**************************************************************************
	 * 1.) Set up the CSR as a new x509 request by creating a blank request
	 *     then adding in the public key, setting the subject, and signing
	 *     it with the private key.
	 ************************************************************************/
	log_verbose("%s%s-Setting up an agent CSR", MODULE, FUNCTION);
	req = X509_REQ_new();
	result = X509_REQ_set_subject_name(req, subject);
	if ( SSL_SUCCESS == result )
	{
		result = X509_REQ_set_pubkey(req, keyPair);
		if ( SSL_SUCCESS == result )
		{
			result = X509_REQ_sign(req, keyPair, EVP_sha256());
			/* wolfSSL returns WOLF_SSL_SUCCESS (defined as 1)  */
			/* or WOLF_SSL_FAILURE (defined as 0) */
			/* opoenSSL returns the size of the signature or 0 if it fails */
			if ( 0 == result )
			{
				log_error("%s%s-CSR signing failed with code, 0x%X", 
							MODULE, FUNCTION, result);
			}
			else
			{
				/* make sure to set this to success if openSSL */
				result = SSL_SUCCESS;
			}
		}
		else
		{
			log_error("%s%s-CSR set of public key failed with code, 0x%X", 
						MODULE, FUNCTION, result);
		}
	}
	else
	{
		log_error("%s%s-CSR subject name set failed with code, 0x%X", 
			MODULE, FUNCTION, result);
	}

	/**************************************************************************
	 * 2.) Take the resulting data structure, encode it and convert it to a
	 *     string.
	 ************************************************************************/
	if( SSL_SUCCESS == result )	
	{
		log_verbose("%s%s-Encoding the CSR and converting it to a base 64 encoded string."
						, MODULE, FUNCTION);
		reqBytes = malloc(MAX_CSR_SIZE); // the csr should not be this long
		if ( NULL != reqBytes )
		{
			unsigned char* tempReqBytes = reqBytes;
			int writeLen = i2d_X509_REQ(req, &tempReqBytes);
			csrString = base64_encode(reqBytes, (size_t)writeLen, false, NULL);
			log_trace("%s%s-csrString=%s", MODULE, FUNCTION, csrString);
		}
		else
		{
			log_error("%s%s-Out of memory allocating %u bytes for reqBytes",
						MODULE, FUNCTION, MAX_CSR_SIZE);
		}
	}

	free(reqBytes);
	X509_REQ_free(req);
	return csrString;
}

static unsigned long write_cert_bio(BIO* bio, const char* b64cert)
{
	#undef FUNCTION
	#define FUNCTION "write_cert_bio"
	unsigned long errNum = 0;

	unsigned char* certBytes = NULL;
	size_t outLen;
	X509* certStruct = NULL;
	certBytes = base64_decode(b64cert, -1, &outLen);

	const unsigned char* tempCertBytes = certBytes;
	// Long way around, but PEM_write was segfaulting
	if(d2i_X509(&certStruct, &tempCertBytes, outLen) && PEM_write_bio_X509(bio, certStruct))
	{
		log_verbose("%s%s-Cert written to BIO", MODULE, FUNCTION);
	}
	else
	{
		errNum = ERR_peek_last_error();
	}

	X509_free(certStruct);
	free(certBytes);
	return errNum;
}

static unsigned long write_key_bio(BIO* bio, const char* password,
																	 const EVP_PKEY* privKey)
{
	#undef FUNCTION
	#define FUNCTION "write_key_bio"
	unsigned long errNum = 0;

	const char* tmpPass = (password && strcmp(password, "") != 0) ? password : NULL;
	const EVP_CIPHER* tmpCiph = (password && strcmp(password, "") != 0) ? EVP_aes_256_cbc() : NULL;

	if(PEM_write_bio_PKCS8PrivateKey(bio, (EVP_PKEY*)privKey,
																	 tmpCiph, NULL, 0, 0, (char*)tmpPass))
	{
		log_verbose("%s%s-Key written to BIO", MODULE, FUNCTION);
	}
	else
	{
		errNum = ERR_peek_last_error();
	}
	return errNum;
}

unsigned long save_cert_key(const char* storePath, const char* keyPath,
														const char* password, const char* cert,
														const EVP_PKEY* privKey, char** pMessage,
														enum AgentApiResultStatus* pStatus)
{
	#undef FUNCTION
	#define FUNCTION "save_cert_key"
	unsigned long err = 0;
	BIO* certBIO = NULL;
	BIO* keyBIO = NULL;
	log_verbose("%sEntering function %s", MODULE, FUNCTION);
	err = backup_file(storePath);
	if(err != 0 && err != ENOENT)
	{
		char* errStr = strerror(err);
		log_error("%s%s-Unable to backup store at %s: %s\n",
													MODULE, FUNCTION, storePath, errStr);
		append_linef(pMessage, "Unable to open store at %s: %s", storePath, errStr);
		*pStatus = STAT_ERR;
	}
	else
	{
		certBIO = BIO_new(BIO_s_mem());
		keyBIO = NULL;

		err = write_cert_bio(certBIO, cert);
		if(err)
		{
			char errBuf[120];
			ERR_error_string(err, errBuf);
			log_error("%s%s-Unable to write certificate to BIO: %s", MODULE, FUNCTION, errBuf);
			append_linef(pMessage, "Unable to write certificate to BIO: %s", errBuf);
			*pStatus = STAT_ERR;
		}
	}
	if(!err)
	{
		if(keyPath)
		{
			keyBIO = BIO_new(BIO_s_mem());
			err = write_key_bio(keyBIO, password, privKey);
		}
		else
		{
			err = write_key_bio(certBIO, password, privKey);
		}

		if(err)
		{
			char errBuf[120];
			ERR_error_string(err, errBuf);
			log_error("%s%s-Unable to write key to BIO: %s", MODULE, FUNCTION, errBuf);
			append_linef(pMessage, "Unable to write key to BIO: %s", errBuf);
			*pStatus = STAT_ERR;
		}
	}

	if(!err)
	{
		char* data = NULL;
		long len = BIO_get_mem_data(certBIO, &data);
		err = replace_file(storePath, data, len, true);

		if(err)
		{
			char* errStr = strerror(err);
			log_error("%s%s-Unable to write store at %s: %s",
											MODULE, FUNCTION, storePath, errStr);
			append_linef(pMessage, "Unable to write store at %s: %s",
												storePath, errStr);
			*pStatus = STAT_ERR;
		}
	}

	if(!err && keyPath)
	{
		char* data = NULL;
		long len = BIO_get_mem_data(keyBIO, &data);
		err = replace_file(keyPath, data, len, true);

		if(err)
		{
			char* errStr = strerror(err);
			log_error("%s%s-Unable to write key at %s: %s", MODULE, FUNCTION, keyPath, errStr);
			append_linef(pMessage, "Unable to write key at %s: %s", keyPath, errStr);
			*pStatus = STAT_ERR;
		}
	}

	if ( certBIO ) BIO_free(certBIO);
	if ( keyBIO  ) BIO_free(keyBIO);
	return err;
}
