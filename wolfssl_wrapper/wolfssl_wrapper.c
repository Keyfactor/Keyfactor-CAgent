/******************************************************************************/
/* Copyright 2021 Keyfactor                                                   */
/* Licensed under the Apache License, Version 2.0 (the "License"); you may    */
/* not use this file except in compliance with the License.  You may obtain a */
/* copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless */
/* required by applicable law or agreed to in writing, software distributed   */
/* under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   */
/* OR CONDITIONS OF ANY KIND, either express or implied. See the License for  */
/* thespecific language governing permissions and limitations under the       */
/* License.                                                                   */
/******************************************************************************/

#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include "wolfssl_wrapper.h"
#include "../utils.h"
#include "../logging.h"
#include "../lib/base64.h"
#include "../global.h"

/* NOTE:                                                                      */
/*  <wolfssl/options.h> & <wolfssl/wolfcrypt/settings.h>                      */
/*  are included in the header file so that they appear before any            */
/*  other included wolf library, per the wolf protocol.                       */
/*                                                                            */

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>	
/* Included in header file =  <wolfssl/wolfcrypt/types.h>                     */
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/pkcs12.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "../openssl_compat.h" 

#define RSA_DEFAULT_EXP 65537
#define MAX_CSR_SIZE 8192 /* shouldn't get longer than this */
#define SHA1LEN 20
#define MAX_ENTROPY_SIZE 2048 /* 4096 bytes */
#define ONEK_SIZE 1024
#define FOURK_SIZE (4*ONEK_SIZE)
#define FIVEK_SIZE (5*ONEK_SIZE)

/* Only return a byte of randomness at a time */
#if defined(RAND_MAX)
#	undef RAND_MAX
#endif
#define RAND_MAX 0xFF  

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/
enum keyTypeEnum
{
	NO_KEY_TYPE,
	RSA_KEY_TYPE,
	ECC_KEY_TYPE
};

struct entropy_storage
{
	byte* entropy_blob;
	bool has_entropy_loaded;
	size_t current_byte_ptr;
	size_t entropy_size;
};
typedef struct entropy_storage entropy_storage;

/**                                                                           */
/* This structure temporarily matches a PEMInventoryItem to an X509 cert      */
/* by its location in the PEMInventoryItem List.  That is the cert at         */
/* location 0 in PEMInventoryItem is matched to the X509 cert in this list.   */
/*                                                                            */
struct PEMx509List
{
	int item_count;
	WOLFSSL_X509** certs;
};
typedef struct PEMx509List PEMx509List;

/**                                                                           */
/* This structure allows for dynamic allocation of a list of private keys     */
/* located in a store.                                                        */
/*                                                                            */
struct PrivKeyList
{
	int key_count;
	WOLFSSL_EVP_PKEY** priv_keys;
};
typedef struct PrivKeyList PrivKeyList;

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/
/* Native wolfssl doesn't provide a keyPair union structure */
/* Instead we must hold both types of Keypairs */
RsaKey rsaKey;
ecc_key eccKey;
enum keyTypeEnum keyType = NO_KEY_TYPE;

/* Hold the private key in this structure, too because some wolf functions */
/* require the above key types, and some wolf functions require this type  */
/* this key is stored as a DER */
WOLFSSL_EVP_PKEY privateKey;
WOLFSSL_EVP_PKEY* pPrivateKey = &privateKey;

/* Also, native wolfSSL requires you to handhold the RNG, so create a */
/* Variable to hold the RNG seed if entropy was provided and a structure */
/* to hold the entropy */
WC_RNG rng;
entropy_storage ES;

/* Use this global variable to hold a password for the callback function */
char* gPasswd = NULL;


/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**                                                                           */
/*                                                                            */
/* This function either uses a supplied entropy or generates some entropy     */
/* for the wc_GenerateSeed function internally defined by wolfssl             */
/*                                                                            */
/* @param  - none                                                             */
/* @return - A random (or psuedo-random) byte                                 */
/*                                                                            */
/*                                                                            */
byte custom_rng_seed_generator(void)
{
	byte returnByte;
	if ( ES.has_entropy_loaded && (0 < ES.entropy_size) ) {
		returnByte = ES.entropy_blob[ES.current_byte_ptr++];
		if(ES.entropy_size >= ES.current_byte_ptr) {
			/* make sure we can't overrun this buffer */
			ES.current_byte_ptr = 0; 
		}
	} else { 
		/* Use the OSes pseudo random number generator */
		returnByte = (byte)random();
	}
	return returnByte;
} /* custom_rng_seed_generator */

/**                                                                           */
/* Password Callback function for encrypted password encoding/decoding        */
/*                                                                            */
/* @param  - passwd = The password                                            */
/* @param  - sz = The number of characters in the password                    */
/* @param  - rwflag = 0 when reading, 1 when writing                          */
/* @param  - userdata = user parameter, in this case we pass a password or    */
/*                      null to use the global password                       */
/* @return - success : # of characters in the password                        */
/*           failure : -1                                                     */
/*                                                                            */
static WC_INLINE int PasswordCallBack(char* passwd, int sz, int rwflag, 
	void* userdata)
{
	(void)rwflag;/* we aren't going to implement writes differently than reads*/
	(void)userdata;
	/* Prefer user supplied data over global data */
	if (userdata != NULL) {
		log_trace("%s::%s(%d) : Using user data", LOG_INF);
		strncpy(passwd, (char*)userdata, sz);
		return (int)strlen((char*)userdata);
	}
	else {
		log_trace("%s::%s(%d) : User data is null", LOG_INF);
		if ( NULL == gPasswd )
		{
			gPasswd = strdup("");
		}
		passwd = strdup(gPasswd);
		return strlen(gPasswd);
	}
} /* PasswordCallBack */

/**                                                                           */
/* rewritten for wolfssl; tested = true;                                      */
/*                                                                            */
/* Compute the sha1 hash of the certificate                                   */
/*                                                                            */
/* @param  - [Input] : cert = the X509 cert to compute the thumbprint         */
/* @return - success : an ascii encoded thumbprint                            */
/*         - failure : NULL                                                   */
/*                                                                            */
static char* compute_thumbprint(WOLFSSL_X509* cert)
{
	const WOLFSSL_EVP_MD* pSha1 = wolfSSL_EVP_sha1();
	unsigned len = 0;
	unsigned char* buf = calloc(SHA1LEN, sizeof(*buf));

	if ( !buf )
	{
		log_error("%s::%s(%d) : Out of memory",	LOG_INF);
		return NULL;
	}

	int rc = wolfSSL_X509_digest(cert, pSha1, buf, &len);
	if ( (rc == 0) || (len != SHA1LEN) )
	{
		log_error("%s::%s(%d) : Error generating sha1 hash", LOG_INF);
		return NULL;
	}

	char* return_value = hex_encode(buf, len);
	if ( buf ) free(buf);
	/* Now convert the binary data to a character string */
	return return_value;
} /* compute_thumbprint */

/**                                                                           */
/* Convert a "naked" PEM into a PEM.  A naked PEM is a PEM without the        */
/* headers and footers.  (e.g., -----BEGIN CERTIFICATE-----,                  */
/* -----END CERTIFICATE-----, etc.).                                          */
/*                                                                            */
/* The Keyfactor platform sends down a DER to the Agent.  However, a DER      */
/* includes non-printable characters.  So, to send the DER down, the          */
/* Keyfactor platform encodes the DER as base 64.  This is the same data      */
/* as a PEM file without the begin and end.  This is why we get a naked PEM   */
/*                                                                            */
/*                                                                            */
/* To do this in wolf, convert the naked PEM to a DER.  A DER is a binary     */
/* representation of the PEM.  The PEM is a base64 (aka ASCII) representation */
/* of the data. The DER is always naked.                                      */
/*                                                                            */
/* Then convert the DER back to a PEM with the appropriate headers.  The      */
/* valid types are: CERT_TYPE, PRIVATEKEY_TYPE, ECC_PRIVATEKEY_TYPE, and      */
/* CERTREQ_TYPE.                                                              */
/*                                                                            */
/* NOTE: The pem structure is initialized here & must be freed by the calling */
/* function.                                                                  */
/*                                                                            */
/* @param  - [Input] : in = the naked PEM                                     */
/* @param  - [Output] : &pem = the completed PEM                              */
/* @parm   - [Input] : the type of PEM to write                               */
/* @return - success : true                                                   */
/*           failure : false                                                  */
/*                                                                            */
static bool naked_PEM_to_PEM(const char* in, char** pem, int type)
{
	bool bResult = false;
	int ret = 0;
	int pemSz = 0;
	size_t derSz = 0;
	byte* der = NULL;

	log_trace("%s::%s(%d) : Converting naked_PEM_to_PEM", LOG_INF);
	if ( 
		 (CERT_TYPE != type) && \
		 (PRIVATEKEY_TYPE != type) && \
		 (ECC_PRIVATEKEY_TYPE != type) && \
		 (CERTREQ_TYPE != type) )
	{
		log_error("%s::%s(%d) : Error in requested PEM type.  "
			"Type %d is not supported", LOG_INF, type);
		goto exit;
	}
	/* Decode the naked PEM to create the DER format */
	der = base64_decode(in, -1, &derSz);
	if ( !der || 0 == derSz )
	{
		log_error("%s::%s(%d) : Error decoding PEM", LOG_INF);
		goto exit;
	}
	/* Re-encode the PEM with headers & footers */
	pemSz = wc_DerToPemEx(der, derSz, NULL, 0, NULL, type);
	if ( 0 >= pemSz )
	{
		log_error("%s::%s(%d) : Error converting DER to PEM", LOG_INF);
		goto exit;
	}
	*pem = calloc(pemSz, sizeof(*(*pem)));
	if ( !(*pem) )
	{
		log_error("%s::%s(%d) : Out of memory", LOG_INF);
		goto exit;
	}
	ret = wc_DerToPemEx(der, derSz, (byte*)*pem, pemSz, NULL, type);
	if ( 0 >= ret )
	{
		log_error("%s::%s(%d) : Error converting DER to PEM second time", 
			LOG_INF);
		goto exit;
	}

	log_trace("%s::%s(%d) : Successfuly converted naked PEM to PEM", LOG_INF);
	bResult = true;
exit:
	if (!bResult) {
		if (*pem) free(*pem);
        *pem = NULL;
	}
	if (der) free(der);
	return bResult;
} /* naked_PEM_to_PEM */

/**                                                                           */
/* Allocate memory for a new PrivKeyList                                      */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success = a pointer to the newly allocated memory area           */
/*	       - failure = NULL                                                   */
/*                                                                            */
static PrivKeyList* PrivKeyList_new(void)
{
	PrivKeyList* pList = calloc(1,sizeof(*pList));
	if (pList)
	{
		pList->key_count = 0;
		pList->priv_keys = NULL;
	}
	else
	{
		log_error("%s::%s(%d) : Out of memory", LOG_INF);
	}
	return pList;
} /* PrivKeyList_new */

/**                                                                           */
/* Free the PrivKeyList from memory                                           */
/*                                                                            */
/* @param  - [Input] : list = the list to free                                */
/* @return - none                                                             */
/*                                                                            */
static void PrivKeyList_free(PrivKeyList* pList)
{
	if (0 < pList->key_count)
	{
		for(int i = 0; pList->key_count > i; i++)
		{
			log_trace("%s::%s(%d) : Freeing PrivKey #%d from PrivKeyList", 
				LOG_INF, i);
			if ( pList->priv_keys[i] )
			{
				wolfSSL_EVP_PKEY_free(pList->priv_keys[i]);
			}
		}
		pList->key_count = 0;
	}

	log_trace("%s::%s(%d) : Freeing the PrivKeyList", LOG_INF);
	if (pList->priv_keys) free(pList->priv_keys);
	if (pList) free(pList);
	pList = NULL;

	return;
} /* PrivKeyList_free */

/**                                                                           */
/* rewritten for wolfssl; tested = test;                                      */
/*                                                                            */
/* Add a key to a PrivKeyList                                                 */
/*                                                                            */
/* @param  - [Output] : list = the list to add the key into                   */
/* @param  - [Input]  : pPrivateKey = an EVP_PKEY                             */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
static bool PrivKeyList_add(PrivKeyList* pList, WOLFSSL_EVP_PKEY* pPrivateKey)
{
	bool bResult = false;

	if( pList && pPrivateKey )
	{
		pList->priv_keys = realloc(pList->priv_keys, 
			(1 + pList->key_count) * sizeof(*(pList->priv_keys)));

		if (pList->priv_keys)
		{
			log_trace("%s::%s(%d) : Added EVP_PKEY #%d to PrivKeyList", 
				LOG_INF, pList->key_count);
			pList->priv_keys[pList->key_count] = pPrivateKey;
			pList->key_count++;
			bResult = true;
		}
		else
		{
			log_error("%s::%s(%d) : Out of memory",	LOG_INF);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Either the list or PrivateKey was NULL", 
			LOG_INF);
	}
	return bResult;
} /* PrivKeyList_add */

/**                                                                           */
/* Allocate memory for a new PEMx509List                                      */
/*                                                                            */
/* NOTE: This item is linked to the PEMInventoryItemList.  For each entry in  */
/* the PEMInventoryItemList, the index is the same into this dynamic list     */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success = a pointer to the newly allocated memory area           */
/*	       - failure = NULL                                                   */
/*                                                                            */
static PEMx509List* PEMx509List_new(void)
{
	PEMx509List* pX509list = calloc(1,sizeof(*pX509list));
	if (pX509list)
	{
		pX509list->item_count = 0;
		pX509list->certs = NULL;
	}
	return pX509list;
} /* PEMx509List_new */

/**                                                                           */
/* Free the PEMx509List from memory                                           */
/*                                                                            */
/* @param  - [Input] : list = the list to free                                */
/* @return - none                                                             */
/*                                                                            */
static void PEMx509List_free(PEMx509List* pList)
{
	if (0 < pList->item_count)
	{
		for(int i = 0; pList->item_count > i; i++)
		{
			log_trace("%s::%s(%d) Freeing cert #%d from PEMx509List", 
				LOG_INF, i);
			wolfSSL_X509_free(pList->certs[i]);
		}
		pList->item_count = 0;
	}

	log_trace("%s::%s(%d) : Freeing the PEMx509List", LOG_INF);
	if (pList ->certs) free(pList->certs);
	if (pList) free(pList);
	pList = NULL;

	return;
} /* PEMx509List_free */

/**                                                                           */
/* Add an X509 cert to a PEMx509List                                          */
/*                                                                            */
/* @param  - [Output] : list = the list to add the cert to                    */
/* @param  - [Input]  : cert = the cert to add to the list                    */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
static bool PEMx509List_add(PEMx509List* pList, WOLFSSL_X509* pCert)
{
	bool bResult = false;
	if(pList && pCert)
	{
		pList->certs = realloc(pList->certs, 
			(1 + pList->item_count) * sizeof(pCert));
		if (pList->certs)
		{
			log_trace("%s::%s(%d) : Adding X509 cert #%d to PEMx509List", 
				LOG_INF, pList->item_count);
			pList->certs[pList->item_count] = pCert;
			pList->item_count++;
			bResult = true;
		}
		else
		{
			log_error("%s::%s(%d) : Out of memory",	LOG_INF);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Either the pList or cert was NULL", LOG_INF);
	}
	return bResult;
} /* PEMx509List_add */

/******************************************************************************/
/* NOTE: PemInventoryItem and list are created here, but freed in the Agent.  */
/* The ssl wrapper MUST know about this structure to communicate with the     */
/* agent layer.                                                               */
/******************************************************************************/
/**                                                                           */
/* Allocate memory for a new PemInventoryItem                                 */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success : a pointer to the memory allocated for the new item     */
/*         - failure : NULL                                                   */
/*                                                                            */
static PemInventoryItem* PemInventoryItem_new()
{
	PemInventoryItem* pPem = calloc(1,sizeof(*pPem));
	if(pPem)
	{
		pPem->cert = NULL;
		pPem->thumbprint_string = NULL;
		pPem->has_private_key = false;
	}
	else
	{
		log_error("%s::%s(%d) : Out of memory",	LOG_INF);
	}
	return pPem;
} /* PemInventoryItem_new */

/**                                                                           */
/* NOTE: GLOBAL FUNCTION                                                      */
/*                                                                            */
/* Free a PemInventory item from memory                                       */
/*                                                                            */
/* @param  - [Input] : pem = the pem Item to free                             */
/* @return - none                                                             */
/*                                                                            */
void PemInventoryItem_free(PemInventoryItem* pem)
{
	if(pem)
	{
		if (pem->cert) {
			log_trace("%s::%s(%d) : Freeing pem inventory item cert", LOG_INF);
			 free(pem->cert);
			 pem->cert = NULL;
		}
		if (pem->thumbprint_string) {
			log_trace("%s::%s(%d) : Freeing pem inventory item thumbprint", 
				LOG_INF);
			free(pem->thumbprint_string);
			pem->thumbprint_string = NULL;
		}		
		free(pem);
	}
	return;
} /* PemInventoryItem_free */

/**                                                                           */
/* Populate a PemInventoryItem with a certificate and thumbnail.              */
/* Default the has_private_key bit to false.                                  */
/*                                                                            */
/* @param  - [Output] : pem = the PemInventoryItem to populate                */
/* @param  - [Input]  : cert = the Cert to populate into the pem item         */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
static bool PemInventoryItem_populate(PemInventoryItem* pem, WOLFSSL_X509* cert)
{
	bool bResult = false;
	char* pThumb = NULL;
	unsigned char* pCertContent = NULL;
	int contLen = 0;

	if (pem && cert)
	{
		pThumb = compute_thumbprint(cert);
		if ( NULL == pThumb )
		{
			pThumb = strdup("NULL");
		}
		log_verbose("%s::%s(%d) : Thumbprint: %s", LOG_INF, pThumb );
		contLen = wolfSSL_i2d_X509(cert, &pCertContent);

		if (0 < contLen)
		{
			/* Store the PEM minus any header or footer in here */
			/* Note a PEM is a DER that is base64 encoded */
			pem->cert = base64_encode(pCertContent, contLen, false, NULL);
			pem->thumbprint_string = strdup(pThumb);
			pem->has_private_key = false;
			bResult = true;
			log_trace("%s::%s(%d) : Cert added to a PemInventoryItem", LOG_INF);
		}
		else
		{
			log_error("%s::%s:(%d) : Error decoding cert i2d_X509\n%s", 
				LOG_INF, pCertContent);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Bad pem, cert, or certString",
			LOG_INF);
	}
	if ( pThumb )
	{
		free(pThumb);
	}
	if ( pCertContent )
	{
		wolfSSL_OPENSSL_free(pCertContent);
	}
	return bResult;
} /* PemInventoryItem_populate */

/**                                                                           */
/* Allocate memory for a new PemInventoryList                                 */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success : a pointer to the memory allocated for the new list     */
/*         - failure : NULL                                                   */
/*                                                                            */
static PemInventoryList* PemInventoryList_new()
{
	PemInventoryList* pList = (PemInventoryList*)malloc(sizeof(*pList));
	if(pList)
	{
		pList->item_count = 0;
		pList->items = NULL;
	}
	return pList;
} /* PemInventoryList_new */

/**                                                                           */
/* Free the PemInventoryList from memory                                      */
/*                                                                            */
/* @param  - [Input] : list = the PemInventoryList to free from memory        */
/* @return - none                                                             */
/*                                                                            */
void PemInventoryList_free(PemInventoryList* list)
{
	if(list && list->items)
	{
		for(int i = 0; list->item_count > i; i++)
		{
			log_trace("%s::%s(%d) : Freeing PemInventoryItem #%d", LOG_INF, i);
			PemInventoryItem_free(list->items[i]);
		}		
		log_trace("%s::%s(%d) : Freeing PemInventoryList", LOG_INF);
		if (list->items) free(list->items);
		if (list) free(list);
		list = NULL;
	}
	return;
} /* PemInventoryList_free */

/**                                                                           */
/* Add a PemInventoryItem to a PemInventoryList                               */
/*                                                                            */
/* @param  - [Ouput] : list = the list to add to (NULL if the add fails)      */
/* @param  - [Input] : item = the item to add to the list                     */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
static bool PemInventoryList_add(PemInventoryList* list, PemInventoryItem* item)
{
	bool bResult = false;
	if(list && item)
	{
		list->items = realloc(list->items, 
			(1 + list->item_count) * sizeof(item));
		if (list->items)
		{
			list->items[list->item_count] = item;
			list->item_count++;
			log_trace("%s::%s(%d) : Added cert with thumbprint %s to local "
				" inventory", LOG_INF, item->thumbprint_string);
			bResult = true;
		}
		else
		{
			log_error("%s::%s(%d) : Out of memory", LOG_INF);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Either the list or item was NULL", LOG_INF);
	}
	return bResult;
} /* PemInventoryList_add */

/**                                                                           */
/* Free the local keys, as they are no longer required                        */
/*                                                                            */
/* @param  - none                                                             */
/* @return - none                                                             */
/*                                                                            */
static void free_local_keys(void)
{

	log_trace("%s::%s(%d) : Freeing RSA key", LOG_INF);
	wc_FreeRsaKey(&rsaKey);


	log_trace("%s::%s(%d) : Freeing ECC key", LOG_INF);
	wc_ecc_free(&eccKey);

	log_trace("%s::%s(%d) : Freeing RNG", LOG_INF);
	wc_FreeRng(&rng);


	keyType = NO_KEY_TYPE;	

	log_trace("%s::%s(%d) : Freeing EVP_PKEY structure", LOG_INF);
	wolfSSL_EVP_PKEY_free(pPrivateKey); 
	pPrivateKey = NULL;

	return;
} /* free_local_keys */

/**                                                                           */
/* Compare the public key stored in the certificate with a private key and    */
/* determine if they are a matched pair.                                      */
/*                                                                            */
/* @param  - [Input] : cert = An x509 certificate (contining a pub key)       */
/* @param  - [Input] : key = a keypair structure containing a private key     */
/* @return - true = public key is the pair for the private key                */
/*		   - false = they key types or common factors are not equal           */
/*                                                                            */
static bool is_cert_key_match(WOLFSSL_X509* cert, WOLFSSL_EVP_PKEY* key)
{
	bool ret = false;
	RSA* rsaPriv = NULL;
	RSA* rsaCert = NULL;
	EC_KEY* ecPriv = NULL;
	EC_KEY* ecCert = NULL;
	EVP_PKEY* certPubKey = NULL;
	int certBaseId = -1;
	int keyBaseId = -1;
	const BIGNUM* nCert;
	const BIGNUM* nPriv;
	const EC_POINT* privPoint;
	const EC_GROUP* privGroup;
	const EC_POINT* certPoint;
	const EC_GROUP* certGroup;
	char* privPubBytes = NULL;
	char* certPubBytes = NULL;

	if(cert && key)
	{
		/* Get the public key from cert */
		certPubKey = wolfSSL_X509_get_pubkey(cert);	
		/* Get the type of the public key */	
		certBaseId = wolfSSL_EVP_PKEY_base_id(certPubKey); 
		/* Get the type of the private key passed */
		keyBaseId = wolfSSL_EVP_PKEY_base_id(key);  

		/* if the key types match we need to process things further */
		if(certBaseId == keyBaseId) 
		{
			switch(certBaseId)
			{
			case EVP_PKEY_RSA:
				rsaPriv = wolfSSL_EVP_PKEY_get1_RSA(key);		
				rsaCert = wolfSSL_EVP_PKEY_get1_RSA(certPubKey);
				if(rsaCert && rsaPriv)
				{
					/* get RSA n (ignore d & e) */
					wolfSSL_RSA_get0_key(rsaCert, &nCert, NULL, NULL); 
					wolfSSL_RSA_get0_key(rsaPriv, &nPriv, NULL, NULL); 
					/* Compare the n's which should be equal */
					/* when the priv and public key match */
					ret = (wolfSSL_BN_cmp(nCert, nPriv) == 0); 
				}
				wolfSSL_RSA_free(rsaPriv);
				wolfSSL_RSA_free(rsaCert);
				break;
			case EVP_PKEY_EC:
				ecPriv = wolfSSL_EVP_PKEY_get1_EC_KEY(key);		
				ecCert = wolfSSL_EVP_PKEY_get1_EC_KEY(certPubKey);  
				if(ecPriv && ecCert)
				{
					/* get EC_POINT public key */
					privPoint = wolfSSL_EC_KEY_get0_public_key(ecPriv); 
					/* get EC_GROUP  */
					privGroup = wolfSSL_EC_KEY_get0_group(ecPriv); 
					/*                                                        */
					/* Convert the ECC_POINT using the EC_GROUP's curve into a*/
					/* Hex representation:                                    */
					/*                                                        */
					/* An EC_GROUP structure is used to represent the         */
					/* 	definition of an elliptic curve.                      */
					/* An EC_POINT represents a point on the EC_GROUP's curve.*/
					/*                                                        */
					/* EC_POINT can be converted to and from various external */
					/* representations. The octet form is the binary encoding */
					/* of the ECPoint structure (as defined in RFC5480 and    */
					/* used in certificates and TLS records): only the content*/
					/* octets are present, the OCTET STRING tag and length are*/
					/* not included.                                          */
					/* BIGNUM form is the octet form interpreted as a big     */
					/* endian integer converted to a BIGNUM structure.        */
					/* Hexadecimal form is the octet form converted to a NULL */
					/* terminated character string where each character is one*/
					/* of the printable values 0-9 or A-F (or a-f).           */
					/*                                                        */
					/* For POINT_CONVERSION_UNCOMPRESSED the point is encoded */
					/* as an octet signifying the UNCOMPRESSED form has been  */
					/* used followed by the octets for x, followed by the     */
					/* octets for y.                                          */
					/*                                                        */
					privPubBytes = wolfSSL_EC_POINT_point2hex(privGroup, 
						privPoint, POINT_CONVERSION_UNCOMPRESSED, NULL);
					/* get EC_POINT public key */
					certPoint = wolfSSL_EC_KEY_get0_public_key(ecCert); 
					/* get EC_GROUP */
					certGroup = wolfSSL_EC_KEY_get0_group(ecCert); 
					certPubBytes = wolfSSL_EC_POINT_point2hex(certGroup, 
						certPoint, POINT_CONVERSION_UNCOMPRESSED, NULL);

					/* Now that we have the point on the curve compare them, 
					 * they should be equal if the keys match */
					ret = (strcasecmp(privPubBytes, certPubBytes) == 0);

					wolfSSL_OPENSSL_free(privPubBytes);
					wolfSSL_OPENSSL_free(certPubBytes);
				}
				wolfSSL_EC_KEY_free(ecCert);
				wolfSSL_EC_KEY_free(ecPriv);
				break;
			default:
				log_error("%s::%s(%d) : Unknown algorithm: %d", 
					LOG_INF, certBaseId);
				break;
			}
		}

		wolfSSL_EVP_PKEY_free(certPubKey);
	}

	return ret;
} /* is_cert_key_match */

/**                                                                           */
/* Look through the subject to decode the subject's value                     */
/* e.g., if subject is CN=12345,O=Keyfactor then this function is passed      */
/* the portion after the equals sign.  The first time it is called, it will   */
/* receive 12345,O=Keyfactor.  It will return 12345                           */
/* The next time it is called it will be passed Keyfactor & return Keyfactor. */
/*                                                                            */
/* If an ascii escaped string is encountered it parses the value accordingly. */
/* e.g., if domain\\user is sent, the subject is converted to domain\user     */
/*                                                                            */
/* If an ascii escaped hex value is encontered it parses the value accordingly*/
/* e.g., if \\3F  then the value ? is returned.                               */
/*                                                                            */
/* @param  - [Input] : subject = a portion of the full subject after a key    */
/*                               i.e., it starts with a value for the key     */
/* @param  - [Ouput] : buf = string containing the value                      */
/* @return - success : how far into the subject string we found a subject     */
/*					   separator                                              */
/*         - failure : -1                                                     */
/*                                                                            */
static int read_subject_value(const char* subject, char* buf)
{
	int subjLen = strlen(subject);
	int subInd = 0;
	int bufInd = 0;
	char c = ' ';
	char escaped[1] = {' '};
	unsigned int hexHi, hexLo;

	bool done = false;
	bool hasError = false;

	while(!done && !hasError && subInd < subjLen)
	{
		c = subject[subInd];
		switch(c)
		{
		case '\\':
			if(sscanf(&subject[subInd], "\\%1[\" #+,;<=>\\]", escaped) == 1) {
				if(buf)	{
					buf[bufInd++] = escaped[0];
				}
				subInd += 2;
			}
			else if(sscanf(&subject[subInd], "\\%1x%1x", &hexHi, &hexLo) == 2){
				if(buf)	{
					buf[bufInd++] = (char)((hexHi << 4) | hexLo);
				}
				subInd += 3;
			}
			else {
				hasError = true;
			}
			break;
		case ',':
			done = true;
			break;
		default:
			if(buf)	{
				buf[bufInd++] = c;
			}
			++subInd;
			break;
		}
	}

	if(buf)	{
		buf[bufInd] = '\0'; /* Null terminate the string */
	}

	return hasError ? -1 : subInd;
} /* read_subject_value */

/**                                                                           */
/* Return a pointer to the first non-space element in the string.  The string */
/* MAY be modified by this function by adding a NULL ('\0') terminator        */
/* inside the string.  This null terminator may be before the null terminator */
/* of the original string.                                                    */
/*                                                                            */
/* for example, both of these may happen:                                     */
/*   string = " I have spaces before and after me      "\0                    */
/* Here is what happens this function does:                                   */
/*                                                                            */
/* sring = " I have spaces before and after me      "\0                       */
/*           ^                                ^ is replaced with \0           */
/*           |                                                                */
/*            - beg (returned value)                                          */
/*                                                                            */
/* NOTE: This doesn't ADD any dynamically allocated memory                    */
/*       so you MUST NOT DEALLOCATE the returned value.  The returned         */
/*       value is at a minimum, a subset pointing inside the original data    */
/*       structure.  At a maximum it is the same pointer.                     */
/*                                                                            */
/* @param  - [Input/Output] : string = the string to parse                    */
/* @param  - [Input] : the length of the string                               */
/* @return - none                                                             */
/*                                                                            */
static char* strip_blanks(char* string, const unsigned long strSz)
{
	char* beg = string;  /* Copy the pointer so we can advance */
	char* end = string + strlen(string) - 1; /* Point to the string's end */

	/* Remove any leading spaces */
	while (isspace((unsigned char)*beg)) 
	{
		beg++;
	}

	/* beg now points to the first non whitespace character */
	/* now find the last non-whitespace character */
	while (isspace((unsigned char)*end) && (end != (beg-1)) )
	{
		end--;
	}

	/* Null terminate one after the last non-whitespace character */
	end[1] = '\0';

	return beg;
} /* strip_blanks */

/**                                                                           */
/* Populate the correct subject of the certificate request                    */
/*                                                                            */
/* @param  - [Input/Output] nm = The name to modify                           */
/* @param  - [Input] key = the subject key to modify                          */
/* @param  - [Input] value = the value to populate                            */
/* @return - none                                                             */
/*                                                                            */
static void populate_subject(Cert* pReq, char* key, char* value)
{
	if ( 0 == (strcasecmp(key,"C")) ) 
	{
		log_trace("%s::%s(%d) : Setting Country to %s", LOG_INF, value);
		strncpy(pReq->subject.country, value, CTC_NAME_SIZE-1);
	} 
	else if ( 0 == (strcasecmp(key,"S")) ) 
	{
		log_trace("%s::%s(%d) : Setting State to %s", LOG_INF, value);
		strncpy(pReq->subject.state, value, CTC_NAME_SIZE-1);
	} 
	else if ( 0 == (strcasecmp(key,"L")) ) 
	{
		log_trace("%s::%s(%d) : Setting locality to %s", LOG_INF, value);
		strncpy(pReq->subject.locality, value, CTC_NAME_SIZE-1);
	} 
	else if ( 0 == (strcasecmp(key,"O")) ) 
	{
		log_trace("%s::%s(%d) : Setting Organization to %s", LOG_INF, value);
		strncpy(pReq->subject.org, value, CTC_NAME_SIZE-1);
	} 
	else if ( 0 == (strcasecmp(key,"OU")) ) 
	{
		log_trace("%s::%s(%d) : Setting Organizational Unit to %s", LOG_INF, 
			value);
		/* Note pReq->subject.unit is only 64 bytes, so only copy 63 */
		strncpy(pReq->subject.unit, value, CTC_NAME_SIZE-1);
	} 
	else if ( 0 == (strcasecmp(key,"CN")) ) 
	{
		log_trace("%s::%s(%d) : Setting Common Name to %s", LOG_INF, value);
		strncpy(pReq->subject.commonName, value, CTC_NAME_SIZE-1);
	} 
	else 
	{
		log_info("%s::%s(%d) : key = %s is unknown, skipping", LOG_INF, key);
	}
	return;
} /* populate_subject */

/**                                                                           */
/* Take an ASCII subject and convert it into an openSSL                       */
/* X509_NAME structure                                                        */
/*                                                                            */
/* @param  - [Input] : subject = ascii subject string                         */
/* @return - success = a ptr to a filled out X509_NAME subject                */
/*         - failure = NULL                                                   */
/*                                                                            */
static bool parse_subject(Cert* pReq, const char* subject)
{
	bool bResult = false;
	char* keyBytes = NULL;
	char* strippedKey = NULL;
	unsigned long keyLen = 0;
	char* valBytes = NULL;
	char* strippedVal = NULL;
	unsigned long valLen = 0;
	char* localSubjectPtr = NULL;
	bool hasError = false;
	int cur = 0;
	char* curPtr = NULL;
	int allocateMemorySize = 0;
	bool endOfSubject = false;

	localSubjectPtr = strdup(subject);
	curPtr = localSubjectPtr;
	log_debug("%s::%s(%d) : Subject \"%s\" is %ld characters long", 
		LOG_INF, curPtr, strlen(curPtr));

	log_trace("%s::%s(%d) : hasError = %s endOfSubject = %s", LOG_INF, 
		hasError ? "true" : "false", endOfSubject ? "true" : "false");
	
	while( !hasError && !endOfSubject )
	{
		/* Get the Key */
		keyLen = strcspn(curPtr, "=");
		allocateMemorySize = (int)keyLen + 1;
		keyBytes = calloc(allocateMemorySize,sizeof(*keyBytes));
		if (NULL == keyBytes)
		{
			log_error("%s::%s(%d) : Out of memory", LOG_INF);
			goto cleanup;
		}		
		strncpy(keyBytes, curPtr, (int)keyLen);
		
		strippedKey = strip_blanks(keyBytes, keyLen);   
		log_verbose("%s::%s(%d) : Key: \"%s\" is %ld characters long", 
			LOG_INF, strippedKey, strlen(strippedKey));

		/* Now get the value for the key */
		curPtr += (keyLen+1); /* Advance past the equals character */
		if( *curPtr != '\0' )
		{
			log_trace("%s::%s(%d) : localSubject is now \"%s\"", 
				LOG_INF, curPtr);
			valLen = read_subject_value(curPtr, NULL);
			if(valLen != 0)
			{
				allocateMemorySize = (int)valLen + 1;
				valBytes = calloc(allocateMemorySize,sizeof(*valBytes));
				if (NULL == valBytes)
				{
					log_error("%s::%s(%d) : Out of memory", LOG_INF);
					goto cleanup;
				}			
				read_subject_value(curPtr, valBytes);
				curPtr += (valLen+1); // advance past the comma
				strippedVal = strip_blanks(valBytes, strlen(valBytes));
			   log_verbose("%s::%s(%d) : Value: \"%s\" is %ld characters long",	
			   		LOG_INF, strippedVal, strlen(strippedVal));

				populate_subject(pReq, strippedKey, strippedVal); 

				/* Don't try to advance if we just advanced past the 
				 * null-terminator */
				if( *(curPtr-1) != '\0' ) 
				{
					if ( *curPtr != '\0' )
					{
						/* Whitespace between RDNs should be ignored */
						log_trace("%s::%s(%d) : Stripping leading whitespace"
							" from \"%s\"", LOG_INF, curPtr);
						curPtr = strip_blanks(curPtr, strlen(curPtr));
					}
					else
					{
						log_trace("%s::%s(%d) : Reached end of subject string", 
							LOG_INF);
						endOfSubject = true;
					}
				}
				else
				{
					log_trace("%s::%s(%d) : Reached end of subject string", 
						LOG_INF);
					endOfSubject = true;
				}
			}
			else
			{
				log_error("%s::%s(%d) : Input string '%s' is not a valid "
					"X509 name", LOG_INF, localSubjectPtr);
				hasError = true;
			}
		}
		else
		{
			log_error("%s::%s(%d) : Input string '%s' is not a valid X509"
				" name", LOG_INF, localSubjectPtr);
			hasError = true;
		}
		if (keyBytes) free(keyBytes);
		if (valBytes) free(valBytes);
		/* Remember, *DONT* double free valBytes by freeing strippedVal */
		/* Likewise with strippedKey */
		keyBytes = NULL;
		valBytes = NULL;
		strippedVal = NULL;
		strippedKey = NULL;
		log_trace("%s::%s(%d) : hasError = %s endOfSubject = %s", LOG_INF, 
			hasError ? "true" : "false", endOfSubject ? "true" : "false");
	}

	if (!hasError) bResult = true;

cleanup:
	if (localSubjectPtr)
	{
		log_trace("%s::%s(%d) : Freeing localSubjectPtr", LOG_INF);
		free(localSubjectPtr);
		localSubjectPtr = NULL;
	}
	if (keyBytes) free(keyBytes);
	if (valBytes) free(valBytes);
	/* Remember, *DONT* double free valBytes by freeing strippedVal */
	/* Likewise with strippedKey */
	keyBytes = NULL;
	valBytes = NULL;
	strippedVal = NULL;
	strippedKey = NULL;

	return bResult;
} /* parse_subject */

/**                                                                           */
/* Convert the base 64 encoded cert into a BIO structure to use in saving     */
/* NOTE: The Keyfactor platform sends down the certificate as a DER, except   */
/*       that DER is base 64 encoded to send via HTTP.  The result is a       */
/*       "naked PEM" that is, a PEM without the -----BEGIN CERTIFICATE-----   */
/*       and -----END CERTIFICATE---- in it.                                  */
/*                                                                            */
/* To get a true PEM to write to disk, we leverage the internal conversion    */
/* routines.  So, decode the "naked PEM" to create a DER.                     */
/* then write the DER function as a PEM into a BIO structure.                 */
/*                                                                            */
/* When the BIO gets populated, the ----BEGIN CERTIFICATE---- and -----END    */
/* CERTIFICATE----- are added.  In addition, this method verifies that the    */
/* data passed from the Keyfactor platform is a valid certificate structure   */
/* and wasn't corrupted in transit.                                           */
/*                                                                            */
/* @param  - [Output] : the bio to write the cert into                        */
/* @return - success : 0                                                      */
/*         - failure : error code                                             */
/*                                                                            */
static unsigned long write_cert_bio(WOLFSSL_BIO* pBio, const char* pB64cert)
{
	unsigned long errNum = 0;
	char* pem = NULL;

	log_trace("%s::%s(%d) : Converting naked PEM to CERT PEM", LOG_INF);
	if ( !naked_PEM_to_PEM(pB64cert, &pem, CERT_TYPE) )
	{
		log_error("%s::%s(%d) : Error converting naked PEM to CERT PEM", 
			LOG_INF);
		errNum = -1;
		goto cleanup;
	}
	log_trace("%s::%s(%d) : Successfully converted naked PEM to PEM", LOG_INF);
	
	wolfSSL_BIO_puts(pBio, pem);
	log_verbose("%s::%s(%d) : Cert written to BIO", LOG_INF);
	
cleanup:
	if ( pem ) free(pem);
	return errNum;
} /* write_cert_bio */

/**                                                                           */
/* Convert a private key into a BIO structure to use in saving                */
/*                                                                            */
/* @param  - [Output] : the bio to write the key into                         */
/* @param  - [Input] : A password (or NULL or "" if none) to encode the bio   */
/* @param  - [Input] : An WOLFSSL_EVP_PKEY pointer structure or NULL if we    */
/*                     should use the global structure                        */
/* @return - success : 0                                                      */
/*         - failure : error code                                             */
/*                                                                            */
static unsigned long write_key_bio(WOLFSSL_BIO* pBio, const char* password, 
	WOLFSSL_EVP_PKEY* pkey)
{
	unsigned long errNum = 0;

	const char* tmpPass = 
	(password && strcmp(password, "") != 0) ? password : NULL;

	const WOLFSSL_EVP_CIPHER* tmpCiph = 
	(password && strcmp(password, "") != 0) ? wolfSSL_EVP_aes_256_cbc() : NULL;

	if ( NULL == pkey ) /* We want to save the keyPair since no key was passed*/
	{
		log_trace("%s::%s(%d) : Writing temporary keyPair to BIO", LOG_INF);
		errNum = wolfSSL_PEM_write_bio_PKCS8PrivateKey(pBio, pPrivateKey, 
			tmpCiph, NULL, 0, PasswordCallBack, (char*)tmpPass);
		if(0 < errNum)
		{
			log_verbose("%s::%s(%d) : Key written to BIO", LOG_INF);
			free_local_keys();
			errNum = 0;
		}
		else
		{
			errNum = ERR_peek_last_error();
		}
	}
	else
	{
		errNum = wolfSSL_PEM_write_bio_PKCS8PrivateKey(pBio, pkey, tmpCiph, 
			NULL, 0, PasswordCallBack, (char*)tmpPass);
		if(0 < errNum)
		{
			log_verbose("%s::%s(%d) : Key written to BIO", LOG_INF);
			errNum = 0;
		}
		else
		{
			errNum = ERR_peek_last_error();
		}
	}

	return errNum;
} /* write_key_bio */

/**                                                                           */
/* Read a list of keys from a keystore                                        */
/*                                                                            */
/* @param  - [Input] path = location of the keystore                          */
/* @param  - [Input] password = password of the keys in the keystore          */
/* @param  - [Ouput] ppKeyList = the array of keys                            */
/*                   NOTE: This must be freed by the calling function         */
/* @return - success = 0                                                      */
/*           failure = Any other integer                                      */
/*                                                                            */
static int get_key_inventory(const char* path, const char* password, 
	PrivKeyList** ppKeyList)
{
	int ret = 0;
	long length = 0;
	FILE* fp = NULL;
	char* name = NULL;
	char* header = NULL;
	unsigned char* pData = NULL;
	WOLFSSL_BIO* pKeyBio = NULL;
	char aErrBuf[256];
	/* Don't lose the pointer so it can be freed */
	const unsigned char* pTempData = pData; 

	const char* tmpPass = 
		(password && strcmp(password, "") != 0) ? password : NULL;

	/* Set the global password for callback */
	if ( tmpPass )
	{
		gPasswd = strdup(tmpPass);
	}

	/* Create an array to store keys into */
	*ppKeyList = PrivKeyList_new();
	if ( NULL == *ppKeyList )
	{
		log_error("%s::%s(%d) : Out of memory", LOG_INF);
		return -1;
	}

	/* Open the filestore */
	fp = fopen(path, "r");
	if(!fp)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s::%s(%d) : Unable to open store at %s: %s", 
			LOG_INF, path, errStr);
		free(errStr);
		goto cleanup;
	}

	/* Loop through the filestore adding keys to the keyList */
	WOLFSSL_EVP_PKEY* pKey = NULL;
	while(wolfSSL_PEM_read(fp, &name, &header, &pData, &length))
	{
		pKey = NULL;
		pTempData = pData;
	
		if( (strcasecmp(name, "CERTIFICATE") == 0) )
		{
			log_error("%s::%s(%d) WARNING: Certificate found in keystore"
				" -- skipping", LOG_INF);
		}
		else if( (strcasecmp(name, "PRIVATE KEY") == 0) && 
			     (wolfSSL_d2i_AutoPrivateKey(&pKey, &pTempData, length)) )
		{
			log_verbose("%s::%s(%d) : Entry is a private key", LOG_INF);
			PrivKeyList_add(*ppKeyList, pKey);
		}
		else if(strcasecmp(name, "ENCRYPTED PRIVATE KEY") == 0)
		{
			log_trace("%s::%s(%d) : FOUND ENCRYPTED PRIVATE KEY, "
				"Attempting decrypt", LOG_INF);
			log_trace("%s::%s(%d) : Using PASSWORD = %s", LOG_INF, gPasswd);

			pKeyBio = wolfSSL_BIO_new_mem_buf(pTempData, length);
			log_trace("%s::%s(%d) : DECODED BIO = \n%s", LOG_INF, \
				(char*)base64_encode(pKeyBio->ptr,length,false,NULL));

			pKey = \
				wolfSSL_d2i_PKCS8PrivateKey_bio(pKeyBio,&pKey,PasswordCallBack, 
					(void*)tmpPass );

	        if (pKey == NULL) {
	            unsigned long errNum = wolfSSL_ERR_peek_last_error();
				ERR_error_string(errNum, aErrBuf);
				log_error("%s::%s(%d) : Unable to decrypt private key:"
					" %s Error code = %ld", LOG_INF, aErrBuf, errNum);
				ret = -1;
	        }
	        else
			{
				log_verbose("%s::%s(%d) : Entry is an encrypted private key", 
					LOG_INF);
				PrivKeyList_add(*ppKeyList, pKey);
			}
			wolfSSL_BIO_free(pKeyBio);
		}
		else
		{
			log_verbose("%s::%s(%d) : Entry is not a key, and will be skipped", 
				LOG_INF);
		}

		wolfSSL_OPENSSL_free(name);
		wolfSSL_OPENSSL_free(header);
		wolfSSL_OPENSSL_free(pData);
		length = 0;
	}

cleanup:
	if ( fp ) fclose(fp);
	if ( gPasswd )
	{
		free(gPasswd);
		gPasswd = NULL;
	}
	return ret;
} /* get_key_inventory */

/**                                                                           */
/* rewritten for wolfssl, tested = true                                       */
/*                                                                            */
/* Read the inventory of certificates and keys located at path.               */
/* This function always populates PemInventoryList.  However, it can also     */
/* return the PEMx509List and the PrivKeyList.  The latter two assist in      */
/* key management functions.                                                  */
/*                                                                            */
/* @param  - [Input] : path = the store location                              */
/* @param  - [Input] : password = the password for private keys               */
/* @param  - [Output]: pPemList = the PemInventory                            */
/* @param  - [Output]: (optional) pPemArray = the X509 cert array which is    */
/*                     mapped 1:1 with the pPemList. The latter only contains */
/*                     the ASCII representation of the cert.                  */
/* @param  - [Input] : returnX509array =                                      */
/*                     true if you want the array passed back via pPemArray   */
/*                       NOTE: This means the calling function must dispose   */
/*                             of the allocated memory                        */
/*                     false disposes of the array here                       */
/* @param  - [Output]: (optional) pKeyArray = the list of private keys in the */
/*                     store                                                  */
/* @param  - [Input] : returnKeyArray =                                       */
/*                     true if you want the array passed back via pKeyArray   */
/*                       NOTE: This means the calling function must dispose   */
/*                             of the allocated memory                        */
/*                     false disposes of the array here                       */
/* @return - success = 0                                                      */
/*         - failure = any other integer                                      */
/*                                                                            */
static int get_inventory(const char* path, const char* password, 
	PemInventoryList** ppPemList, PEMx509List** pPemArray, 
	const bool returnX509array, PrivKeyList** pKeyArray, 
	const bool returnKeyArray)
{
	int ret = 0; 
	char* name = NULL;
	char* header = NULL;
	unsigned char* data = NULL;
	WOLFSSL_BIO* pKeyBio = NULL;
	long length = 0;
	char errBuf[1024];
	char* pErrBuf = &errBuf[0];

	const char* tmpPass = 
		(password && strcmp(password, "") != 0) ? password : NULL;

	if (tmpPass)
	{
		gPasswd = strdup(tmpPass);
	}

	/* Open the filestore */
	log_trace("%s::%s(%d) : Opening %s", LOG_INF, path);
	FILE* fp = fopen(path, "r");
	if(!fp)
	{
		ret = errno;
		pErrBuf = strerror(errno);
		log_error("%s::%s(%d) : Unable to open store at %s: %s", 
			LOG_INF, path, pErrBuf);
		return ret;
	}
	log_trace("%s::%s(%d) : Opened file, now allocating memory for new lists", 
		LOG_INF);

	/* Create the inventory list to share with the agent */
	*ppPemList = PemInventoryList_new();
	log_trace("%s::%s(%d) : Created a new PemInventoryList", LOG_INF);
	/* Now create a 'mirror' array where each index into the                  */
	/* PemInventoryList->items array is equal to the index into this array.   */
	/* That is:                                                               */
	/* PemInventoryList->items[x] = PEMx509List->certs[x] for all values of x */
	/*                                                                        */ 
	PEMx509List* x509array = PEMx509List_new(); 
	log_trace("%s::%s(%d) : Created a new PEMx509List", LOG_INF);
	/* Also create an array into which private keys are stored */
	PrivKeyList* keyList = PrivKeyList_new();
	log_trace("%s::%s(%d) : Created a new PrivKeyList", LOG_INF);

	if ( (NULL == (*ppPemList)) || 
		 (NULL == x509array) || 
		 (NULL == keyList) )
	{
		log_error("%s::%s(%d) : Out of memory",
			LOG_INF);
		ret = -1;
		goto cleanup;
	}

	PemInventoryItem* pem = NULL;
	WOLFSSL_X509* cert = NULL;
	WOLFSSL_EVP_PKEY* key = NULL;
	/* Don't lose the pointer so it can be freed */
	const unsigned char* tempData = data; 
	/* Loop through the data in the store, one object at a time */
	log_trace("%s::%s(%d) : Fetching objects from the datastore", LOG_INF);
	while(PEM_read(fp, &name, &header, &data, &length))
	{
		pem = NULL;
		cert = NULL;
		key = NULL;
		tempData = data;

		log_trace("%s::%s(%d) : found %s", LOG_INF, name);
		if( (strcmp(name, "CERTIFICATE") == 0) && \
			(wolfSSL_d2i_X509(&cert, &tempData, length)) )
		{
			/* Then, store it into the inventory list */
			pem = PemInventoryItem_new();
			if ( PemInventoryItem_populate(pem, cert) )
			{
				PemInventoryList_add(*ppPemList, pem);
				PEMx509List_add(x509array, cert);
			}
			else
			{
			  log_error("%s::%s(%d) Not adding cert to list of certs in store", 
			  	LOG_INF);
			}		
		}
		else if( (strcmp(name, "PRIVATE KEY") == 0) && 
			     (wolfSSL_d2i_AutoPrivateKey(&key, &tempData, length)) )
		{
			log_verbose("%s::%s(%d) : Entry is a private key", LOG_INF);
			PrivKeyList_add(keyList, key);
		}
		else if(strcmp(name, "ENCRYPTED PRIVATE KEY") == 0)
		{
			pKeyBio = wolfSSL_BIO_new_mem_buf(data, length);
			key = wolfSSL_d2i_PKCS8PrivateKey_bio(pKeyBio, &key, 
				PasswordCallBack, (char*)(password ? password : ""));
			if(NULL != key)
			{
				log_verbose("%s::%s(%d) : Entry is an encrypted private key", 
					LOG_INF);
				PrivKeyList_add(keyList, key);
			}
			else
			{
				unsigned long errNum = wolfSSL_ERR_peek_last_error();
				ERR_error_string(errNum, errBuf);
			  log_error("%s::%s(%d) : Unable to decrypt private key: %s = %ld", 
			  	LOG_INF, errBuf, errNum);
			}
			wolfSSL_BIO_free(pKeyBio);
		}
		else
		{
			log_verbose("%s::%s(%d) : Entry is not a certificate, "
				"and will be skipped", LOG_INF);
		}

		wolfSSL_OPENSSL_free(name);
		wolfSSL_OPENSSL_free(header);
		wolfSSL_OPENSSL_free(data);
		length = 0;
	}

	log_verbose("%s::%s(%d) : %d items in PEM list", LOG_INF, 
		(*ppPemList)->item_count);
	log_verbose("%s::%s(%d) : Checking for matching private keys", LOG_INF);
	for(int i = 0; i < (*ppPemList)->item_count; ++i)
	{
		log_verbose("%s::%s(%d) : Thumbprint: %s", LOG_INF, 
			(*ppPemList)->items[i]->thumbprint_string);

		for(int k = 0; k < keyList->key_count; ++k)
		{
			/* Use the x509array to grab the X509 certificate associated with */
			/* the (*ppPemList)->items[i]->cert.  Since *ppPemList has the    */
			/* cert stored as an ASCII encoded string instead of an X509 cert.*/
			/*                                                                */
			/* Remember, the x509array is a 1:1 match with the items array    */
			/* in the *ppPemList.                                             */
			/*                                                                */
			if(is_cert_key_match(x509array->certs[i], keyList->priv_keys[k]))
			{
				log_verbose("%s::%s(%d) : Found matching cert and private key", 
					LOG_INF);
				(*ppPemList)->items[i]->has_private_key = true;
			}
		}
	}

cleanup:
	/* Cleanup things */
	if ( x509array )
	{
		if ( !returnX509array || (0 != ret) )
		{
			log_trace("%s::%s(%d) : Freeing x509array", LOG_INF);
			/* We no longer need the X509 cert versions */
			PEMx509List_free(x509array); 
		}
		else
		{
			(*pPemArray) = x509array; /* Return the array */
		}
		x509array = NULL;
	}
	if ( *ppPemList && (0 != ret) )
	{
		log_trace("%s::%s(%d) : Freeing *ppPemList", LOG_INF);
		PemInventoryList_free(*ppPemList);
		*ppPemList = NULL;
	}
	if ( keyList )
	{
		if ( !returnKeyArray )
		{
			log_trace("%s::%s(%d) : Freeing keyList", LOG_INF);
			PrivKeyList_free(keyList);
		}
		else
		{
			(*pKeyArray) = keyList;

		}
		keyList = NULL;
	}

	if(fp)
	{
		log_trace("%s::%s(%d) : Closing fp", LOG_INF);
		fclose(fp);
		fp = NULL;
	}
	return ret;
} /* get_inventory */

/**                                                                           */
/* Add a new cert to the end of a store; this doesn't check to see if         */
/*                                                                            */
/*                                                                            */
/* @param  - [Input] : storePath = the stores location                        */
/* @param  - [Input] : cert = the X509 certificate                            */
/* @return - success = 0;                                                     */
/*           failure = Any other integer                                      */
/*                                                                            */
static int store_append_cert(const char* storePath, WOLFSSL_X509* pCert)
{
	FILE* fpAdd = fopen(storePath, "a");
	int ret = 0;
	if(!fpAdd)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s::%s(%d) : Unable to open store at %s: %s", LOG_INF, 
			storePath, errStr);
	}
	else
	{
		if(!wolfSSL_PEM_write_X509(fpAdd, pCert))
		{
			char errBuf[120];
			unsigned long errNum = ERR_peek_last_error();
			ERR_error_string(errNum, errBuf);
			log_error("%s::%s(%d) : Unable to write certificate to store: %s", 
				LOG_INF, errBuf);
			ret = -1;
		}

		if(fpAdd)
		{
			fclose(fpAdd);
		}
	}
	return ret;
} /* store_append_cert */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**                                                                           */
/* Take the ASCII entropy sent by the platform & seed the RNG                 */
/*                                                                            */
/* @param  - [Input] : b64entropy is the string to use to seed the RNG        */
/* @return - success : 0                                                      */
/*         - failure : -1                                                     */
/*                                                                            */
int ssl_seed_rng(const char* b64entropy)
{
	if(b64entropy)
	{	
		/* Init the locally global entropy variable with the provided entropy */
		/* convert the entropy from b64 */
		if (ES.entropy_blob) free(ES.entropy_blob); /* Free old entropy */
		ES.entropy_blob = base64_decode(b64entropy, -1, &ES.entropy_size);
		ES.has_entropy_loaded = true;
		ES.current_byte_ptr = 0;
		return 0;
	}
	else
	{
		log_error("%s::%s(%d) : No entropy provided", LOG_INF);
		return -1;
	}
} /* seed_rng */

/**                                                                           */
/* Generate an RSA keypair & store it into tempKeypair                        */
/* Also store it in the WOLFSSL_EVP_PKEY global structure                     */
/*                                                                            */
/* @param  - [Input] : keySize = the size of the RSA key                      */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
bool ssl_generate_rsa_keypair(int keySize)
{
	unsigned long errNum = 0;
	bool bResult = false;
	byte* pDer = NULL;
	const unsigned char ** ppDer = NULL;
	int derSz = 0;

	log_trace("%s::%s(%d) : Received request to generate RSA key of length %d", 
		LOG_INF, keySize);

	log_trace("%s::%s(%d) : Allocating space for DER", LOG_INF);
	pDer = calloc((keySize+1),sizeof(*pDer));	
	if(!pDer)
	{
		log_error("%s::%s(%d) : Out of memory", LOG_INF);
		goto fail_cleanup;
	}

	log_trace("%s::%s(%d) : Seeding the RNG", LOG_INF);
	errNum = wc_InitRng(&rng);
	if ( 0 != errNum )
	{
		log_error("%s::%s(%d) : Error seeding rng: %ld", LOG_INF, errNum);
		goto fail_cleanup;
	}
	
	log_trace("%s::%s(%d) : Initializing RSA key", LOG_INF);
	errNum = wc_InitRsaKey(&rsaKey, NULL); /* not using heap hint. */
	if ( 0 != errNum )
	{
		log_error("%s::%s(%d) : Error initializing RSA key", LOG_INF);
		goto fail_cleanup;
	}

	log_trace("%s::%s(%d) : Generating RSA key", LOG_INF);
	errNum = wc_MakeRsaKey(&rsaKey, keySize, RSA_DEFAULT_EXP, &rng);
	if ( 0 == errNum )
	{
		log_verbose("%s::%s(%d) : Successfully created RSA keypair - "
			"converting to DER", LOG_INF);
		derSz = wc_RsaKeyToDer(&rsaKey, pDer, (keySize+1));
		if (0 >= derSz)
		{
			log_error("%s::%s(%d) Error converting key to DER", LOG_INF);
			goto fail_cleanup;
		}

		ppDer = (const unsigned char**)&pDer;
		pPrivateKey = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, &pPrivateKey, 
			ppDer, derSz);
		if ( pPrivateKey )
		{
			log_trace("%s::%s(%d) : Successfully converted RSA keypair to DER", 
				LOG_INF);
		}
		else
		{
			log_error("%s::%s(%d) : Failed to convert RSA key to EVP_PKEY", 
				LOG_INF);
			goto fail_cleanup;
		}
	}
	else
	{
		log_error("%s::%s(%d) : Error making RSA key. code = %ld", LOG_INF, 
			errNum);
		goto fail_cleanup;
	}

/* successful_cleanup: */
	if (pDer)
	{
		/*NOTE wolfSSL_d2i_PrivateKey advanced pDer by derSz */
		/* So reset it back to the beginning of the der */
		pDer -= derSz; 
		free(pDer);
		pDer = NULL;
	}
	keyType = RSA_KEY_TYPE;
	bResult = true;
	return bResult;

fail_cleanup:
	if (pDer)
	{
		free(pDer);
		pDer = NULL;
	}
	if ( pPrivateKey )
	{
		log_trace("%s::%s(%d) : Freeing EVP_PKEY Private Key Structure", 
			LOG_INF);
		wolfSSL_EVP_PKEY_free(pPrivateKey);
	}
	keyType = NO_KEY_TYPE;
	return bResult;

} /* generate_rsa_keypair */

/**                                                                           */
/* rewritten for wolfssl, tested = true;                                      */
/*                                                                            */
/* Generate an ECC keypair & store it into tempKeypair                        */
/*                                                                            */
/* @param  - [Input] : keySize = the size of the ECC key                      */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
bool ssl_generate_ecc_keypair(int keySize)
{
	int eccNid = -1;
	int keySz = -1;
	unsigned long errNum = 0;
	bool bResult = false;
	byte* pDer = NULL;
	const unsigned char** ppDer = NULL;
	int derSz = 0;

	log_trace("%s::%s(%d) : Allocating memory for DER", LOG_INF);
	pDer = calloc(ONEK_SIZE, sizeof(*pDer));

	if ( !pDer ) 
	{
		log_error("%s::%s(%d) : Out of memory", LOG_INF);
		goto fail_cleanup;
	}

	switch(keySize)
	{
		case 256:
			log_trace("%s::%s(%d) : Setting ECC curve to ECC_SECP256R1", 
				LOG_INF);
			eccNid = ECC_SECP256R1; 
			keySz = 32; /* 256/8 = 32 bytes */
			break;
		case 384:
			log_trace("%s::%s(%d) : Setting ECC curve to ECC_SECP384R1", 
				LOG_INF);
			eccNid = ECC_SECP384R1;
			keySz = 48; /* 384/8 = 48 bytes */
			break;
		case 521:
			log_trace("%s::%s(%d) : Setting ECC curve to ECC_SECP521R1", 
				LOG_INF);
			eccNid = ECC_SECP521R1;
			keySz = 66; /* 521/8 = 65.125 bytes */
			break;
		default:
		log_error("%s::%s(%d) : Invalid ECC key length: %d. "
			"Falling back to default curve", LOG_INF, keySize);
			eccNid = ECC_SECP256R1;
			keySz = 32;
			break;
	}

	/**********************************************************************/
	/* Create keypair using wolfcrypt                                     */
	/**********************************************************************/
	log_trace("%s::%s(%d) : Initializing ECC key", LOG_INF);
	errNum = wc_ecc_init(&eccKey);
	if ( errNum != 0 )
	{
		log_error("%s::%s(%d) : Error initializing ecc key", LOG_INF);
		goto fail_cleanup;
	}

	log_trace("%s::%s(%d) : Initializing RNG", LOG_INF);
	errNum = wc_InitRng(&rng);
	if ( 0 != errNum )
	{
		log_error("%s::%s(%d) : Error seeding rng: %ld", LOG_INF, errNum);
		goto fail_cleanup;
	}

	log_trace("%s::%s(%d) : Generating ECC key", LOG_INF);
	errNum = wc_ecc_make_key_ex(&rng, keySz, &eccKey, eccNid);
	if (errNum != 0)
	{
		log_error("%s::%s(%d) : Error generating ecc key. code = %ld", 
			LOG_INF, errNum);
		goto fail_cleanup;
	}

	log_trace("%s::%s(%d) : Converting ECC to der", LOG_INF);
	derSz = wc_EccKeyToDer(&eccKey, pDer, ONEK_SIZE);
	if (0 >= derSz)
	{
		log_error("%s::%s(%d) : Error converting ECC key to DER", LOG_INF);
		goto fail_cleanup;
	}

	log_trace("%s::%s(%d) : Converting DER to EVP_PKEY structure", LOG_INF);
	ppDer = (const unsigned char**)&pDer;
	pPrivateKey = wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, &pPrivateKey, 
		ppDer, derSz);
	if ( pPrivateKey )
	{
		log_trace("%s::%s(%d) : Successfully converted ECC keypair to EVP_PKEY", 
			LOG_INF);
	}
	else
	{
		log_error("%s::%s(%d) : Failed to convert ECC key to EVP_PKEY", 
			LOG_INF);
		goto fail_cleanup;
	}

/* successful_cleanup: */
	/*NOTE wolfSSL_d2i_PrivateKey advanced pDer by derSz */
	if (pDer)
	{
		pDer -= derSz;
		free(pDer);
		pDer = NULL;
	}
	keyType = ECC_KEY_TYPE;
	bResult = true;
	return bResult;

fail_cleanup:
	if (pDer)
	{
		free(pDer);
		pDer = NULL;
	}
	keyType = NO_KEY_TYPE;
	return bResult;
} /* generate_ecc_keypair */

/**
 * rewritten for wolfssl; tested = true;
 *
 * Create a CSR using the subject provided and the temporary key keyPair.
 * Return an ASCII CSR (minus the header and footer).
 *
 * @param  - [Input]  : asciiSubject string with the subject line
 *                      e.g., CN=1234,OU=NA,O=Keyfactor,C=US
 * @param  - [Output] : csrLen the # of ASCII characters in the csr
 * @param  - [Output]: pMessage = a string array containing any messages
 *                                we want to pass back to the calling function
 * @return - success : the CSR string minus the header and footer
 *           failure : NULL
 */
char* ssl_generate_csr(const char* asciiSubject, size_t* csrLen, char** pMessage)
{
	char* csrString = NULL;
	byte* pDer = calloc(MAX_CSR_SIZE, sizeof(*pDer));
	Cert req;
	int derSz = -1;
	int ret = -1;

	/* Validate memory allocation succeeded */
	if ( !pDer )
	{
		log_error("%s::%s(%d) : Out of memory",	LOG_INF);
		goto cleanup;
	}

	/************************************************************************/
	/* 1.) Set up the CSR as a new Cert request by creating a blank request */
	/************************************************************************/
	log_verbose("%s::%s(%d) : Setting up a CSR", LOG_INF);
	/* Init the new structure */
	ret = wc_InitCert(&req);	
	if ( ret != 0 )
	{
		log_error("%s::%s(%d) : Init cert failed %d", LOG_INF, ret);
		append_linef(pMessage, "%s::%s(%d) : Init cert failed %d", LOG_INF, ret);
		goto cleanup;
	}
	req.version = 1;


	/************************************************************************/
	/* 2.) Update the request's subject                                     */
	/************************************************************************/
	if ( !parse_subject(&req, asciiSubject) )
	{
		log_error("%s::%s(%d) : Subject creation failed", LOG_INF);
		append_linef(pMessage, "%s::%s(%d) : Subject creation failed", LOG_INF);
		goto cleanup;
	}

	/************************************************************************/
	/* 3.) Add the CSR request to the DER before signing it. DER now has    */
	/*     the CSR request - which includes the public portion of the key.  */
	/************************************************************************/
	switch (keyType)
	{
		case ECC_KEY_TYPE:
			log_trace("%s::%s(%d) : Creating CSR Request with ECC key", 
				LOG_INF);
			ret = wc_MakeCertReq(&req, pDer, MAX_CSR_SIZE, NULL, &eccKey);
			break;
		case RSA_KEY_TYPE:
			log_trace("%s::%s(%d) : Creating CSR Request with RSA key", 
				LOG_INF);
			ret = wc_MakeCertReq(&req, pDer, MAX_CSR_SIZE, &rsaKey, NULL);
			break;
		case NO_KEY_TYPE:
		default:
			log_error("%s::%s(%d) : Error -- cannot make CSR before "
				"generating key pair", LOG_INF);
			goto cleanup;
	}
	if ( ret <= 0 ) {
		log_error("%s::%s(%d) : CSR creation failed code %d", LOG_INF, ret);
		append_linef(pMessage, "%s::%s(%d) : CSR creation failed code %d", 
			LOG_INF, ret);
		goto cleanup;
	}
	derSz = ret;

	/***********************************************************************/
	/* 4.) Sign the cert request that sits in der                          */
	/***********************************************************************/
	switch (keyType)
	{
		case ECC_KEY_TYPE:
			log_trace("%s::%s(%d) : Signing CSR Request with ECC key", LOG_INF);
			req.sigType = CTC_SHA256wECDSA;
			ret = wc_SignCert(req.bodySz, req.sigType, pDer, MAX_CSR_SIZE, 
				NULL, &eccKey, &rng);
			log_trace("%s::%s(%d) : Successfully exited signing function", 
				LOG_INF);
			break;
		case RSA_KEY_TYPE:
			log_trace("%s::%s(%d) : Signing CSR Request with RSA key", LOG_INF);
			req.sigType = CTC_SHA256wRSA;
			ret = wc_SignCert(req.bodySz, req.sigType, pDer, MAX_CSR_SIZE, 
				&rsaKey, NULL, &rng);
			log_trace("%s::%s(%d) : Successfully exited signing function", 
				LOG_INF);
			break;
		default:
			log_error("%s::%s(%d) : Logically can't get here!", LOG_INF);
			goto cleanup;
	}

	if ( ret <= 0 ) {
		log_error("%s::%s(%d) : CSR signing failed code %d", LOG_INF, ret);
		append_linef(pMessage, "%s::%s(%d) : CSR signing failed code %d", 
			LOG_INF, ret);
		goto cleanup;
	}
	derSz = ret;

	/************************************************************************/
	/* 5.) Encode the DER as b64 (aka PEM) to send to the platform          */
	/*     do it this way to prevent the BEGIN CERT REQUEST and             */
	/*     END CERT REQUEST lines from being added to the platform's request*/
	/************************************************************************/
    csrString = base64_encode(pDer, (size_t)derSz, false, NULL);
	*csrLen = strlen(csrString); 
	log_trace("%s::%s(%d) : csrString=\n%s", LOG_INF, csrString);
	log_trace("%s::%s(%d) : csrLen = %ld", LOG_INF, *csrLen);

cleanup:
	if ( pDer ) free(pDer);
	return csrString;
} /* ssl_generate_csr */

/**                                                                           */
/* rewritten for wolfssl; tested = true                                       */
/*                                                                            */
/* Save the cert and key to the locations requested                           */
/* Store the locally global variable keyPair to the location requested        */
/*                                                                            */
/* @param  - [Input] : storePath = the store location for the cert            */
/* @param  - [Input] : keyPath = the location to save the key, if NULL or     */
/*                     blank, store the encoded key appended to the cert.     */
/* @param  - [Input] : password = the password for the private key            */
/* @param  - [Input] : cert = The cert as a PEM without header & footer.      */
/*                            The act of creating a bio places the correct    */
/*                            Header and footer onto the PEM.                 */
/* @param  - [Output]: pMessage = a string array containing any messages      */
/*                     we want to pass back to the calling function           */
/* @return - unsigned long error code                                         */
/*                                                                            */
unsigned long ssl_save_cert_key(const char* storePath, const char* keyPath,	
	const char* password, const char* cert, char** pMessage)
{
	WOLFSSL_BIO* pCertBIO = NULL;
	WOLFSSL_BIO* pKeyBIO = NULL;
	char* pData = NULL;
	long len = 0;
	unsigned long err = 0;
	char errBuf[120];

	log_verbose("%s::%s(%d) : Entering function %s", LOG_INF, __FUNCTION__);
	err = backup_file(storePath);
	if(err != 0 && err != ENOENT)
	{
		char* errStr = strerror(err);
		log_error("%s::%s(%d) : Unable to backup store at %s: %s\n", 
			LOG_INF, storePath, errStr);
		append_linef(pMessage, "Unable to open store at %s: %s", 
			storePath, errStr);
		goto cleanup;
	}

	pCertBIO = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());

	err = write_cert_bio(pCertBIO, cert);
	if(err)
	{
		wolfSSL_ERR_error_string(err, errBuf);
		log_error("%s::%s(%d) : Unable to write certificate to BIO: %s", 
			LOG_INF, errBuf);
		append_linef(pMessage, "Unable to write certificate to BIO: %s", 
			errBuf);
		goto cleanup;
	}

	if(keyPath)
	{
		pKeyBIO = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
		err = write_key_bio(pKeyBIO, password, NULL); 
	}
	else
	{
		err = write_key_bio(pCertBIO, password, NULL); 
	}
	if(err)
	{
		wolfSSL_ERR_error_string(err, errBuf);
		log_error("%s::%s(%d) : Unable to write key to BIO: %ld - %s", 
			LOG_INF, err, errBuf);
		append_linef(pMessage, "Unable to write key to BIO: %ld - %s", 
			err, errBuf);
		goto cleanup;
	}

	len = wolfSSL_BIO_get_mem_data(pCertBIO, &pData);
	err = replace_file(storePath, pData, len, true);
	if(err)
	{
		char* errStr = strerror(err);
		log_error("%s::%s(%d) : Unable to write store at %s: %s", 
			LOG_INF, storePath, errStr);
		append_linef(pMessage, "Unable to write store at %s: %s", 
			storePath, errStr);
		goto cleanup;
	}

	if(keyPath)
	{
		pData = NULL; /* Don't point to pCertBio->ptr anymore */
		len = wolfSSL_BIO_get_mem_data(pKeyBIO, &pData);
		err = replace_file(keyPath, pData, len, true);
		if(err)
		{
			char* errStr = strerror(err);
			log_error("%s::%s(%d) : Unable to write key at %s: %s", 
				LOG_INF, keyPath, errStr);
			append_linef(pMessage, "Unable to write key at %s: %s", 
				keyPath, errStr);
			goto cleanup;
		}
	}

cleanup:
	if ( pCertBIO ) wolfSSL_BIO_free(pCertBIO);
	if ( pKeyBIO  ) wolfSSL_BIO_free(pKeyBIO);
	return err;
} /* ssl_save_cert_key */

/**                                                                           */
/* Read all of the certificates inside of the store at the path requested.    */
/* Convert each of these into a PemInventoryItem & add it into the variable   */
/* provided.                                                                  */
/*                                                                            */
/* @param  - [Input] : path = the path to the store (or the id of the store)  */
/* @param  - [Input] : password = the password of private keys in the store   */
/* @param  - [Output] : pPemList an array to hold the inventory               */
/*                     (SEND IN A NULL VARIABLE - we create the list in the   */
/*                      wrapper)                                              */
/* @return - success : 0                                                      */
/*		   - failure : the error code from opening the file or such           */
/*                                                                            */
int ssl_read_store_inventory(const char* path, const char* password, PemInventoryList** ppPemList)
{
	return get_inventory(path, password, ppPemList, NULL, false, NULL, false);
} /* ssl_read_store_inventory */

/**                                                                           */
/* Create a PemInventoryItem (with has_private_key set to false) from an      */
/* ASCII cert.  Verify the cert is valid & compute its thumbprint.            */
/*                                                                            */
/* NOTE: The PemInventoryItem must be freed by the calling function by        */
/*       invoking PemInventoryItem_free(pem);                                 */
/*                                                                            */
/* @param  - [Output] : ppPEMout = the variable which points to the new item  */
/* @param  - [Input] : pCertASCII = the naked PEM                             */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
bool ssl_PemInventoryItem_create(struct PemInventoryItem** ppPEMout, 
	const char* pCertASCII)
{
	bool bResult = false;
	WOLFSSL_X509* pCert = NULL;
	char* pPEM = NULL;
	WOLFSSL_BIO* pBIO = NULL;
	
	if ( !naked_PEM_to_PEM(pCertASCII, &pPEM, CERT_TYPE) )
	{
		log_error("%s::%s(%d) : Error converting naked PEM to PEM", LOG_INF);
		goto cleanup;
	}
	/* Place the PEM into a BIO structure to be decoded */
	pBIO = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
	wolfSSL_BIO_puts(pBIO, pPEM);
	
	if (pBIO && pPEM)
	{
		pCert = wolfSSL_PEM_read_bio_X509(pBIO, NULL, 0, NULL);
		if ( NULL == pCert )
		{
			log_error("%s::%s(%d) : This is not a valid X509 cert: \n%s", 
				LOG_INF, pPEM);
			goto cleanup;
		}
		/* cert now contains the X509 cert */
		if ( NULL == (*ppPEMout = PemInventoryItem_new()) )
		{
			log_error("%s::%s(%d) : Out of memory",	LOG_INF);
			goto cleanup;
		}
		/* Populate the PemInventoryItem with a thumbprint */
		if ( PemInventoryItem_populate(*ppPEMout, pCert) )
		{
			bResult = true;
		}
		else
		{
			log_error("%s::%s(%d) : Error populating cert",	LOG_INF);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Out of memory",	LOG_INF);
	}

cleanup:
	if (pPEM) free(pPEM); 
	if (pCert) wolfSSL_X509_free(pCert); 
	if (pBIO) wolfSSL_BIO_free(pBIO); 

	return bResult;
} /* ssl_PemInventoryItem_create */

/**                                                                           */
/* Append the certificate provided to the store.                              */
/*                                                                            */
/* @param  - [Input] : storePath = where to find the store                    */
/* @param  - [Input] : certASCII = a naked PEM                                */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
bool ssl_Store_Cert_add(const char* storePath, const char* certASCII)
{
	bool bResult = false;
	int ret = 0;
	char* pPem = NULL;
	WOLFSSL_X509* pCert = NULL;
	WOLFSSL_BIO* pBIO = NULL;

	log_trace("%s::%s(%d) : Converting naked PEM to a CERT PEM", LOG_INF);
	if ( !naked_PEM_to_PEM(certASCII, &pPem, CERT_TYPE) )
	{
		log_error("%s::%s(%d) : Error converting naked PEM to CERT PEM", 
			LOG_INF);
		goto exit;
	}

	log_trace("%s::%s(%d) : Converting cert to X509\n %s", LOG_INF, pPem);
	/* Place the PEM into a BIO structure to be decoded */
	pBIO = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
	wolfSSL_BIO_puts(pBIO, pPem);

	if (pBIO && pPem)
	{
		pCert = wolfSSL_PEM_read_bio_X509(pBIO, NULL, 0, NULL);
		if ( NULL == pCert )
		{
			log_error("%s::%s(%d) : This is not a valid cert:\n%s", 
				LOG_INF, pPem);
			goto exit;
		}

		ret = backup_file(storePath);
		if(ret != 0 && ret != ENOENT)
		{
			char* errStr = strerror(ret);
			log_error("%s::%s(%d) : Unable to backup store at %s: %s\n", 
				LOG_INF, storePath, errStr);
		}
		else
		{
			ret = store_append_cert(storePath, pCert);
			if ( 0 != ret )
			{
				log_error("%s::%s(%d) : Unable to append cert to store at %s", 
					LOG_INF, storePath);
				goto exit;
			}
			else
			{
				bResult = true;
			}
		}
	}
	else
	{
		log_error("%s::%s(%d) : Out of memory", LOG_INF);
	}

exit:
	if ( pCert ) wolfSSL_X509_free(pCert);
	if ( pPem ) free(pPem);
	if ( pBIO )	wolfSSL_BIO_free(pBIO);
	return bResult;
} /* ssl_Store_Cert_add */

/**
 * rewritten for wolfssl; tested = true
 *
 * Remove a cert (and associated key) from a store/keystore
 *
 * @param  - [Input] : storePath = the path for the certificate store
 * @param  - [Input] : searchThumb = the sha1 hash of the cert to remove
 * @param  - [Input] : keyPath = the path of the keystore.  
 *                     if NULL an use storePath
 * @param  - [Input] : password = password for any encrypted keys
 * @return - success : true
 *           failure : false
 */
bool ssl_remove_cert_from_store(const char* storePath, const char* searchThumb, 
	const char* keyPath, const char* password)
{
	bool bResult = false;
	PemInventoryList* pemList = NULL;
	PEMx509List* pemX509Array = NULL;
	PrivKeyList* keyArray = NULL;
	WOLFSSL_BIO* bio = NULL;
	char* data = NULL;
	size_t len = 0;
	int ret = 0;
	char* pem = NULL;

   /***************************************************************************/
   /*1.)Get the PEM inventory, X509 PEM, and list of private keys in the store*/
   /***************************************************************************/
	log_trace("%s::%s(%d) : Get PEM inventory",
		LOG_INF);
	if ( 0 != get_inventory(storePath, password, &pemList, &pemX509Array, true, 
		&keyArray, true) )
	{
		log_error("%s::%s(%d) : Failed to get inventory", LOG_INF);
		goto cleanup;
	}

	/**************************************************************************/
	/* 2.) Search for the certificate inside of the store by sha1 hash        */
	/**************************************************************************/
	log_trace("%s::%s(%d) : Search for matching hash to remove in inventory", 
		LOG_INF);
	bool certFound = false;
	int i = pemList->item_count-1;
	while ( (!certFound) && \
		    (0 <= i) )
	{
		log_trace("%s::%s(%d) : comparing thumbprint #%d "
			      "searchThumb = %s, "
			      "thumbprint = %s", \
			LOG_INF, i, searchThumb, \
			pemList->items[i]->thumbprint_string);
		if (0 == strcasecmp(searchThumb, pemList->items[i]->thumbprint_string) )
		{
			certFound = true;
			log_trace("%s::%s(%d) : Certificate #%d matches thumbprint %s", 
				LOG_INF, i, searchThumb);
		}
		else
		{
			i--;
		}
	}
	log_verbose("%s::%s(%d) : Found cert: %s", LOG_INF, 
		(certFound ? "yes" : "no"));

	/**************************************************************************/
	/* 3.) Update the store, but skip the cert we want to remove              */
	/**************************************************************************/
	if ( certFound )
	{
		/**************************/
		/* 3a.) Add all the certs */
		/**************************/
		log_trace("%s::%s(%d) : Writing certs to store", LOG_INF);
		/* Get new memory to store the bio */
		bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()); 
		/* At this point i points to the pemList & */
		/* PEMx509List of the cert to delete */
		for (int j = 0; pemList->item_count > j; j++)
		{
			if (i != j)
			{
				log_trace("%s::%s(%d) : Adding certificate #%d to BIO"
					" with thumbprint %s", LOG_INF, j, 
					(char*)pemList->items[j]->thumbprint_string);
				if ( pem ) free(pem);
				pem = NULL;
				if (!naked_PEM_to_PEM(pemList->items[j]->cert, &pem, CERT_TYPE)) 
				{
					log_error("%s::%s(%d) Failed converting naked PEM to PEM", 
						LOG_INF);
					goto cleanup;
				}
				ret = wolfSSL_BIO_puts(bio, pem);
				if ( 0 >= ret )
				{
					log_error("%s::%s(%d) : Failed to put cert into BIO", 
						LOG_INF);
					goto cleanup;
				}
			}
		}
		/**********************************************************************/
		/* 3b.) Add all the keys found but the one for the cert we don't want */
		/**********************************************************************/
		/* Now, loop through all the private keys & */
		/* save them too, except the one */
		for (int k = 0; keyArray->key_count > k; k++)
		{
			if ( !is_cert_key_match(pemX509Array->certs[i], 
				keyArray->priv_keys[k]) )
			{
				log_trace("%s::%s(%d) : Writing key #%d to BIO", LOG_INF, k);
				ret = write_key_bio(bio, password, keyArray->priv_keys[k]);
				if ( 0!= ret )
				{
					log_error("%s::%s(%d) : Failed to add key to BIO %s", 
						LOG_INF, storePath);
					goto cleanup;
				}
			}
		}

		/**********************/
		/* 3c.) Write to disk */
		/**********************/
		data = NULL;
		len = wolfSSL_BIO_get_mem_data(bio, &data);
		ret = replace_file(storePath, data, len, true);
		if( 0 != ret)
		{
			char* errStr = strerror(ret);
			log_error("%s::%s(%d) : Unable to write BIO at %s: %s", 
				LOG_INF, storePath, errStr);
			goto cleanup;
		}

		/**************************************************************/
		/* 3d.) Optional: if a keystore was provided, remove that key */
		/*      from the keystore                                     */
		/**************************************************************/
		if ( keyPath )
		{
			BIO_free(bio);
			free(data);
			if ( keyArray )
			{
				PrivKeyList_free(keyArray); /* Free this bit of keys */
			}
			/* And populate it with the keystore located at keyPath */
			ret = get_key_inventory(keyPath, password, &keyArray);
			if ( 0 != ret )
			{
				log_error("%s::%s(%d) : Error reading keystore %s", 
					LOG_INF, keyPath);
				goto cleanup;
			}
			bio = BIO_new(BIO_s_mem()); /* Get new memory to store the bio */
			/* Write the keys to bio memory */
			for (int x = keyArray->key_count; 0 < x; x--)
			{
				ret = write_key_bio(bio, password, keyArray->priv_keys[x]);
				if ( 0 != ret )
				{
					log_error("%s::%s(%d) : Failed to add key to store %s", 
						LOG_INF, keyPath);
					goto cleanup;
				}
			}

			/*******************************/
			/* 3e.) Write keystore to disk */
			/*******************************/
			data = NULL;
			len = wolfSSL_BIO_get_mem_data(bio, &data);
			ret = replace_file(keyPath, data, len, true);
			if( 0 != ret)
			{
				char* errStr = strerror(ret);
				log_error("%s::%s(%d) : Unable to write key at %s: %s", 
					LOG_INF, keyPath, errStr);
				goto cleanup;
			}
		} /* end separate keystore */
	}
	else
	{
		log_error("%s::%s(%d) Cert not found in PEM store %s", 
			LOG_INF, storePath);
		goto cleanup;
	}

cleanup:
	if ( pemList ) PemInventoryList_free(pemList);
	if ( pemX509Array )	PEMx509List_free(pemX509Array);
	if ( keyArray )	PrivKeyList_free(keyArray);
	if ( pem ) free(pem);
	if ( bio ) wolfSSL_BIO_free(bio);
	/* Note data is freed with bio, data is just a pointer into the bio */
	pem = NULL;
	data = NULL;
	bio = NULL;
	if ( 0 == ret )	bResult = true;
	return bResult;
} /* ssl_remove_cert_from_store */

/**                                                                           */
/* Verify if a provided certificate (in PEM format) is within its dates       */
/*                                                                            */
/* @param  - [Input] certFile = the filename with the PEM                     */
/* @return - Cert is in active range = true                                   */
/*           otherwise = false                                                */
bool ssl_is_cert_active(char* certFile)
{
    bool bResult = false;
    WOLFSSL_X509* x509 = NULL;
    const unsigned char* start_date = NULL;
    const unsigned char* end_date = NULL;
    time_t start_time = 0;
    time_t end_time = 0;
    time_t now = 0;

    do
    {
        log_info("%s::%s(%d) : Verify certificate is active", LOG_INF);
        log_trace("%s::%s(%d) : Reading PEM file %s", LOG_INF, certFile);
        x509 = wolfSSL_X509_load_certificate_file(certFile, SSL_FILETYPE_PEM);
        if (NULL == x509)
        {
            log_error("%s::%s(%d) : Error reading PEM file", LOG_INF);
            break;
        }

        log_trace("%s::%s(%d) : Getting certificate start date", LOG_INF);
        start_date = wolfSSL_X509_notBefore(x509);
        if(!start_date)
        {
            log_warn("%s::%s(%d) : Cannot get start date of the certificate",
                     LOG_INF);
            break;
        }

        log_trace("%s::%s(%d) : Getting certificate end date", LOG_INF);
        end_date = wolfSSL_X509_notAfter(x509);
        if(!end_date)
        {
            log_warn("%s::%s(%d) : Cannot get end date of the certificate",
                     LOG_INF);
            break;
        }

        if(start_date && end_date)
        {
            log_verbose("%s::%s(%d) : Certificate is valid from "
                        "20%c%c-%c%c-%c%c %c%c:%c%c:%c%c GMT to "
                        "20%c%c-%c%c-%c%c %c%c:%c%c:%c%c GMT",
                        LOG_INF,
                        (char)start_date[2], (char)start_date[3],
                        (char)start_date[4], (char)start_date[5],
                        (char)start_date[6], (char)start_date[7],
                        (char)start_date[8], (char)start_date[9],
                        (char)start_date[10], (char)start_date[11],
                        (char)start_date[12], (char)start_date[13],
                        (char)end_date[2], (char)end_date[3],
                        (char)end_date[4], (char)end_date[5],
                        (char)end_date[6], (char)end_date[7],
                        (char)end_date[8], (char)end_date[9],
                        (char)end_date[10], (char)end_date[11],
                        (char)end_date[12], (char)end_date[13]);
        }

        log_trace("%s::%s(%d) : Converting start date to a time_t structure",
                  LOG_INF);
        string_to_time_t(start_date, &start_time);
        if( (time_t)-1 == start_time )
        {
            log_error("%s::%s(%d) : Failed to convert start date structure"
                      " to time_t", LOG_INF);
            break;
        }

        log_trace("%s::%s(%d) : Converting end date to a time_t structure",
                  LOG_INF);
        string_to_time_t(end_date, &end_time);
        if( (time_t)-1 == end_time )
        {
            log_error("%s::%s(%d) Failed to convert end date to a time_t "
                      "structure", LOG_INF);
            break;
        }

        log_trace("%s::%s(%d) : Getting curent GMT time", LOG_INF);
        now = time(&now);
        if( (time_t)-1 == now )
        {
            log_error("%s::%s(%d) : Failed to get local time", LOG_INF);
            break;
        }
        now = mktime(gmtime(&now));
        if( (time_t)-1 == now )
        {
            log_error("%s::%s(%d) : Failed to convert local time to GMT", LOG_INF);
            break;
        }

        log_trace("%s::%s(%d) : Current GMT time %ld", LOG_INF, now);
        log_trace("%s::%s(%d) : %s", LOG_INF, ctime(&now));
        log_verbose("%s::%s(%d) : Comparing start time of %ld to "
                    "current time of %ld", LOG_INF, start_time, now);

        if( now < start_time )
        {
            log_error("%s::%s(%d) : Error certificate is NOT active yet", LOG_INF);
            break;
        }

        log_verbose("%s::%s(%d) : Comparing end time of %ld to "
                    "current time of %ld", LOG_INF, end_time, now);

        if( now > end_time )
        {
            log_error("%s::%s(%d) : Error certificate is EXPIRED", LOG_INF);
            break;
        }

        log_info("%s::%s(%d) : Certificate dates are ok", LOG_INF);
        bResult = true;
    } while(false);

    if (!bResult)
    {
        log_info("%s::%s(%d) : Certificate dates are not ok", LOG_INF);
    }
    if (x509) wolfSSL_X509_free(x509);
    return bResult;
} /* ssl_isCertActive */

/**                                                                           */
/* Initialize the platform to use wolfssl                                     */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success : true                                                   */
/*           failure : false                                                  */
/*                                                                            */
bool ssl_init(void)
{
	int errNum = 0;
	log_trace("%s::%s(%d) : Initializing wolfssl and wolfcrypt", LOG_INF);
	
	errNum = wolfSSL_Init();
	if (WOLFSSL_SUCCESS != errNum) 
	{
		log_trace("%s::%s(%d) : wolfSSL_Init failed with code = %d", 
			LOG_INF, errNum);
		return false;
	}
	
	errNum = wolfCrypt_Init(); 
	/* wolfCrypt returns 0 on success not WOLFSSL_SUCCESS */
	if (0 != errNum) 
	{
		log_error("%s::%s(%d) : wolfCrypt_Init() failed with code = %d", 
			LOG_INF, errNum);
	    return false;
	}
	
	/* Initialize the entropy blob */
	ES.entropy_blob = NULL; /* If we seed this, we will allocate memory */
	ES.has_entropy_loaded = false;
	ES.current_byte_ptr = 0;
	ES.entropy_size = 0;

	/* Seed the pseudo-random number generator on the OS */
	srandom(time(NULL));
	return true;
} /* ssl_init */

/**                                                                           */
/* Clean up all of the wolfssl items that are outstanding                     */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success - true                                                   */
/*           failure - false                                                  */
/*                                                                            */
bool ssl_cleanup(void)
{
	int errNum = 0;
	bool bResult = true;
	log_trace("%s::%s(%d) : Cleaning up local key structures", LOG_INF);
	free_local_keys();

	if(ES.entropy_blob)
    {
    	log_trace("%s::%s(%d) : Freeing entropy_blob", LOG_INF);
    	free(ES.entropy_blob);
    	ES.entropy_blob = NULL;
    	ES.has_entropy_loaded = false;
    	ES.current_byte_ptr = 0;
    	ES.entropy_size = 0;
    }

	log_trace("%s::%s(%d) : Freeing RNG", LOG_INF);
	wc_FreeRng(&rng);

	log_trace("%s::%s(%d) : Cleaning up wolfcrypt", LOG_INF);
	errNum = wolfCrypt_Cleanup();
	if ( 0 != errNum )
	{
		log_error("%s::%s(%d) : wolfCrypt_Cleanup failed with code = %d", 
			LOG_INF, errNum);
		bResult = false;
	}
	log_trace("%s::%s(%d) : Cleaning up wolfssl", LOG_INF);
	errNum = wolfSSL_Cleanup();
	if ( WOLFSSL_SUCCESS != errNum )
	{
		log_error("%s::%s(%d) : wolfSSL_Cleanup failed with code = %d", 
			LOG_INF, errNum);
		bResult = false;
	}
    return bResult;
} /* ssl_cleanup */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/