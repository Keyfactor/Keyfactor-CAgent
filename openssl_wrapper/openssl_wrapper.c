/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include "openssl_wrapper.h"
#include "../utils.h"
#include "../logging.h"
#include "../lib/base64.h"
#include "../global.h"

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "../openssl_compat.h" // Took this out of utils.c

#ifndef SSL_SUCCESS
#define SSL_SUCCESS 1
#endif

#define RSA_DEFAULT_EXP 65537
#define MAX_CSR_SIZE 1024 // shouldn't get longer than this
#define SHA1LEN 20

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/**
 * This structure temporarily matches a PEMInventoryItem to an X509 cert
 * by its location in the PEMInventoryItem List.  That is the cert at location
 * 0 in PEMInventoryItem is matched to the X509 cert in this list.
 */
struct PEMx509List
{
	int item_count;
	X509** certs;
};
typedef struct PEMx509List PEMx509List;

/**
 * This structure allows for dynamic allocation of a list of private keys
 * located in a store.
 */
struct PrivKeyList
{
	int key_count;
	EVP_PKEY** keys;
};
typedef struct PrivKeyList PrivKeyList;

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/
/* This keypair is for temporary storage in memory. */
/* Once the certificate is received from the platform, this gets stored to */
/* The file system */
EVP_PKEY* keyPair = NULL;

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * Compute the sha1 hash of the certificate
 *
 * @param  - [Input] : cert = the X509 cert to compute the thumbprint
 * @return - success : an ascii encoded thumbprint
 *         - failure : NULL
 */
static char* compute_thumbprint(X509* cert)
{
	const EVP_MD* sha1 = EVP_sha1();
	unsigned char buf[SHA1LEN];
	unsigned len = 0;

	int rc = X509_digest(cert, sha1, buf, &len);
	if ( (rc == 0) || (len != SHA1LEN) )
	{
		return NULL;
	}

	return hex_encode(buf, len);
} /* compute_thumbprint */

/**
 * Allocate memory for a new PrivKeyList
 *
 * @param  - none
 * @return - success = a pointer to the newly allocated memory area
 *	       - failure = NULL
 */
static PrivKeyList* PrivKeyList_new(void)
{
	PrivKeyList* list = (PrivKeyList*)calloc(1,sizeof(*list));
	if (list)
	{
		list->key_count = 0;
		list->keys = NULL;
	}
	else
	{
		log_error("%s::%s(%d) : Out of memory", \
			__FILE__, __FUNCTION__, __LINE__);
	}
	return list;
} /* PrivKeyList_new */

/**
 * Free the PrivKeyList from memory
 *
 * @param  - [Input] : list = the list to free
 * @return - none
 */
static void PrivKeyList_free(PrivKeyList* pList)
{
	if (0 < pList->key_count)
	{
		for(int i = 0; pList->key_count > i; i++)
		{
			log_trace("%s::%s(%d) : Freeing PrivKey #%d from PrivKeyList", \
				__FILE__, __FUNCTION__, __LINE__, i);
			if ( pList->keys[i] )
			{
				EVP_PKEY_free(pList->keys[i]);
			}
		}
		pList->key_count = 0;
	}

	log_trace("%s::%s(%d) : Freeing the PrivKeyList", \
		__FILE__, __FUNCTION__, __LINE__);
	if (pList->keys) free(pList->keys);
	if (pList) free(pList);
	pList = NULL;

	return;
} /* PrivKeyList_free */

/**
 * Add a key to a PrivKeyList
 *
 * @param  - [Output] : list = the list to add the key into
 * @param  - [Input]  : cert = the key to add to the list
 * @return - success : true
 *         - failure : false
 */
static bool PrivKeyList_add(PrivKeyList* list, EVP_PKEY* key)
{
	bool bResult = false;
	if(list && key)
	{
		list->keys = realloc(list->keys, \
			(1 + list->key_count) * sizeof(key));
		if (list->keys)
		{
			log_trace("%s::%s(%d) : Added EVP_PKEY #%d to PrivKeyList", \
				__FILE__, __FUNCTION__, __LINE__, list->key_count);
			list->keys[list->key_count] = key;
			list->key_count++;
			bResult = true;
		}
		else
		{
			log_error("%s::%s(%d) : Out of memory",
				__FILE__, __FUNCTION__, __LINE__);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Either the list or key was NULL", \
			__FILE__, __FUNCTION__, __LINE__);
	}
	return bResult;
} /* PrivKeyList_add */

/**
 * Allocate memory for a new PEMx509List
 *
 * NOTE: This item is linked to the PEMInventoryItemList.  For each entry in
 * the PEMInventoryItemList, the index is the same into this dynamic list
 *
 * @param  - none
 * @return - success = a pointer to the newly allocated memory area
 *	       - failure = NULL
 */
static PEMx509List* PEMx509List_new(void)
{
	PEMx509List* x509list = (PEMx509List*)calloc(1,sizeof(*x509list));
	if (x509list)
	{
		x509list->item_count = 0;
		x509list->certs = NULL;
	}
	return x509list;
} /* PEMx509List_new */

/**
 * Free the PEMx509List from memory
 *
 * @param  - [Input] : list = the list to free
 * @return - none
 */
static void PEMx509List_free(PEMx509List* pList)
{
	if (0 < pList->item_count)
	{
		for(int i = 0; pList->item_count > i; i++)
		{
			log_trace("%s::%s(%d) Freeing cert #%d from PEMx509List",\
				__FILE__, __FUNCTION__, __LINE__, i);
			X509_free(pList->certs[i]);
		}
		pList->item_count = 0;
	}

	log_trace("%s::%s(%d) : Freeing the PEMx509List", \
		__FILE__, __FUNCTION__, __LINE__);
	if (pList ->certs) free(pList->certs);
	if (pList) free(pList);
	pList = NULL;

	return;
} /* PEMx509List_free */

/**
 * Add an X509 cert to a PEMx509List
 *
 * @param  - [Output] : list = the list to add the cert to
 * @param  - [Input]  : cert = the cert to add to the list
 * @return - success : true
 *         - failure : false
 */
static bool PEMx509List_add(PEMx509List* list, X509* cert)
{
	bool bResult = false;
	if(list && cert)
	{
		list->certs = realloc(list->certs, \
			(1 + list->item_count) * sizeof(cert));
		if (list->certs)
		{
			log_trace("%s::%s(%d) : Adding X509 cert #%d to PEMx509List", \
				__FILE__, __FUNCTION__, __LINE__, list->item_count);
			list->certs[list->item_count] = cert;
			list->item_count++;
			bResult = true;
		}
		else
		{
			log_error("%s::%s(%d) : Out of memory",
				__FILE__, __FUNCTION__, __LINE__);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Either the list or cert was NULL", \
			__FILE__, __FUNCTION__, __LINE__);
	}
	return bResult;
} /* PEMx509List_add */

/**************************************************************************** 
 * NOTE: PemInventoryItem and list are created here, but freed in the Agent.  
 * The ssl wrapper MUST know about this structure to communicate with the 
 * agent layer.
 ***************************************************************************/
/**
 * Allocate memory for a new PemInventoryItem
 *
 * @param  - none
 * @return - success : a pointer to the memory allocated for the new item
 *         - failure : NULL
 */
static PemInventoryItem* PemInventoryItem_new()
{
	PemInventoryItem* pem = (PemInventoryItem*)malloc(sizeof(PemInventoryItem));
	if(pem)
	{
		pem->cert = NULL;
		pem->thumbprint_string = NULL;
		pem->has_private_key = false;
	}
	else
	{
		log_error("%s::%s(%d) : Out of memory",
			__FILE__, __FUNCTION__, __LINE__);
	}
	return pem;
} /* PemInventoryItem_new */

/**
 * Allocate memory for a new PemInventoryList
 *
 * @param  - none
 * @return - success : a pointer to the memory allocated for the new list
 *         - failure : NULL
 */
static PemInventoryList* PemInventoryList_new()
{
	PemInventoryList* list = \
		(PemInventoryList*)malloc(sizeof(PemInventoryList));
	if(list)
	{
		list->item_count = 0;
		list->items = NULL;
	}
	return list;
} /* PemInventoryList_new */

/**
 * Free the PemInventoryList from memory
 *
 * @param  - [Input] : list = the PemInventoryList to free from memory
 * @return - none
 */
void PemInventoryList_free(PemInventoryList* list)
{
	if(list && list->items)	{
		for(int i = 0; list->item_count > i; i++) {
			log_trace("%s::%s(%d) : Freeing PemInventoryItem #%d",\
				__FILE__, __FUNCTION__, __LINE__, i);
			PemInventoryItem_free(list->items[i]);
		}		
		log_trace("%s::%s(%d) : Freeing PemInventoryList", \
			__FILE__, __FUNCTION__, __LINE__);
		if (list->items) free(list->items);
		if (list) free(list);
		list = NULL;
	}
	return;
} /* PemInventoryList_free */

/**
 * Add a PemInventoryItem to a PemInventoryList
 *
 * @param  - [Ouput] : list = the list to add to (NULL if the add fails)
 * @param  - [Input] : item = the item to add to the list
 * @return - success : true
 *         - failure : false
 */
static bool PemInventoryList_add(PemInventoryList* list, PemInventoryItem* item)
{
	bool bResult = false;
	if(list && item)
	{
		list->items = realloc(list->items, \
			(1 + list->item_count) * sizeof(item));
		if (list->items)
		{
			list->items[list->item_count] = item;
			list->item_count++;
			log_trace(\
			"%s::%s(%d) : Added cert with thumbprint %s to local inventory",\
				__FILE__, __FUNCTION__, __LINE__, item->thumbprint_string);
			bResult = true;
		}
		else
		{
			log_error("%s::%s(%d) : Out of memory",
				__FILE__, __FUNCTION__, __LINE__);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Either the list or item was NULL",
			__FILE__, __FUNCTION__, __LINE__);
	}
	return bResult;
} /* PemInventoryList_add */

/** 
 * NOTE: GLOBAL FUNCTION
 *
 * Free a PemInventory item from memory
 *
 * @param  - [Input] : pem = the pem Item to free
 * @return - none
 */
void PemInventoryItem_free(PemInventoryItem* pem)
{
	if(pem)
	{
		if (pem->cert) {
			log_trace("%s::%s(%d) : Freeing pem inventory item cert",\
				__FILE__, __FUNCTION__, __LINE__);
			 free(pem->cert);
			 pem->cert = NULL;
		}
		if (pem->thumbprint_string) {
			log_trace("%s::%s(%d) : Freeing pem inventory item thumbprint",\
				__FILE__, __FUNCTION__, __LINE__);
			free(pem->thumbprint_string);
			pem->thumbprint_string = NULL;
		}		
		free(pem);
	}
	return;
} /* PemInventoryItem_free */

/**
 * Populate a PemInventoryItem with a certificate and thumbnail. 
 * Default the has_private_key bit to false.
 *
 * @param  - [Output] : pem = the PemInventoryItem to populate
 * @param  - [Input]  : cert = the Cert to populate into the pem item
 * @return - success : true
 *         - failure : false
 */
static bool PemInventoryItem_populate(PemInventoryItem* pem, X509* cert)
{
	bool bResult = false;
	char* thumb = NULL;
	unsigned char* certContent = NULL;
	int contLen = 0;

	if (pem && cert)
	{
		thumb = compute_thumbprint(cert);
		log_verbose("%s::%s(%d) : Thumbprint: %s", \
			__FILE__, __FUNCTION__, __LINE__, thumb);
		contLen = i2d_X509(cert, &certContent);

		if (0 < contLen)
		{
			/* Store the b64 encoded DER version of the pem in here */
			pem->cert = base64_encode(certContent, contLen, false, NULL);
			pem->thumbprint_string = strdup(thumb);
			pem->has_private_key = false;
			bResult = true;
		}
		else
		{
			log_error("%s::%s:(%d) : Error decoding cert i2d_X509\n%s",
				__FILE__, __FUNCTION__, __LINE__, certContent);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Bad pem, cert, or certString",
			__FILE__, __FUNCTION__, __LINE__);
	}
	if ( thumb )
	{
		free(thumb);
	}
	if ( certContent )
	{
		OPENSSL_free(certContent);
	}
	return bResult;
} /* PemInventoryItem_populate */

/**
 * Compare the public key stored in the certificate with a private key and
 * determine if they are a matched pair.
 *
 * @param  - [Input] : cert = An x509 certificate (contining a pub key by defn)
 * @param  - [Input] : key = a keypair structure containing a private key
 * @return - true = public key is the pair for the private key 
 *		   - false = they key types or common factors are not equal
 */
static bool is_cert_key_match(X509* cert, EVP_PKEY* key)
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
		certPubKey = X509_get_pubkey(cert);		// Get the public keypair from cert
		certBaseId = EVP_PKEY_base_id(certPubKey); // Get the type of the public keypair
		keyBaseId = EVP_PKEY_base_id(key);  // Get the type of the keypair passed

		if(certBaseId == keyBaseId) // if the key types match
		{
			switch(certBaseId)
			{
			case EVP_PKEY_RSA:
				// get the private key of the pair
				rsaPriv = EVP_PKEY_get1_RSA(key);		
				rsaCert = EVP_PKEY_get1_RSA(certPubKey);// get the public key of the pair
				if(rsaCert && rsaPriv)
				{
					RSA_get0_key(rsaCert, &nCert, NULL, NULL); // get RSA n (ignore d & e)
					RSA_get0_key(rsaPriv, &nPriv, NULL, NULL); // get RSA n (ignore d & e)
					/* Compare the n's which should be equal in the priv and public key */
					ret = (BN_cmp(nCert, nPriv) == 0); 
				}
				RSA_free(rsaPriv);
				RSA_free(rsaCert);
				break;
			case EVP_PKEY_EC:
				// get the private key of the pair
				ecPriv = EVP_PKEY_get1_EC_KEY(key);		
				// get the public key of the pair	
				ecCert = EVP_PKEY_get1_EC_KEY(certPubKey);  
				if(ecPriv && ecCert)
				{
					/* get EC_POINT public key */
					privPoint = EC_KEY_get0_public_key(ecPriv); 
					privGroup = EC_KEY_get0_group(ecPriv); // get EC_GROUP 
					/* 
					 * Convert the ECC_POINT using the EC_GROUP's curve into a 
					 * Hex representation:
					 *
					 * An EC_GROUP structure is used to represent the definition 
					 * 	of an elliptic curve.
					 * An EC_POINT represents a point on the EC_GROUP's curve.
					 * 
					 * EC_POINT can be converted to and from various external 
					 * representations. The octet form is the binary encoding of
					 * the ECPoint structure (as defined in RFC5480 and used in 
					 * certificates and TLS records): only the content octets 
					 * are present, the OCTET STRING tag and length are not 
					 * included. 
					 * BIGNUM form is the octet form interpreted as a big endian 
					 * integer converted to a BIGNUM structure. 
					 * Hexadecimal form is the octet form converted to a NULL 
					 * terminated character string where each character is one 
					 * of the printable values 0-9 or A-F (or a-f).
					 *
					 * For POINT_CONVERSION_UNCOMPRESSED the point is encoded as
					 * an octet signifying the UNCOMPRESSED form has been used 
					 * followed by the octets for x, followed by the octets 
					 * for y.
					 *
					 */
					privPubBytes = EC_POINT_point2hex(privGroup, privPoint, \
						POINT_CONVERSION_UNCOMPRESSED, NULL);
					/* get EC_POINT public key */
					certPoint = EC_KEY_get0_public_key(ecCert); 
					certGroup = EC_KEY_get0_group(ecCert); // get EC_GROUP 
					certPubBytes = EC_POINT_point2hex(certGroup, certPoint, \
						POINT_CONVERSION_UNCOMPRESSED, NULL);

					/* Now that we have the point on the curve compare them, 
					 * they should be equal if the keys match */
					ret = (strcmp(privPubBytes, certPubBytes) == 0);

					OPENSSL_free(privPubBytes);
					OPENSSL_free(certPubBytes);
				}
				EC_KEY_free(ecCert);
				EC_KEY_free(ecPriv);
				break;
			default:
				log_error("%s::%s(%d) : Unknown algorithm: %d", 
					__FILE__, __FUNCTION__, __LINE__, certBaseId);
				break;
			}
		}

		EVP_PKEY_free(certPubKey);
	}

	return ret;
} /* is_cert_key_match */

/**
 * Look through the subject to decode the subject's value
 * e.g., if subject is CN=12345,O=Keyfactor then this function is passed
 * the portion after the equals sign.  The first time it is called, it will
 * receive 12345,O=Keyfactor.  It will return 12345
 * The next time it is called it will be passed Keyfactor & return Keyfactor.
 *
 * If an ascii escaped string is encountered it parses the value accordingly.
 * e.g., if domain\\user is sent, the subject is converted to domain\user
 *
 * If an ascii escaped hex value is encontered it parses the value accordingly
 * e.g., if \\3F  then the value ? is returned.
 *
 * @param  - [Input] : subject = a portion of the full subject after a key
 *                               i.e., it starts with a value for the key
 * @param  - [Ouput] : buf = string containing the value 
 * @return - success : how far into the subject string we found a subject 
 *					   separator
 *         - failure : -1
 */
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
} /* read_subject_value */

/* ================================= ### ================================ */
/**
 * Return a pointer to the first non-space element in the string.  The string
 * MAY be modified by this function by adding a NULL ('\0') terminator 
 * inside the string.  This null terminator may be before the null terminator
 * of the original string.
 *
 * for example, both of these may happen:
 *   string = " I have spaces before and after me      "\0
 * Here is what happens this function does:
 * 
 * sring = " I have spaces before and after me      "\0
 *           ^                                ^ is replaced with \0
 *           |
 *            - beg (returned value)
 *
 * NOTE: This doesn't ADD any dynamically allocated memory
 *       so you MUST NOT DEALLOCATE the returned value.  The returned
 *       value is at a minimum, a subset pointing inside the original data
 *       structure.  At a maximum it is the same pointer.
 *
 * @param  - [Input/Output] : string = the string to parse
 * @param  - [Input] : the length of the string
 * @return - none
 */
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

/**
 * Populate the correct subject of the certificate request
 *
 * @param  - [Input/Output] nm = The name to modify
 * @param  - [Input] key = the subject key to modify
 * @param  - [Input] value = the value to populate
 * @return - none
 */
static void populate_subject(X509_NAME* nm, char* key, char* value)
{
	if ( 0 == (strcasecmp(key,"C")) ) {
		log_trace("%s::%s(%d) : Setting Country to %s", \
			__FILE__, __FUNCTION__, __LINE__, value);
		X509_NAME_add_entry_by_txt(nm, "C", MBSTRING_UTF8, value, -1, -1, 0);
	} else if ( 0 == (strcasecmp(key,"S")) ) {
		log_trace("%s::%s(%d) : Setting State to %s", \
			__FILE__, __FUNCTION__, __LINE__, value);
		X509_NAME_add_entry_by_txt(nm, "S", MBSTRING_UTF8, value, -1, -1, 0);
	} else if ( 0 == (strcasecmp(key,"L")) ) {
		log_trace("%s::%s(%d) : Setting locality to %s", \
			__FILE__, __FUNCTION__, __LINE__, value);
		X509_NAME_add_entry_by_txt(nm, "L", MBSTRING_UTF8, value, -1, -1, 0);
	} else if ( 0 == (strcasecmp(key,"O")) ) {
		log_trace("%s::%s(%d) : Setting Organization to %s", \
			__FILE__, __FUNCTION__, __LINE__, value);
		X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_UTF8, value, -1, -1, 0);
	} else if ( 0 == (strcasecmp(key,"OU")) ) {
		log_trace("%s::%s(%d) : Setting Organizational Unit to %s", \
			__FILE__, __FUNCTION__, __LINE__, value);
		X509_NAME_add_entry_by_txt(nm, "OU", MBSTRING_UTF8, value, -1, -1, 0);
	} else if ( 0 == (strcasecmp(key,"CN")) ) {
		log_trace("%s::%s(%d) : Setting Common Name to %s", \
			__FILE__, __FUNCTION__, __LINE__, value);
		X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_UTF8, value, -1, -1, 0);
	} else {
		log_info("%s::%s(%d) : key = %s is unknown, skipping", \
			__FILE__, __FUNCTION__, __LINE__, key);
	}
	return;
} /* populate_subject */

/**
 * Take an ASCII subject and convert it into an openSSL
 * X509_NAME structure
 *
 * @param  - [Input] : subject = ascii subject string
 * @return - success = a ptr to a filled out X509_NAME subject
 *         - failure = NULL
 */
static X509_NAME* parse_subject(const char* subject)
{
	X509_NAME* subjName = NULL;
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

	subjName = X509_NAME_new();
	if(NULL == subjName) {
		log_error("%s::%s(%d) : Out of memory", \
			__FILE__, __FUNCTION__, __LINE__);
		goto cleanup;
	}

	localSubjectPtr = strdup(subject);
	curPtr = localSubjectPtr;
	log_debug("%s::%s(%d) : Subject \"%s\" is %ld characters long", \
		__FILE__, __FUNCTION__, __LINE__, curPtr, strlen(curPtr));

	log_trace("%s::%s(%d) : hasError = %s endOfSubject = %s",\
		__FILE__, __FUNCTION__, __LINE__, \
		hasError ? "true" : "false", endOfSubject ? "true" : "false");

	while(!hasError && !endOfSubject)
	{
		/* Get the Key */
		keyLen = strcspn(curPtr, "=");
		allocateMemorySize = (int)keyLen + 1;
		keyBytes = calloc(allocateMemorySize,sizeof(*keyBytes));
		if (NULL == keyBytes)
		{
			log_error("%s::%s(%d) : Out of memory", \
				__FILE__, __FUNCTION__, __LINE__);
			goto cleanup;
		}		
		strncpy(keyBytes, curPtr, (int)keyLen);
		
		strippedKey = strip_blanks(keyBytes, keyLen);   
		log_verbose("%s::%s(%d) : Key: \"%s\" is %ld characters long", \
			__FILE__, __FUNCTION__, __LINE__, strippedKey, strlen(strippedKey));

		/* Now get the value for the key */
		curPtr += (keyLen+1); // Advance past the equals character
		if( *curPtr != '\0' )
		{
			log_trace("%s::%s(%d) : localSubject is now \"%s\"",\
				__FILE__,__FUNCTION__,__LINE__,curPtr);
			valLen = read_subject_value(curPtr, NULL);
			if(valLen != 0)
			{
				allocateMemorySize = (int)valLen + 1;
				valBytes = calloc(allocateMemorySize,sizeof(*valBytes));
				if (NULL == valBytes)
				{
					log_error("%s::%s(%d) : Out of memory",\
						 __FILE__, __FUNCTION__, __LINE__);
					goto cleanup;
				}			
				read_subject_value(curPtr, valBytes);
				curPtr += (valLen+1); // advance past the comma
				strippedVal = strip_blanks(valBytes, strlen(valBytes));
			   log_verbose("%s::%s(%d) : Value: \"%s\" is %ld characters long",\
					__FILE__, __FUNCTION__, __LINE__, strippedVal, \
					strlen(strippedVal));

				populate_subject(subjName, strippedKey, strippedVal);

				/* Don't try to advance if we just advanced past the 
				 * null-terminator */
				if( *(curPtr-1) != '\0' ) 
				{
					if ( *curPtr != '\0' )
					{
						/* Whitespace between RDNs should be ignored */
						log_trace("%s::%s(%d) : Stripping leading whitespace "
							      "from \"%s\"", __FILE__, __FUNCTION__, \
							      __LINE__, curPtr);
						curPtr = strip_blanks(curPtr, strlen(curPtr));
					}
					else
					{
						log_trace("%s::%s(%d) : Reached end of subject string",\
						__FILE__, __FUNCTION__, __LINE__);
						endOfSubject = true;
					}
				}
				else
				{
					log_trace("%s::%s(%d) : Reached end of subject string", \
						__FILE__, __FUNCTION__, __LINE__);
					endOfSubject = true;
				}
			}
			else
			{
				log_error(\
					"%s::%s(%d) : Input string '%s' is not a valid X500 name", \
					__FILE__, __FUNCTION__, __LINE__, localSubjectPtr);
				hasError = true;
			}
		}
		else
		{
			log_error(\
				"%s::%s(%d) : Input string '%s' is not a valid X500 name", \
				__FILE__, __FUNCTION__, __LINE__, localSubjectPtr);
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
		log_trace("%s::%s(%d) : hasError = %s endOfSubject = %s",\
			__FILE__, __FUNCTION__, __LINE__, \
			hasError ? "true" : "false", endOfSubject ? "true" : "false");
	}

cleanup:
	if (localSubjectPtr)
	{
		log_trace("%s::%s(%d) : Freeing localSubjectPtr", \
			__FILE__, __FUNCTION__, __LINE__);
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

	if (!hasError) {
		return subjName;	
	}
	else {
		return NULL;
	}
	
} /* parse_subject */

/* ============================== ### ===================================== */

/**
 * Convert the base 64 encoded cert into a BIO structure to use in saving
 *
 * @param  - [Output] : the bio to write the cert into
 * @return - success : 0
 *         - failure : error code
 */
static unsigned long write_cert_bio(BIO* bio, const char* b64cert)
{
	unsigned long errNum = 0;
	size_t outLen;
	X509* certStruct = NULL;
	bool result = false;
	char *certBytePtr = NULL;

	certBytePtr = base64_decode(b64cert, -1, &outLen);
	const unsigned char** tempPtrPtr = (const unsigned char**)&(certBytePtr);

	// Long way around, but PEM_write was segfaulting
	if (d2i_X509(&certStruct, tempPtrPtr, outLen)) {
		if (PEM_write_bio_X509(bio, certStruct)) {
			result = true;
		}
	}

	if(result)	{
		log_verbose("%s::%s(%d) : Cert written to BIO", 
			__FILE__, __FUNCTION__, __LINE__);
	}
	else {
		errNum = ERR_peek_last_error();
	}

	if ( certStruct ) {
		X509_free(certStruct);
	}

	/* OpenSSL corrupts certBytePtr.  If we attempt to free it, it causes a */
	/* core dump.  Therefore, we must deal with this memory leak of around */
	/* 1k */
	
	if (certBytePtr) {
		certBytePtr -= outLen;
		free(certBytePtr);
	}
	return errNum;
}

/**
 * Convert a private key into a BIO structure to use in saving
 *
 * @param  - [Output] : the bio to write the key into
 * @param  - [Input] : A password (or NULL or "" if none) to encode the bio
 * @return - success : 0
 *         - failure : error code
 */
static unsigned long write_key_bio(BIO* bio, const char* password, \
	EVP_PKEY* key)
{
	unsigned long errNum = 0;

	const char* tmpPass = \
		(password && strcmp(password, "") != 0) ? password : NULL;

	const EVP_CIPHER* tmpCiph = \
		(password && strcmp(password, "") != 0) ? EVP_aes_256_cbc() : NULL;

	if ( NULL == key ) // We want to save the keyPair since no key was passed
	{
		if(PEM_write_bio_PKCS8PrivateKey(bio, keyPair,
				tmpCiph, NULL, 0, 0, (char*)tmpPass))
		{
			log_verbose("%s::%s(%d) : Key written to BIO", 
				__FILE__, __FUNCTION__, __LINE__);
		}
		else
		{
			errNum = ERR_peek_last_error();
		}
	}
	else
	{
		if(PEM_write_bio_PKCS8PrivateKey(bio, key,
				tmpCiph, NULL, 0, 0, (char*)tmpPass))
		{
			log_verbose("%s::%s(%d) : Key written to BIO", 
				__FILE__, __FUNCTION__, __LINE__);
		}
		else
		{
			errNum = ERR_peek_last_error();
		}
	}
	return errNum;
} /* write_key_bio */

/**
 * Read a list of keys from a keystore
 *
 * @param  - [Input] path = location of the keystore
 * @param  - [Input] password = password of the keys in the keystore
 * @param  - [Ouput] keyList = the array of keys
 *                   NOTE: This must be freed by the calling function
 * @return - success = 0
 *           failure = Any other integer
 */
static int get_key_inventory(const char* path, const char* password, \
	PrivKeyList** keyList)
{
	int ret = 0;
	FILE* fp = NULL;
	char* name = NULL;
	char* header = NULL;
	unsigned char* data = NULL;
	char errBuf[256];
	/* Don't lose the pointer so it can be freed */
	const unsigned char* tempData = data; 
	long length = 0;
	/* Create an array to store keys into */
	*keyList = PrivKeyList_new();
	if ( NULL == *keyList )
	{
		log_error("%s::%s(%d) : Out of memory", \
			__FILE__, __FUNCTION__, __LINE__);
		return -1;
	}

	/* Open the filestore */
	fp = fopen(path, "r");
	if(!fp)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s::%s(%d) : Unable to open store at %s: %s", \
			__FILE__, __FUNCTION__, __LINE__, path, errStr);
		free(errStr);
		goto cleanup;
	}

	/* Loop through the filestore adding keys to the keyList */
	EVP_PKEY* key = NULL;
	while(PEM_read(fp, &name, &header, &data, &length))
	{
		key = NULL;
		tempData = data;
	
		if( (strcmp(name, "CERTIFICATE") == 0) )
		{
			log_error(\
	"%s::%s(%d) WARNING: Certificate found in keystore -- skipping", \
					__FILE__, __FUNCTION__, __LINE__);
		}
		else if( (strcmp(name, "PRIVATE KEY") == 0) && \
			     (d2i_AutoPrivateKey(&key, &tempData, length)) )
		{
			log_verbose("%s::%s(%d) : Entry is a private key", \
				__FILE__, __FUNCTION__, __LINE__);
			PrivKeyList_add(*keyList, key);
		}
		else if(strcmp(name, "ENCRYPTED PRIVATE KEY") == 0)
		{
			BIO* keyBio = BIO_new_mem_buf(data, length);
			if(d2i_PKCS8PrivateKey_bio(keyBio, &key, NULL, \
				(char*)(password ? password : "")))
			{
				log_verbose("%s::%s(%d) : Entry is an encrypted private key", \
					__FILE__, __FUNCTION__, __LINE__);
				PrivKeyList_add(*keyList, key);
			}
			else
			{
				unsigned long errNum = ERR_peek_last_error();
				ERR_error_string(errNum, errBuf);
				log_error("%s::%s(%d) : Unable to decrypt private key: %s", \
					__FILE__, __FUNCTION__, __LINE__, errBuf);
			}
			BIO_free(keyBio);
		}
		else
		{
			log_verbose("%s::%s(%d) : Entry is not a key, and will be skipped",\
				__FILE__, __FUNCTION__, __LINE__);
		}

		OPENSSL_free(name);
		OPENSSL_free(header);
		OPENSSL_free(data);
		length = 0;
	}

cleanup:
	if ( fp )
	{
		fclose(fp);
	}
	return ret;
} /* get_key_inventory */

/**
 * Read the inventory of certificates and keys located at path.
 * This function always populates PemInventoryList.  However, it can also 
 * return the PEMx509List and the PrivKeyList.  The latter two assist in
 * key management functions.
 *
 * @param  - [Input] : path = the store location
 * @param  - [Input] : password = the password for private keys
 * @param  - [Output]: pPemList = the PemInventory
 * @param  - [Output]: (optional) pPemArray = the X509 cert array which is
 *                     mapped 1:1 with the pPemList. The latter only contains
 *                     the ASCII representation of the cert.  
 * @param  - [Input] : returnX509array =
 *                         true if you want the array passed back via pPemArray
 *                           NOTE: This means the calling function must dispose
 *                                 of the allocated memory
 *                         false disposes of the array here
 * @param  - [Output]: (optional) pKeyArray = the list of private keys in the 
 *											  store
 * @param  - [Input] : returnKeyArray = 
 *                         true if you want the array passed back via pKeyArray
 *                           NOTE: This means the calling function must dispose
 *                                 of the allocated memory
 *                         false disposes of the array here
 * @return - success = 0
 *         - failure = any other integer
 */
static int get_inventory(const char* path, const char* password, \
	PemInventoryList** pPemList, PEMx509List** pPemArray, \
	const bool returnX509array, PrivKeyList** pKeyArray, \
	const bool returnKeyArray)
{
	int ret = 0; 
	char* name = NULL;
	char* header = NULL;
	unsigned char* data = NULL;
	long length = 0;
	char errBuf[120];

	/* Open the filestore */
	log_trace("%s::%s(%d) : Opening %s", \
		__FILE__, __FUNCTION__, __LINE__, path);
	FILE* fp = fopen(path, "r");
	if(!fp)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s::%s(%d) : Unable to open store at %s: %s", \
			__FILE__, __FUNCTION__, __LINE__, path, errStr);
		free(errStr);
		return ret;
	}

	/* Create the inventory list to share with the agent */
	*pPemList = PemInventoryList_new();
	/* Now create a 'mirror' array where each index into the 
	 * PemInventoryList->items array is equal to the index into this array.
	 * That is:
	 * PemInventoryList->items[x] = PEMx509List->certs[x] for all values of x
	 */
	PEMx509List* x509array = PEMx509List_new(); 
	/* Also create an array to store keys into */
	PrivKeyList* keyList = PrivKeyList_new();

	if ( (NULL == (*pPemList)) || \
		 (NULL == x509array) || \
		 (NULL == keyList) )
	{
		log_error("%s::%s(%d) : Out of memory",
			__FILE__, __FUNCTION__, __LINE__);
		ret = -1;
		goto cleanup;
	}

	PemInventoryItem* pem = NULL;
	X509* cert = NULL;
	EVP_PKEY* key = NULL;
	/* Don't lose the pointer so it can be freed */
	const unsigned char* tempData = data; 
	while(PEM_read(fp, &name, &header, &data, &length))
	{
		pem = NULL;
		cert = NULL;
		key = NULL;
		tempData = data;

		log_trace("%s::%s(%d) : found %s", \
			__FILE__, __FUNCTION__, __LINE__, name);
		if( (strcmp(name, "CERTIFICATE") == 0) && \
			(d2i_X509(&cert, &tempData, length)) )
		{
			/* Then, store it into the inventory list */
			pem = PemInventoryItem_new();
			if ( PemInventoryItem_populate(pem, cert) )
			{
				PemInventoryList_add(*pPemList, pem);
				PEMx509List_add(x509array, cert);
			}
			else
			{
				log_error(\
					"%s::%s(%d) Not adding cert to list of certs in store",\
					__FILE__, __FUNCTION__, __LINE__);
			}		
		}
		else if( (strcmp(name, "PRIVATE KEY") == 0) && \
			     (d2i_AutoPrivateKey(&key, &tempData, length)) )
		{
			log_verbose("%s::%s(%d) : Entry is a private key", \
				__FILE__, __FUNCTION__, __LINE__);
			PrivKeyList_add(keyList, key);
		}
		else if(strcmp(name, "ENCRYPTED PRIVATE KEY") == 0)
		{
			BIO* keyBio = BIO_new_mem_buf(data, length);
			if(d2i_PKCS8PrivateKey_bio(keyBio, &key, NULL, \
				(char*)(password ? password : "")))
			{
				log_verbose("%s::%s(%d) : Entry is an encrypted private key", \
					__FILE__, __FUNCTION__, __LINE__);
				PrivKeyList_add(keyList, key);
			}
			else
			{
				unsigned long errNum = ERR_peek_last_error();
				ERR_error_string(errNum, errBuf);
				log_error("%s::%s(%d) : Unable to decrypt private key: %s", \
					__FILE__, __FUNCTION__, __LINE__, errBuf);
			}
			BIO_free(keyBio);
		}
		else
		{
			log_verbose(\
				"%s::%s(%d) : Entry is not a certificate, and will be skipped",\
				__FILE__, __FUNCTION__, __LINE__);
		}

		OPENSSL_free(name);
		OPENSSL_free(header);
		OPENSSL_free(data);
		length = 0;
	}

	log_verbose("%s::%s(%d) : %d items in PEM list", \
		__FILE__, __FUNCTION__, __LINE__, (*pPemList)->item_count);
	log_verbose("%s::%s(%d) : Checking for matching private keys", \
		__FILE__, __FUNCTION__, __LINE__);
	for(int i = 0; i < (*pPemList)->item_count; ++i)
	{
		log_verbose("%s::%s(%d) : Thumbprint: %s", \
			__FILE__, __FUNCTION__, __LINE__, \
			(*pPemList)->items[i]->thumbprint_string);

		for(int k = 0; k < keyList->key_count; ++k)
		{
			/* Use the x509array to grab the X509 certificate associated with
			 * the (*pPemList)->items[i]->cert.  Since *pPemList has the cert
			 * stored as an ASCII encoded string instead of an X509 cert.
			 *
			 * Remember, the x509array is a 1:1 match with the items array
			 * in the *pPemList.
			 */
			if(is_cert_key_match(x509array->certs[i], keyList->keys[k]))
			{
				log_verbose("%s::%s(%d) : Found matching cert and private key",\
					 __FILE__, __FUNCTION__, __LINE__);
				(*pPemList)->items[i]->has_private_key = true;
			}
		}
	}

cleanup:
	/* Cleanup things */
	if ( x509array )
	{
		if ( !returnX509array || (0 != ret) )
		{
			log_trace("%s::%s(%d) : Freeing x509array",\
				__FILE__, __FUNCTION__, __LINE__);
			// We no longer need the X509 cert versions
			PEMx509List_free(x509array); 
		}
		else
		{
			(*pPemArray) = x509array; // Return the array
		}
		x509array = NULL;
	}
	if ( *pPemList && (0 != ret) )
	{
		log_trace("%s::%s(%d) : Freeing *pPemList",\
				__FILE__, __FUNCTION__, __LINE__);
		PemInventoryList_free(*pPemList);
		*pPemList = NULL;
	}
	if ( keyList )
	{
		if ( !returnKeyArray )
		{
			log_trace("%s::%s(%d) : Freeing keyList",\
				__FILE__, __FUNCTION__, __LINE__);
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
		log_trace("%s::%s(%d) : Closing fp",\
				__FILE__, __FUNCTION__, __LINE__);
		fclose(fp);
		fp = NULL;
	}
	return ret;
} /* get_inventory */

/**
 * Append to a store a new cert
 *
 * @param  - [Input] : storePath = the stores location
 * @param  - [Input] : cert = the X509 certificate
 * @return - success = 0;
 *           failure = Any other integer
 */
static int store_append_cert(const char* storePath, X509* cert)
{
	FILE* fpAdd = fopen(storePath, "a");
	int ret = 0;
	if(!fpAdd)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s::%s(%d) : Unable to open store at %s: %s", \
			__FILE__, __FUNCTION__, __LINE__, storePath, errStr);
	}
	else
	{
		if(!PEM_write_X509(fpAdd, cert))
		{
			char errBuf[120];
			unsigned long errNum = ERR_peek_last_error();
			ERR_error_string(errNum, errBuf);
			log_error("%s::%s(%d) : Unable to write certificate to store: %s", \
				__FILE__, __FUNCTION__, __LINE__, errBuf);
			ret = -1;
		}

		if(fpAdd) fclose(fpAdd);
	}
	return ret;
} /* store_append_cert */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * Take the ASCII entropy sent by the platform & seed the RNG for openSSL
 *
 * @param  - [Input] : b64entropy is the string to use to seed the RNG
 * @return - success : 0
 *         - failure : -1
 */
int ssl_seed_rng(const char* b64entropy)
{
	size_t outLen;
	unsigned char* entBytes = NULL;
	if(b64entropy)
	{
		/* convert the entropy to binary */
		entBytes = base64_decode(b64entropy, -1, &outLen);
		RAND_seed(entBytes, outLen);
		if ( NULL != entBytes ) 
		{ 
			free(entBytes); 
		}
		return 0;
	}
	else
	{
		return -1;
	}
} /* seed_rng */

/**
 * Generate an RSA keypair & store it into tempKeypair
 *
 * @param  - [Input] : keySize = the size of the RSA key
 * @return - success : true
 *         - failure : false
 */
bool ssl_generate_rsa_keypair(int keySize)
{
	char errBuf[120];
	BIGNUM* exp = NULL;
 	RSA* newRsa = NULL;
	unsigned long errNum = 0;
	int setWordResult = 0;
	bool bResult = false;

	exp = BN_new();

	if (!exp)
    {
        log_error(\
        	"%s::%s(%d) : out of memory when creating exponent in genkey_rsa",
											__FILE__, __FUNCTION__, __LINE__);
        return NULL;
    }

	setWordResult = BN_set_word(exp, RSA_DEFAULT_EXP);

	if ( 0 == setWordResult )
	{
		log_error("%s::%s(%d) : Failed assigning exp for RSA keygen",
			__FILE__, __FUNCTION__, __LINE__);
		return NULL;
	}

	newRsa = RSA_new();

	if (!newRsa)
    {
        log_error(\
        "%s::%s(%d) : out of memory when creating RSA variable in genkey_rsa",
											__FILE__, __FUNCTION__, __LINE__);
        if ( exp ) 
        { 
        	BN_free(exp); 
        }
        return NULL;
    }
	/***************************************************************************
	 * Create keypair using standard openSSL engine
	 **************************************************************************/
	if(RSA_generate_key_ex(newRsa, keySize, exp, NULL))	{
		if ( NULL != keyPair ) {
			EVP_PKEY_free(keyPair);
			keyPair = NULL;
		}
		keyPair = EVP_PKEY_new();

		if (!keyPair) {
			log_error("%s::%s(%d) : Out of memory allocating keypair", \
				__FILE__, __FUNCTION__, __LINE__);
			goto exit;
		}

		EVP_PKEY_assign_RSA(keyPair, newRsa);
		bResult = true;
	}
	else
	{
		errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error("%s::%s(%d) : Unable to generate key pair: %s",
					__FILE__, __FUNCTION__, __LINE__, errBuf);
	}

exit:
	if ( exp ) BN_free(exp); 
	if ( newRsa ) OPENSSL_free(newRsa); 
	return bResult;
} /* generate_rsa_keypair */

/**
 * Generate an ECC keypair & store it into tempKeypair
 *
 * @param  - [Input] : keySize = the size of the ECC key
 * @return - success : true
 *         - failure : false
 */
bool ssl_generate_ecc_keypair(int keySize)
{
	char errBuf[120];
	int eccNid = -1;
	EC_KEY* newEcc = NULL;
	unsigned long errNum = 0;
	bool bResult = false;

	switch(keySize)
		{
		case 256:
			log_trace("%s::%s(%d) : Setting ECC curve to NID_X9_62_prime256v1",
				__FILE__, __FUNCTION__, __LINE__);
			eccNid = NID_X9_62_prime256v1;
			break;
		case 384:
			log_trace("%s::%s(%d) : Setting ECC curve to NID_secp384r1",
				__FILE__, __FUNCTION__, __LINE__);
			eccNid = NID_secp384r1;
			break;
		case 521:
			log_trace("%s::%s(%d) : Setting ECC curve to NID_secp521r1",
				__FILE__, __FUNCTION__, __LINE__);
			eccNid = NID_secp521r1;
			break;
		default:
		log_error(\
	"%s::%s(%d) : Invalid ECC key length: %d. Falling back to default curve",
						__FILE__, __FUNCTION__, __LINE__, keySize);
			eccNid = NID_X9_62_prime256v1;
			break;
		}

		/***********************************************************************
		 * Create keypair using standard openSSL engine
		 **********************************************************************/

		newEcc = EC_KEY_new_by_curve_name(eccNid);
		EC_KEY_set_asn1_flag(newEcc, OPENSSL_EC_NAMED_CURVE);
		if(EC_KEY_generate_key(newEcc))
		{
			if( NULL != keyPair )
			{
				EVP_PKEY_free(keyPair);
				keyPair = NULL;
			}
			keyPair = EVP_PKEY_new();
			
			if(0 == EVP_PKEY_assign_EC_KEY(keyPair, newEcc))
			{
				log_error("%s::%s(%d) : Error assigning keyPair", 
					__FILE__, __FUNCTION__, __LINE__);
				return NULL;
			}
			else
			{
				log_trace("%s::%s(%d) : Successfully assigned ECC keypair",
					__FILE__, __FUNCTION__, __LINE__);
				bResult = true;
			}
		}
		else
		{
			errNum = ERR_peek_last_error();
			ERR_error_string(errNum, errBuf);
			log_error("%s::%s(%d) : Unable to generate key pair: %s",
					__FILE__, __FUNCTION__, __LINE__, errBuf);
		}
		
	return bResult;
} /* generate_ecc_keypair */

/**
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
char* ssl_generate_csr(const char* asciiSubject, size_t* csrLen, \
	char** pMessage)
{
	X509_REQ* req = NULL;
	X509_NAME* subject = NULL;
	unsigned char* reqBytes = NULL;
	char* csrString = NULL;
	int result = SSL_SUCCESS;
	char errBuf[120];
	int errNum = 0;
	
	/**************************************************************************
	 * 1.) Set up the CSR as a new x509 request by creating a blank request
	 *     then adding in the public key, setting the subject, and signing
	 *     it with the private key.
	 ************************************************************************/
	log_verbose("%s::%s(%d) : Setting up a CSR", \
		__FILE__, __FUNCTION__, __LINE__);
	req = X509_REQ_new();	// Ask for the new structure
	if ( NULL == req )
	{
		log_error("%s::%s(%d) : Out of memory",
			__FILE__, __FUNCTION__, __LINE__);
		append_linef(pMessage, "%s::%s(%d) : Out of memory", \
			__FILE__, __FUNCTION__, __LINE__);
		return NULL;
	}

	result = X509_REQ_set_version(req, 1);
	if ( SSL_SUCCESS != result )
	{
		log_error("%s::%s(%d) : Failed to set REQ version",
			__FILE__, __FUNCTION__, __LINE__);
		append_linef(pMessage, "%s::%s(%d) : Failed to set REQ version", \
			__FILE__, __FUNCTION__, __LINE__);
		X509_REQ_free(req);
		return NULL;
	}

	log_trace("%s::%s(%d) : Converting subject %s into openSSL structure",
		__FILE__, __FUNCTION__, __LINE__, asciiSubject);
	subject = parse_subject(asciiSubject); // Convert ascii to X509_NAME
	/* Add the X509_NAME to the req */
	result = X509_REQ_set_subject_name(req, subject); 
	if ( SSL_SUCCESS == result )
	{
		log_trace("%s::%s(%d) : Adding the public key to the CSR",
			__FILE__, __FUNCTION__, __LINE__);
		result = X509_REQ_set_pubkey(req, keyPair); // Add the public key
		if ( SSL_SUCCESS == result )
		{
			/* Ask for the private key to sign the CSR request */
			result = X509_REQ_sign(req, keyPair, EVP_sha256()); 
			/* wolfSSL returns WOLF_SSL_SUCCESS (defined as 1)  */
			/* or WOLF_SSL_FAILURE (defined as 0) */
			/* opoenSSL returns the size of the signature or 0 if it fails */
			if ( 0 == result )
			{
				errNum = ERR_peek_last_error();
				ERR_error_string(errNum, errBuf);
				log_error(\
					"%s::%s(%d) : CSR signing failed with code, 0x%X = %s", \
					__FILE__, __FUNCTION__, __LINE__, result, errBuf);
				append_linef(pMessage, \
					"CSR signing failed with code, 0x%X = %s", \
					result, errBuf);
				csrString = NULL;
			}
			else
			{
				log_trace("%s::%s(%d) : Successfully signed CSR",
					__FILE__, __FUNCTION__, __LINE__);
				result = SSL_SUCCESS;
			}
		}
		else
		{
			errNum = ERR_peek_last_error();
			ERR_error_string(errNum, errBuf);
			log_error(\
			"%s::%s(%d) : CSR set of public key failed with code, 0x%X = %s", 
				__FILE__, __FUNCTION__, __LINE__, result, errBuf);
			append_linef(pMessage, \
				"CSR set of public key failed with code, 0x%X = %s", \
				result, errBuf);
			csrString = NULL;
		}
	}
	else
	{
		errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error(\
			"%s::%s(%d) : CSR subject name set failed with code, 0x%X = %s", 
			__FILE__, __FUNCTION__, __LINE__, result, errBuf);
		append_linef(pMessage, \
			"CSR subject name set failed with code, 0x%X = %s", \
				result, errBuf);
		csrString = NULL;
	}

	/**************************************************************************
	 * 2.) Take the resulting DER, encode it and convert it to a
	 *     string; the result is a PEM without the BEGIN CERTIFICATE REQUEST
	 *     and END CERTIFICATE REQUEST
	 ************************************************************************/
	if( SSL_SUCCESS == result )	
	{
		log_verbose(\
"%s::%s(%d) : Encoding the CSR and converting it to a base 64 encoded string."
						, __FILE__, __FUNCTION__, __LINE__);
		reqBytes = calloc(MAX_CSR_SIZE,sizeof(*reqBytes)); 
		if ( reqBytes )
		{
			unsigned char* tempReqBytes = reqBytes;
			/* Encode the CSR request as a PKCS#10 certificate request */
			int writeLen = i2d_X509_REQ(req, &tempReqBytes);
			/* Now convert this structure to an ASCII string */
			csrString = base64_encode(reqBytes, (size_t)writeLen, false, NULL);
			*csrLen = (size_t)writeLen; // GM Specific Code
			log_trace("%s::%s(%d) : csrString=%s", \
				__FILE__, __FUNCTION__, __LINE__, csrString);
			log_trace("%s::%s(%d) : csrLen = %ld", \
				__FILE__, __FUNCTION__, __LINE__, *csrLen);
		}
		else
		{
			log_error(\
				"%s::%s(%d) : Out of memory allocating %u bytes for reqBytes",
				__FILE__, __FUNCTION__, __LINE__, MAX_CSR_SIZE);
			append_linef(pMessage, \
				"Out of memory allocating %u bytes for reqBytes",
				MAX_CSR_SIZE);
			csrString = NULL;
		}
	}

	if ( reqBytes )	free(reqBytes);
	if ( req ) X509_REQ_free(req);
	if ( subject ) X509_NAME_free(subject);
	return csrString;
} /* ssl_generate_csr */

/**
 * Save the cert and key to the locations requested 
 * Store the locally global variable keyPair to the location requested
 *
 * @param  - [Input] : storePath = the store location for the cert
 * @param  - [Input] : keyPath = the location to save the key, if NULL or blank, 
 *                               store the encoded key appended to the cert.
 * @param  - [Input] : password = the password for the private key
 * @param  - [Input] : cert = The cert in an ASCII encoded string
 * @param  - [Output]: pMessage = a string array containing any messages
 *                                we want to pass back to the calling function
 * @return - unsigned long error code
 */
unsigned long ssl_save_cert_key(const char* storePath, const char* keyPath,	\
	const char* password, const char* cert, char** pMessage)
{
	BIO* certBIO = NULL;
	BIO* keyBIO = NULL;
	unsigned long err = 0;
	char errBuf[120];

	log_verbose("%s::%s(%d) : Entering function %s", 
		__FILE__, __FUNCTION__, __LINE__, __FUNCTION__);
	err = backup_file(storePath);
	if(err != 0 && err != ENOENT)
	{
		char* errStr = strerror(err);
		log_error("%s::%s(%d) : Unable to backup store at %s: %s\n",
			__FILE__, __FUNCTION__, __LINE__, storePath, errStr);
		append_linef(pMessage, "Unable to open store at %s: %s", storePath, \
			errStr);
	}
	else
	{
		certBIO = BIO_new(BIO_s_mem());
		keyBIO = NULL;

		err = write_cert_bio(certBIO, cert);
		if(err)
		{
			ERR_error_string(err, errBuf);
			log_error("%s::%s(%d) : Unable to write certificate to BIO: %s", \
				__FILE__, __FUNCTION__, __LINE__, errBuf);
			append_linef(pMessage, "Unable to write certificate to BIO: %s", \
				errBuf);
		}
	}
	if(!err)
	{
		if(keyPath)
		{
			keyBIO = BIO_new(BIO_s_mem());
			err = write_key_bio(keyBIO, password, NULL); // save keyPair
		}
		else
		{
			err = write_key_bio(certBIO, password, NULL); // save keyPair
		}

		if(err)
		{
			ERR_error_string(err, errBuf);
			log_error("%s::%s(%d) : Unable to write key to BIO: %s", \
				__FILE__, __FUNCTION__, __LINE__, errBuf);
			append_linef(pMessage, "Unable to write key to BIO: %s", errBuf);
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
			log_error("%s::%s(%d) : Unable to write store at %s: %s",\
				__FILE__, __FUNCTION__, __LINE__, storePath, errStr);
			append_linef(pMessage, "Unable to write store at %s: %s",\
				storePath, errStr);
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
			log_error("%s::%s(%d) : Unable to write key at %s: %s", \
				__FILE__, __FUNCTION__, __LINE__, keyPath, errStr);
			append_linef(pMessage, "Unable to write key at %s: %s", \
				keyPath, errStr);
		}
	}

	if ( certBIO ) BIO_free(certBIO);
	if ( keyBIO  ) BIO_free(keyBIO);
	return err;
} /* ssl_save_cert_key */

/**
 * Read all of the certificates inside of the store at the path requested.
 * Convert each of these into a PemInventoryItem & add it into the variable
 * provided.
 *
 * @param  - [Input] : path = the path to the store (or the id of the store)
 * @param  - [Input] : password = the password of private keys in the store
 * @param  - [Ouput] : pPemList an array to hold the inventory 
 *                     (SEND IN A NULL VARIABLE - we create the list in the
 *                      wrapper)
 * @return - success : 0
 *		   - failure : the error code from opening the file or such
 */
int ssl_read_store_inventory(const char* path, const char* password, \
	PemInventoryList** pPemList)
{
	return get_inventory(path, password, pPemList, NULL, false, NULL, false);
} /* ssl_read_store_inventory */


/**
 * Create a PemInventoryItem (with has_private_key set to false) from an ASCII
 * cert.  Verify the cert is valid & compute its thumbprint. 
 *
 * NOTE: The PemInventoryItem must be freed by the calling function by
 *       invoking PemInventoryItem_free(pem);
 *
 * @param  - [Output] : pem = the variable which points to the new item
 * @param  - [Input] : certASCII = the b64 encoded NULL terminated certificate
 * @return - success : true
 *         - failure : false
 */
bool ssl_PemInventoryItem_create(struct PemInventoryItem** pem, \
	const char* certASCII)
{
	bool bResult = false;
	X509* cert = NULL;
	size_t certLen = 0;
	char* certPEM = NULL;
	/* Decode the b64 encoded certificate to create the PEM format */
	certPEM = base64_decode(certASCII, -1, &certLen);

	/* Place the PEM into a BIO structure to be decoded */
	BIO *cbio = BIO_new(BIO_s_mem());
	BIO_puts(cbio, certPEM);
	
	if (cbio && certPEM)
	{
		cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
		if ( NULL == cert )
		{
			log_error("%s::%s(%d) : This is not a valid X509 cert: \n%s", \
				__FILE__, __FUNCTION__, __LINE__, certPEM);
			goto cleanup;
		}
		/* cert now contains the X509 cert */
		if ( NULL == (*pem = PemInventoryItem_new()) )
		{
			log_error("%s::%s(%d) : Out of memory",
				__FILE__, __FUNCTION__, __LINE__);
			goto cleanup;
		}
		/* Populate the PemInventoryItem with a thumbprint */
		if ( PemInventoryItem_populate(*pem, cert) )
		{
			bResult = true;
		}
		else
		{
			log_error("%s::%s(%d) : Error populating cert",\
				__FILE__, __FUNCTION__, __LINE__);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Out of memory",
			__FILE__, __FUNCTION__, __LINE__);
	}

cleanup:
	if (certPEM) { free(certPEM); }
	if (cert) { X509_free(cert); }
	if (cbio) { BIO_free(cbio); }

	return bResult;
} /* ssl_PemInventoryItem_create */

/**
 * Append the certificate provided to the store.
 *
 * @param  - [Input] : storePath = where to find the store
 * @param  - [Input] : certASCII = the b64 encoded PEM string of the cert
 * @return - success : true
 *         - failure : false
 */
bool ssl_Store_Cert_add(const char* storePath, const char* certASCII)
{
	bool bResult = false;
	int ret = 0;
	X509* cert = NULL;
	size_t certLen;
	char* certPEM = base64_decode(certASCII, -1, &certLen);

	log_trace("%s::%s(%d) : Converting cert to X509", \
		__FILE__, __FUNCTION__, __LINE__);
	/* Place the PEM into a BIO structure to be decoded */
	BIO *cbio = BIO_new(BIO_s_mem());
	BIO_puts(cbio, certPEM);

	if (cbio && certPEM)
	{
		cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
		if ( NULL == cert )
		{
			log_error("%s::%s(%d) : This is not a valid cert:\n%s",\
				__FILE__, __FUNCTION__, __LINE__, certPEM);
			return bResult;
		}

		ret = backup_file(storePath);
		if(ret != 0 && ret != ENOENT)
		{
			char* errStr = strerror(ret);
			log_error("%s::%s(%d) : Unable to backup store at %s: %s\n", \
				__FILE__, __FUNCTION__, __LINE__, storePath, errStr);
		}
		else
		{
			ret = store_append_cert(storePath, cert);
			if ( 0 != ret )
			{
				log_error("%s::%s(%d) : Unable to append cert to store at %s", \
					__FILE__, __FUNCTION__, __LINE__, storePath);
			}
			else
			{
				bResult = true;
			}
		}
	}
	else
	{
		log_error("%s::%s(%d) : Out of memory",
			__FILE__, __FUNCTION__, __LINE__);
	}

	if ( cert ) { X509_free(cert); }
	if ( certPEM ) { free(certPEM); }
	if ( cbio )	{ BIO_free(cbio); }

	return bResult;
} /* ssl_Store_Cert_add */

/**
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
bool ssl_remove_cert_from_store(const char* storePath, const char* searchThumb,\
	const char* keyPath, const char* password)
{
	bool bResult = false;
	PemInventoryList* pemList = NULL;
	PEMx509List* pemX509Array = NULL;
	PrivKeyList* keyArray = NULL;
	// Write the modified store into memory
	BIO* bio = NULL;
	char* data = NULL;
	size_t len = 0;
	int ret = 0;

	/***************************************************************************
	 * 1.)Get the PEM inventory, X509 PEM, and list of private keys in the store
	 **************************************************************************/
	log_trace("%s::%s(%d) : Get PEM inventory",
		__FILE__, __FUNCTION__, __LINE__);
	if ( 0 != get_inventory(storePath, password, &pemList, &pemX509Array, true,\
			&keyArray, true) )
	{
		if ( pemList )
		{
			PemInventoryList_free(pemList);
			pemList = NULL;
		}
		if ( pemX509Array )
		{
			PEMx509List_free(pemX509Array);
			pemX509Array = NULL;
		}
		if ( keyArray )
		{
			PrivKeyList_free(keyArray);
			keyArray = NULL;
		}
		log_error("%s::%s(%d) : Failed to get inventory",
			__FILE__, __FUNCTION__, __LINE__);
		return bResult;
	}

	/***************************************************************************
	 * 2.) Search for the certificate inside of the store by sha1 hash
	 **************************************************************************/
	log_trace("%s::%s(%d) : Search for matching hash to remove in inventory",\
		__FILE__, __FUNCTION__, __LINE__);
	bool certFound = false;
	int i = pemList->item_count-1;
	while ( (!certFound) && \
		    (0 <= i) )
	{
		log_trace("%s::%s(%d) : thumb #%d compared", \
			__FILE__, __FUNCTION__, __LINE__, i);
		if (0 == strcasecmp(searchThumb, pemList->items[i]->thumbprint_string) )
		{
			certFound = true;
		}
		else
		{
			i--;
		}
	}
	log_verbose("%s::%s(%d) : Found cert: %s", \
			__FILE__, __FUNCTION__, __LINE__, (certFound ? "yes" : "no"));

	/**************************************************************************
	 * 3.) Update the store, but skip the cert we want to remove
	 **************************************************************************/
	if ( certFound )
	{
		/*************************
		 * 3a.) Add all the certs
		 ************************/
		log_trace("%s::%s(%d) : Writing certs to store",\
			__FILE__, __FUNCTION__, __LINE__);
		bio = BIO_new(BIO_s_mem()); // Get new memory to store the bio
		/* At this point i points to the pemList & */
		/* PEMx509List of the cert to delete */
		for (int j = 0; pemList->item_count > j; j++)
		{
			if (i != j)
			{
				ret = BIO_puts(bio, pemList->items[j]->cert);					 
				if ( 0 != ret )
				{
					log_error("%s::%s(%d) : Failed to add cert to store %s",
						__FILE__, __FUNCTION__, __LINE__, storePath);
					goto cleanup;
				}
			}
		}
		/********************************************************************
		 * 3b.) Add all the keys found but the one for the cert we don't want
		 *******************************************************************/
		/* Now, loop through all the private keys & */
		/* save them too, except the one */
		for (int k = 0; keyArray->key_count > k; k++)
		{
			if ( !is_cert_key_match(pemX509Array->certs[i], keyArray->keys[k]) )
			{
				ret = write_key_bio(bio, password, keyArray->keys[k]);
				if ( 0!= ret )
				{
					log_error("%s::%s(%d) : Failed to add key to store %s",
						__FILE__, __FUNCTION__, __LINE__, storePath);
					goto cleanup;
				}
			}
		}

		/**********************
		 * 3c.) Write to disk
		 *********************/
		data = NULL;
		len = BIO_get_mem_data(bio, &data);
		ret = replace_file(storePath, data, len, true);
		if( 0 != ret)
		{
			char* errStr = strerror(ret);
			log_error("%s::%s(%d) : Unable to write key at %s: %s", 
				__FILE__, __FUNCTION__, __LINE__, storePath, errStr);
			goto cleanup;
		}

		/*************************************************************
		 * 3d.) Optional: if a keystore was provided, remove that key 
		 *      from the keystore 
		 ************************************************************/
		if ( keyPath )
		{
			BIO_free(bio);
			free(data);
			if ( keyArray )
			{
				PrivKeyList_free(keyArray); // Free this bit of keys
			}
			/* And populate it with the keystore located at keyPath */
			ret = get_key_inventory(keyPath, password, &keyArray);
			if ( 0 != ret )
			{
				log_error("%s::%s(%d) : Error reading keystore %s",
					__FILE__, __FUNCTION__, __LINE__, keyPath);
				goto cleanup;
			}
			bio = BIO_new(BIO_s_mem()); // Get new memory to store the bio
			/* Write the keys to bio memory */
			for (int x = keyArray->key_count; 0 < x; x--)
			{
				ret = write_key_bio(bio, password, keyArray->keys[x]);
				if ( 0 != ret )
				{
					log_error("%s::%s(%d) : Failed to add key to store %s",
						__FILE__, __FUNCTION__, __LINE__, keyPath);
					goto cleanup;
				}
			}

			/******************************
			 * 3e.) Write keystore to disk
			 *****************************/
			data = NULL;
			len = BIO_get_mem_data(bio, &data);
			ret = replace_file(keyPath, data, len, true);
			if( 0 != ret)
			{
				char* errStr = strerror(ret);
				log_error("%s::%s(%d) : Unable to write key at %s: %s", 
					__FILE__, __FUNCTION__, __LINE__, keyPath, errStr);
				goto cleanup;
			}
		} /* end separate keystore */
	}
	else
	{
		log_error("%s::%s(%d) Cert not found in PEM store %s",
			__FILE__, __FUNCTION__, __LINE__, storePath);
		goto cleanup;
	}

cleanup:
	if ( pemList )
	{
		PemInventoryList_free(pemList);
		pemList = NULL;
	}
	if ( pemX509Array )
	{
		PEMx509List_free(pemX509Array);
		pemX509Array = NULL;
	}
	if ( keyArray )
	{
		PrivKeyList_free(keyArray);
		keyArray = NULL;
	}
	if ( bio )
	{
		BIO_free(bio);
		bio = NULL;
	}
	if ( 0 == ret )
	{
		bResult = true;
	}
	return bResult;
} /* ssl_remove_cert_from_store */

/**
 * Clean up all of the openSSL items that are outstanding
 *
 * @param  - none
 * @return - none
 */
void ssl_cleanup(void)
{
	log_trace("%s::%s(%d) : Cleaning up openssl", \
		__FILE__, __FUNCTION__, __LINE__);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return;
} /* ssl_cleanup */

/**
 * Initialize the platform to use openssl
 *
 * @param  - none
 * @return - none
 */
void ssl_init(void)
{
	log_trace("%s::%s(%d) : Adding openSSL algorithms", 
		__FILE__, __FUNCTION__, __LINE__);
	OpenSSL_add_all_algorithms();
	log_trace("%s::%s(%d) : Loading Crypto error strings", 
		      __FILE__, __FUNCTION__, __LINE__);
	ERR_load_crypto_strings();
	return;
} /* ssl_init */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/