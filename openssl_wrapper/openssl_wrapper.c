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

#include "../openssl_compat.h" 

#if defined(__TPM__)
	#include "../agent.h"
	#include <openssl/engine.h>
	#include <tss2/tss2_mu.h>
	#include <tss2/tss2_esys.h>
	#include <tpm2-tss-engine.h>
#endif

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/

#ifndef SSL_SUCCESS
	#define SSL_SUCCESS 1
#endif

#define RSA_DEFAULT_EXP 65537
#define MAX_CSR_SIZE 2048
#define SHA1LEN 20

static const char x509PEMHeader[30] = "-----BEGIN CERTIFICATE-----\n\0";
static const char x509PEMFooter[30] = "-----END CERTIFICATE-----\n\0";
static const int MAX_CERT_SIZE = 4096;

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/**                                                                           */
/* This structure temporarily matches a PEMInventoryItem to an X509 cert      */
/* by its location in the PEMInventoryItem List.  That is the cert at         */
/* location 0 in PEMInventoryItem is matched to the X509 cert in this list.   */
/*                                                                            */
struct PEMx509List
{
	int item_count;
	X509** certs;
};
typedef struct PEMx509List PEMx509List;

/**                                                                           */
/* This structure allows for dynamic allocation of a list of private keys     */
/* located in a store.                                                        */
/*                                                                            */
struct PrivKeyList
{
	int key_count;
	EVP_PKEY** keys;
};
typedef struct PrivKeyList PrivKeyList;

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/

/* This keypair is for temporary storage in memory.                           */
/* Once the certificate is received from the platform, this gets stored to    */
/* The file system                                                            */
EVP_PKEY* keyPair = NULL;

/* The following keys must be locally global & freed upon exiting the program */
/* If these keys are freed, then the global variable above (keyPair) becomes  */
/* corrupted.  Therefore, we must make these global variables.                */
RSA* newRsa = NULL;
EC_KEY* newEcc = NULL;


/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**                                                                           */
/*  @fn pemify                                                                */
/*                                                                            */
/*  @brief Convert a single base64 string (with no carriage returns) into     */
/*  a 64 byte wide string with carriage returns.  Prepend a supplied header   */
/*  and postpend a supplied footer.                                           */
/*                                                                            */
/*  @param - [Input/Output] pToB64 - a pointer to the base64 string to break  */
/*           into 64 byte wide rows.  NOTE: The string pointed to by this     */
/*           parameter is re-sized & the result is placed into this structure.*/
/*           That is, the original contents are destroyed.                    */
/*         - [Input] header - The PEM header to prepend                       */
/*         - [Input] footer - The PEM footer to post-pend                     */
/*  @returns true = successfull execution & the string pointed to by pToB64   */
/*                  is replaced with the new value                            */
/*           false = failure & the string pointed to by pToB64 is unchanged   */
/*                                                                            */
static bool pemify(char** pToB64, const char* header, const char* footer) {
    char result[MAX_CERT_SIZE];
    bool worked = false;
    size_t tempSize = 0;
    size_t base64Length = strlen(*pToB64);
    size_t inputArrayPtr = 0;
    size_t outputArrayPtr = 0;
    size_t lenToWrite = 64;

    /* Validate the input parameters */
    if (NULL == pToB64) {
        log_error("%s::%s(%d) : The Base64 pointer must not be null", LOG_INF);
        return false;
    }
    if (NULL == *pToB64) {
        log_error("%s::%s(%d) : The input string must not be null", LOG_INF);
        return false;
    }
    if (NULL == header) {
        log_error("%s::%s(%d) : The header string must not be null", LOG_INF);
        return false;
    }
    if (NULL == footer) {
        log_error("%s::%s(%d) : The footer string must not be null", LOG_INF);
        return false;
    }
    /* We need to be VERY careful here to not overrun these buffers! */
    /* So validate this stuff!!! */
    tempSize = strlen(header) + strlen(footer) + strlen(*pToB64);
    log_debug("%s::%s(%d) : The size of the header + footer + data leads to a string of size %lu bytes "
              "the buffer is of size %d", LOG_INF, tempSize, MAX_CERT_SIZE);
    if ((size_t)MAX_CERT_SIZE < (tempSize + 1)) {
        log_error("%s::%s(%d) : The size of the header + footer + data is too large for the buffer, which is "
                  "sized at %d bytes", LOG_INF, MAX_CERT_SIZE);
        return false;
    }

    do {
        log_trace("%s::%s(%d) : Writing to result variable PEM header = %s", LOG_INF, header);
        tempSize = strlen(header);
        memcpy(result, header,tempSize); // don't copy \0
        outputArrayPtr += tempSize;
        log_trace("%s::%s(%d) : Successfully wrote PEM header to result variable", LOG_INF);

        log_trace("%s::%s(%d) : Attempting to parse the input string:\n%s", LOG_INF, *pToB64);
        log_trace("%s::%s(%d) : The input string is %lu characters long", LOG_INF, base64Length);
        inputArrayPtr = 0;
        while (base64Length > inputArrayPtr) {
            if (base64Length < (inputArrayPtr+lenToWrite)) {
                lenToWrite = (base64Length - inputArrayPtr);
            } else {
                lenToWrite = 64; // Write 64 bytes
            }
            log_trace("%s::%s(%d) : Attempting to write %lu bytes from input array at location %lu into output "
                      "array at location %lu", LOG_INF, lenToWrite, inputArrayPtr, outputArrayPtr);
            memcpy(result+outputArrayPtr, *pToB64+inputArrayPtr, lenToWrite);
            inputArrayPtr += lenToWrite; // Increment the pointer into the input array by 64. 0,64,128,192,etc.
            outputArrayPtr += lenToWrite; // Increment the pointer into the result array
            log_trace("%s::%s(%d) : Attempting to write a carriage return into output array at location %lu",
                      LOG_INF, outputArrayPtr);
            result[outputArrayPtr] = '\n';
            outputArrayPtr++;
            result[outputArrayPtr] = '\0'; // Temporarily end this string so we can print it.
            log_debug("%s::%s(%d) : Current result is %lu long", LOG_INF, strlen(result));
        }
        worked = true;
    } while(false);

    if (worked) {
        log_trace("%s::%s(%d) : Writing to result variable PEM footer = %s", LOG_INF, header);
        tempSize = strlen(footer);
        memcpy(result+outputArrayPtr, footer,tempSize); // don't copy \0
        outputArrayPtr += tempSize;
        result[outputArrayPtr] = '\0'; // Now add the \0 explicitly
        log_trace("%s::%s(%d) : Successfully wrote PEM footer to result variable", LOG_INF);
    }

    if (worked) {
        if (*pToB64) {
            tempSize = strlen(result) + 1;
            *pToB64 = (char *)realloc(*pToB64,tempSize);
            if (NULL == *pToB64) {
                log_error("%s::%s(%d) : Out of memory in realloc", LOG_INF);
                worked = false;
            } else {
                log_trace("%s::%s(%d) : Successfully reallocated memory", LOG_INF);
                memcpy(*pToB64,result,tempSize);
                worked = true;
            }
        }
    } else {
        log_error("%s::%s(%d) : Could not PEMify the input string\n%s", LOG_INF, *pToB64);
    }

    return worked;
} /* pemify */

/**                                                                           */
/* Get the first PEM structure in a file location.  If the structure is a     */
/* certificate, then try and convert it into a x509 structure.                */
/*                                                                            */
/* @param  - filename = path and filename to read                             */
/* @return - A populated x509 structure if we are successful                  */
/*           NULL, if we are not successful                                   */
/*                                                                            */
static X509* get_single_cert(const char* filename) {
    X509* x509 = NULL;
    char* name = NULL;
    char* header = NULL;
    unsigned char* data = NULL;
    long length = 0;

    do {
        /* Open the filestore */
        log_trace("%s::%s(%d) : Opening %s", LOG_INF, filename);
        FILE* fp = fopen(filename, "r");
        if(!fp) {
            char* errStr = strerror(errno);
            log_error("%s::%s(%d) : Unable to open store at %s: %s", LOG_INF, filename, errStr);
            free(errStr);
            break;
        }

        /* read the file & attempt to convert it to a x509 certificate */
        /* Don't lose the pointer so it can be freed */
        const unsigned char* tempData = NULL;
        if (PEM_read(fp, &name, &header, &data, &length)) {
            tempData = data;
            if ( 0 == (strcmp(name, "CERTIFICATE")) ) {
                log_trace("%s::%s(%d) : Found a certificate, continuing", LOG_INF);
                if ((d2i_X509(&x509, &tempData, length))) {
                    log_debug("%s::%s(%d) : Successfully converted PEM into an x509 cert", LOG_INF);
                }
                else {
                    log_error("%s::%s(%d) : Failed to convert read certificate into an x509 cert", LOG_INF);
                    if (name) OPENSSL_free(name);
                    if (header) OPENSSL_free(header);
                    if (data) OPENSSL_free(data);
                    break;
                }
            }
            else {
                log_error("%s::%s(%d) : Error, file is not a certificate", LOG_INF);
                if (name) OPENSSL_free(name);
                if (header) OPENSSL_free(header);
                if (data) OPENSSL_free(data);
                break;
            }
            if (name) OPENSSL_free(name);
            if (header) OPENSSL_free(header);
            if (data) OPENSSL_free(data);
        }
        else {
            log_error("%s::%s(%d) : Error parsing certificate", LOG_INF);
            break;
        }
    } while(false);

    return x509;
} /* get_single_cert */

/**                                                                           */
/* Convert an ASN1 encoded time to a string like Jul 25 19:44:44 2022 GMT     */
/*                                                                            */
/* @param  - buf = A buffer to store the converted time into                  */
/*           bufLen = the maximum buffer size in bytes                        */
/*           date = the ASN1 encoded date                                     */
/* @return - true  = we were able to convert the time into a string           */
/*           false = we failed to convert the time                            */
/*                                                                            */
static bool get_datestring_ASN1(char* buf, int bufLen, const ASN1_TIME* date) {
    bool bResult = false;
    BIO *bio = BIO_new(BIO_s_mem());
    do {
        if (bio) {
            if (1 == ASN1_TIME_print(bio, date)) {
                int written = BIO_read(bio, buf, bufLen - 1);
                if (0 < written) {
                    buf[written] = '\0'; /* Null terminate */
                    log_debug("%s::%s(%d) : converted string = %s", LOG_INF, buf);
                    if (bio) BIO_free(bio);
                    bResult = true; /* We are good to go */
                } else {
                    log_error("%s::%s(%d) : Error converting ASN1 date to string", LOG_INF);
                    if (bio) BIO_free(bio);
                    break;
                }
            } else {
                log_error("%s::%s(%d) : ASN1 date format on certificate is bad", LOG_INF);
                if (bio) BIO_free(bio);
                break;
            }
        } else {
            log_error("%s::%s(%d) : Out of memory -- exiting", LOG_INF);
            exit(EXIT_FAILURE);
        }
    } while(false);
    return bResult;
} /* get_datestring_ASN1 */

/**                                                                           */
/* Compute the sha1 hash of the certificate                                   */
/*                                                                            */
/* @param  - [Input] : cert = the X509 cert to compute the thumbprint         */
/* @return - success : an ascii encoded thumbprint                            */
/*         - failure : NULL                                                   */
/*                                                                            */
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

/**                                                                           */
/* Allocate memory for a new PrivKeyList                                      */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success = a pointer to the newly allocated memory area           */
/*	       - failure = NULL                                                   */
/*                                                                            */
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
		log_error("%s::%s(%d) : Out of memory", LOG_INF);
	}
	return list;
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
			if ( pList->keys[i] ) {
				EVP_PKEY_free(pList->keys[i]);
			}
		}
		pList->key_count = 0;
	}

	log_trace("%s::%s(%d) : Freeing the PrivKeyList", LOG_INF);
	if (pList->keys) free(pList->keys);
	if (pList) free(pList);
	pList = NULL;

	return;
} /* PrivKeyList_free */

/**                                                                           */
/* Add a key to a PrivKeyList                                                 */
/*                                                                            */
/* @param  - [Output] : list = the list to add the key into                   */
/* @param  - [Input]  : cert = the key to add to the list                     */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
static bool PrivKeyList_add(PrivKeyList* list, EVP_PKEY* key)
{
	bool bResult = false;
	if(list && key)
	{
		list->keys = realloc(list->keys, (1 + list->key_count) * sizeof(key));
		if (list->keys)	
		{
			log_trace("%s::%s(%d) : Added EVP_PKEY #%d to PrivKeyList", 
				LOG_INF, list->key_count);
			list->keys[list->key_count] = key;
			list->key_count++;
			bResult = true;
		} 
		else 
		{
			log_error("%s::%s(%d) : Out of memory",	LOG_INF);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Either the list or key was NULL", LOG_INF);
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
	PEMx509List* x509list = (PEMx509List*)calloc(1,sizeof(*x509list));
	if (x509list)
	{
		x509list->item_count = 0;
		x509list->certs = NULL;
	}
	return x509list;
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
			X509_free(pList->certs[i]);
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
static bool PEMx509List_add(PEMx509List* list, X509* cert)
{
	bool bResult = false;
	if(list && cert)
	{
		list->certs = realloc(list->certs, \
			(1 + list->item_count) * sizeof(cert));
		if (list->certs)
		{
			log_trace("%s::%s(%d) : Adding X509 cert #%d to PEMx509List", 
				LOG_INF, list->item_count);
			list->certs[list->item_count] = cert;
			list->item_count++;
			bResult = true;
		}
		else
		{
			log_error("%s::%s(%d) : Out of memory",
				LOG_INF);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Either the list or cert was NULL", LOG_INF);
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
			LOG_INF);
	}
	return pem;
} /* PemInventoryItem_new */

/**                                                                           */
/* Allocate memory for a new PemInventoryList                                 */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success : a pointer to the memory allocated for the new list     */
/*         - failure : NULL                                                   */
/*                                                                            */
static PemInventoryList* PemInventoryList_new()
{
	PemInventoryList* list = (PemInventoryList*)malloc(sizeof(PemInventoryList));
	if(list)
	{
		list->item_count = 0;
		list->items = NULL;
	}
	return list;
} /* PemInventoryList_new */

/**                                                                           */
/* Free the PemInventoryList from memory                                      */
/*                                                                            */
/* @param  - [Input] : list = the PemInventoryList to free from memory        */
/* @return - none                                                             */
/*                                                                            */
void PemInventoryList_free(PemInventoryList* list)
{
	if(list && list->items)	{
		for(int i = 0; list->item_count > i; i++) {
			log_trace("%s::%s(%d) : Freeing PemInventoryItem #%d", LOG_INF, i);
			PemInventoryItem_free(list->items[i]);
		}		
		log_trace("%s::%s(%d) : Freeing PemInventoryList", LOG_INF);
		if (list->items) free(list->items);
        list->items = NULL;
	}
    if (list) free(list);
    list = NULL;
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
				"inventory", LOG_INF, item->thumbprint_string);
			bResult = true;
		}
		else
		{
			log_error("%s::%s(%d) : Out of memory",	LOG_INF);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Either the list or item was NULL", LOG_INF);
	}
	return bResult;
} /* PemInventoryList_add */

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
			log_trace("%s::%s(%d) : Freeing pem inventory item thumbprint", LOG_INF);
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
static bool PemInventoryItem_populate(PemInventoryItem* pem, X509* cert)
{
	bool bResult = false;
	char* thumb = NULL;
	unsigned char* certContent = NULL;
	int contLen = 0;

	if (pem && cert)
	{
		thumb = compute_thumbprint(cert);
		log_verbose("%s::%s(%d) : Thumbprint: %s", LOG_INF, 
			NULL == thumb ? "" : thumb);
		contLen = i2d_X509(cert, &certContent);
		log_trace("%s::%s(%d) : contLen = %d", LOG_INF, contLen);

		if (0 < contLen)
		{
			/* Store the b64 encoded DER version of the pem in here */
			log_trace("%s::%s(%d) : Storing certContent into PEMInventoryItem", LOG_INF);
			pem->cert = base64_encode(certContent, contLen, false, NULL);
			pem->thumbprint_string = strdup(thumb);
			pem->has_private_key = false;
			bResult = true;
		}
		else
		{
			log_error("%s::%s:(%d) : Error decoding cert i2d_X509\n%s", LOG_INF, certContent);
		}
	}
	else
	{
		log_error("%s::%s(%d) : Bad pem, cert, or certString", LOG_INF);
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

/**                                                                           */
/* Compare the public key stored in the certificate with a private key and    */
/* determine if they are a matched pair.                                      */
/*                                                                            */
/* @param  - [Input] : cert = An x509 certificate (contining a pub key)       */
/* @param  - [Input] : key = a keypair structure containing a private key     */
/* @return - true = public key is the pair for the private key                */
/*		   - false = they key types or common factors are not equal           */
/*                                                                            */
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
		certPubKey = X509_get_pubkey(cert); 
		certBaseId = EVP_PKEY_base_id(certPubKey); /* Get the key type */
		keyBaseId = EVP_PKEY_base_id(key);  /* Get the priv key type */

		if(certBaseId == keyBaseId) /* check for keytype match */
		{
			switch(certBaseId)
			{
			case EVP_PKEY_RSA:
				/* get the private key of the pair */
				rsaPriv = EVP_PKEY_get1_RSA(key);		
				/* get the public key of the pair */
				rsaCert = EVP_PKEY_get1_RSA(certPubKey);
				if(rsaCert && rsaPriv)
				{
					/* get public RSA n (ignore d & e) */
					RSA_get0_key(rsaCert, &nCert, NULL, NULL); 
					/* get private RSA n (ignore d & e) */
					RSA_get0_key(rsaPriv, &nPriv, NULL, NULL); 
					/* Compare the n's which should be equal */
					/* if they keys match */
					ret = (BN_cmp(nCert, nPriv) == 0); 
				}
				RSA_free(rsaPriv);
				RSA_free(rsaCert);
				break;
			case EVP_PKEY_EC:
				/* get the private key  */
				ecPriv = EVP_PKEY_get1_EC_KEY(key);		
				/* get the public key  */
				ecCert = EVP_PKEY_get1_EC_KEY(certPubKey);  
				if(ecPriv && ecCert)
				{
					/* get EC_POINT public key */
					privPoint = EC_KEY_get0_public_key(ecPriv); 
					privGroup = EC_KEY_get0_group(ecPriv); /* get EC_GROUP */
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
					privPubBytes = EC_POINT_point2hex(privGroup, privPoint, 
						POINT_CONVERSION_UNCOMPRESSED, NULL);
					/* get EC_POINT public key */
					certPoint = EC_KEY_get0_public_key(ecCert); 
					certGroup = EC_KEY_get0_group(ecCert); /* get EC_GROUP */
					certPubBytes = EC_POINT_point2hex(certGroup, certPoint, 
						POINT_CONVERSION_UNCOMPRESSED, NULL);

					/* Now that we have the point on the curve compare them, */
					/* they should be equal if the keys match */
					ret = (strcmp(privPubBytes, certPubBytes) == 0);

					OPENSSL_free(privPubBytes);
					OPENSSL_free(certPubBytes);
				}
				EC_KEY_free(ecCert);
				EC_KEY_free(ecPriv);
				break;
			default:
				log_error("%s::%s(%d) : Unknown algorithm: %d", 
					LOG_INF, certBaseId);
				break;
			}
		}

		EVP_PKEY_free(certPubKey);
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
static void populate_subject(X509_NAME* nm, char* key, char* value)
{
	if ( 0 == (strcasecmp(key,"C")) ) 
	{
		log_trace("%s::%s(%d) : Setting Country to %s", LOG_INF, value);
		X509_NAME_add_entry_by_txt(nm, "C", MBSTRING_UTF8, value, -1, -1, 0);
	} 
	else if ( 0 == (strcasecmp(key,"S")) ) 
	{
		log_trace("%s::%s(%d) : Setting State to %s", LOG_INF, value);
		X509_NAME_add_entry_by_txt(nm, "S", MBSTRING_UTF8, value, -1, -1, 0);
	} 
	else if ( 0 == (strcasecmp(key,"L")) ) 
	{
		log_trace("%s::%s(%d) : Setting locality to %s", LOG_INF, value);
		X509_NAME_add_entry_by_txt(nm, "L", MBSTRING_UTF8, value, -1, -1, 0);
	} 
	else if ( 0 == (strcasecmp(key,"O")) ) 
	{
		log_trace("%s::%s(%d) : Setting Organization to %s", LOG_INF, value);
		X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_UTF8, value, -1, -1, 0);
	} 
	else if ( 0 == (strcasecmp(key,"OU")) ) 
	{
		log_trace("%s::%s(%d) : Setting Organizational Unit to %s", LOG_INF, 
			value);
		X509_NAME_add_entry_by_txt(nm, "OU", MBSTRING_UTF8, value, -1, -1, 0);
	} 
	else if ( 0 == (strcasecmp(key,"CN")) ) 
	{
		log_trace("%s::%s(%d) : Setting Common Name to %s", LOG_INF, value);
		X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_UTF8, value, -1, -1, 0);
	}
    else if ( 0 == (strcasecmp(key,"ST")) )
    {
        log_trace("%s::%s(%d) : Setting State to %s", LOG_INF, value);
        X509_NAME_add_entry_by_txt(nm, "ST", MBSTRING_UTF8, value, -1, -1, 0);
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
		log_error("%s::%s(%d) : Out of memory", LOG_INF);
		goto cleanup;
	}

	localSubjectPtr = strdup(subject);
	curPtr = localSubjectPtr;
	log_debug("%s::%s(%d) : Subject \"%s\" is %ld characters long", 
		LOG_INF, curPtr, strlen(curPtr));

	log_trace("%s::%s(%d) : hasError = %s endOfSubject = %s", LOG_INF, 
		hasError ? "true" : "false", endOfSubject ? "true" : "false");

	while(!hasError && !endOfSubject)
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

				populate_subject(subjName, strippedKey, strippedVal);

				/* Don't try to advance if we just advanced past the */
				/* null-terminator */
				if( *(curPtr-1) != '\0' ) 
				{
					if ( *curPtr != '\0' )
					{
						/* Whitespace between RDNs should be ignored */
						log_trace("%s::%s(%d) : Stripping leading whitespace "
							"from \"%s\"", LOG_INF, curPtr);
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
				log_error("%s::%s(%d) : Input string '%s' is not a valid X500"
					" name", LOG_INF, localSubjectPtr);
				hasError = true;
			}
		}
		else
		{
			log_error("%s::%s(%d) : Input string '%s' is not a valid X500 name",
				LOG_INF, localSubjectPtr);
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

	if (!hasError) {
		return subjName;	
	}
	else {
		return NULL;
	}
	
} /* parse_subject */

/**                                                                           */
/* Convert the base 64 encoded cert into a BIO structure to use in saving     */
/* NOTE: The Keyfactor platform sends down the certificate as a DER, except   */
/*       that DER is base 64 encoded to send via HTTP.  The result is a       */
/*       "naked PEM" that is, a PEM without the -----BEGIN CERTIFICATE-----   */
/*       and -----END CERTIFICATE---- in it.                                  */
/*                                                                            */
/* To get a true PEM to write to disk, we leverage the internal conversion    */
/* routines.  So, decode the "naked PEM" to creat a DER.  Then load the DER   */
/* into an openSSL internal data structure using a d2i_ function              */
/* then write the internal function as a PEM into a BIO structure.            */
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
static unsigned long write_cert_bio(BIO* bio, const char* b64cert)
{
	unsigned long errNum = 0;
	size_t outLen;
	X509* certStruct = NULL;
	bool result = false;
	char *certBytePtr = NULL;

    log_trace("%s::%s(%d) : Attempting to decode DER", LOG_INF);
	certBytePtr = base64_decode(b64cert, -1, &outLen);
    log_trace("%s::%s(%d) : Decoded certificate and got contents of \n%s", LOG_INF, certBytePtr);
	const unsigned char** tempPtrPtr = (const unsigned char**)&(certBytePtr);

	if (d2i_X509(&certStruct, tempPtrPtr, outLen)) 
	{
		if (PEM_write_bio_X509(bio, certStruct)) 
		{
			result = true;
		}
	}

	if(result)	
	{
		log_verbose("%s::%s(%d) : Cert written to BIO", LOG_INF);
	}
	else 
	{
		errNum = ERR_peek_last_error();
	}

	if ( certStruct ) 
	{
		X509_free(certStruct);
	}

	if (certBytePtr) {
		certBytePtr -= outLen;
		free(certBytePtr);
	}
	return errNum;
}

/**                                                                           */
/* Convert a private key into a PEM formatted BIO structure to use in saving  */
/*                                                                            */
/* @param  - [Output] : the bio to write the key into                         */
/* @param  - [Input] : A password (or NULL or "" if none) to encode the bio   */
/* @return - success : 0                                                      */
/*         - failure : error code                                             */
/*                                                                            */
static unsigned long write_key_bio(BIO* bio, const char* password, 
	EVP_PKEY* key)
{
	unsigned long errNum = 0;

	/* If no password, then set it to null, else set it to password */
	const char* tmpPass = 
		(password && strcmp(password, "") != 0) ? password : NULL;

	/* If we have a password, set the cypher to AES256 with CBC else null */
	const EVP_CIPHER* tmpCiph = 
		(password && strcmp(password, "") != 0) ? EVP_aes_256_cbc() : NULL;

	if ( NULL == key ) 
	{
		/* We want to save the global keyPair since no key was passed */
		if(PEM_write_bio_PKCS8PrivateKey(bio, keyPair, tmpCiph, NULL, 
			0, 0, (char*)tmpPass))
		{
			log_verbose("%s::%s(%d) : Key written to BIO", LOG_INF);
		}
		else
		{
			errNum = ERR_peek_last_error();
		}
	}
	else
	{
		/* Save the keypair passed to this function */
		if(PEM_write_bio_PKCS8PrivateKey(bio, key, tmpCiph, NULL, 
			0, 0, (char*)tmpPass))
		{
			log_verbose("%s::%s(%d) : Key written to BIO", LOG_INF);
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
/* @param  - [Ouput] keyList = the array of keys                              */
/*                   NOTE: This must be freed by the calling function         */
/* @return - success = 0                                                      */
/*           failure = Any other integer                                      */
/*                                                                            */
static int get_key_inventory(const char* path, const char* password, 
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
	EVP_PKEY* key = NULL;
	while(PEM_read(fp, &name, &header, &data, &length))
	{
		key = NULL;
		tempData = data;
	
		if( (strcmp(name, "CERTIFICATE") == 0) )
		{
			log_error("%s::%s(%d) WARNING: Certificate found in keystore"
				" -- skipping", LOG_INF);
		}
		else if( (strcmp(name, "PRIVATE KEY") == 0) && 
			     (d2i_AutoPrivateKey(&key, &tempData, length)) )
		{
			log_verbose("%s::%s(%d) : Entry is a private key", LOG_INF);
			PrivKeyList_add(*keyList, key);
		}
		else if(strcmp(name, "ENCRYPTED PRIVATE KEY") == 0)
		{
			BIO* keyBio = BIO_new_mem_buf(data, length);
			if(d2i_PKCS8PrivateKey_bio(keyBio, &key, NULL, 
				(char*)(password ? password : "")))
			{
				log_verbose("%s::%s(%d) : Entry is an encrypted private key", 
					LOG_INF);
				PrivKeyList_add(*keyList, key);
			}
			else
			{
				unsigned long errNum = ERR_peek_last_error();
				ERR_error_string(errNum, errBuf);
				log_error("%s::%s(%d) : Unable to decrypt private key: %s", 
					LOG_INF, errBuf);
			}
			BIO_free(keyBio);
		}
		else
		{
			log_verbose("%s::%s(%d) : Entry is not a key, and will be skipped",	
				LOG_INF);
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

/**                                                                           */
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
/*                     the NAKED PEM representation of the cert.              */
/* @param  - [Input] : returnX509array =                                      */
/*                     true if you want the array passed back via pPemArray   */
/*                      NOTE: This means the calling function must dispose    */
/*                            of the allocated memory                         */
/*                     false disposes of the array here                       */
/* @param  - [Output]: (optional) pKeyArray = the list of private keys in the */
/*											  store                           */
/* @param  - [Input] : returnKeyArray =                                       */
/*                     true if you want the array passed back via pKeyArray   */
/*                       NOTE: This means the calling function must dispose   */
/*                             of the allocated memory                        */
/*                     false disposes of the array here                       */
/* @return - success = 0                                                      */
/*         - failure = any other integer                                      */
/*                                                                            */
static int get_inventory(const char* path, const char* password, 
	PemInventoryList** pPemList, PEMx509List** pPemArray, 
	const bool returnX509array, PrivKeyList** pKeyArray, 
	const bool returnKeyArray)
{
	int ret = 0; 
	char* name = NULL;
	char* header = NULL;
	unsigned char* data = NULL;
	long length = 0;
	char errBuf[120];

	/* Open the filestore */
	log_trace("%s::%s(%d) : Opening %s", LOG_INF, path);
	FILE* fp = fopen(path, "r");
	if(!fp)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s::%s(%d) : Unable to open store at %s: %s", 
			LOG_INF, path, errStr);
		free(errStr);
		return ret;
	}

	/* Create the inventory list to share with the agent */
	*pPemList = PemInventoryList_new();
	/* Now create a 'mirror' array where each index into the                  */
	/* PemInventoryList->items array is equal to the index into this array.   */
	/* That is:                                                               */
	/* PemInventoryList->items[x] = PEMx509List->certs[x] for all values of x */
	/*                                                                        */
	PEMx509List* x509array = PEMx509List_new(); 
	/* Also create an array to store keys into */
	PrivKeyList* keyList = PrivKeyList_new();

	if ( (NULL == (*pPemList)) || \
		 (NULL == x509array) || \
		 (NULL == keyList) )
	{
		log_error("%s::%s(%d) : Out of memory",
			LOG_INF);
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

		log_trace("%s::%s(%d) : found %s", LOG_INF, name);
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
				log_error("%s::%s(%d) Not adding cert to list of certs "
					"in store", LOG_INF);
			}		
		}
		else if( (strcmp(name, "PRIVATE KEY") == 0) && \
			     (d2i_AutoPrivateKey(&key, &tempData, length)) )
		{
			log_verbose("%s::%s(%d) : Entry is a private key", LOG_INF);
			PrivKeyList_add(keyList, key);
		}
		else if(strcmp(name, "ENCRYPTED PRIVATE KEY") == 0)
		{
			BIO* keyBio = BIO_new_mem_buf(data, length);
			if(d2i_PKCS8PrivateKey_bio(keyBio, &key, NULL, \
				(char*)(password ? password : "")))
			{
				log_verbose("%s::%s(%d) : Entry is an encrypted private key", 
					LOG_INF);
				PrivKeyList_add(keyList, key);
			}
			else
			{
				unsigned long errNum = ERR_peek_last_error();
				ERR_error_string(errNum, errBuf);
				log_error("%s::%s(%d) : Unable to decrypt private key: %s", 
					LOG_INF, errBuf);
			}
			BIO_free(keyBio);
		}
		else
		{
			log_verbose("%s::%s(%d) : Entry is not a certificate, "
				"and will be skipped",	LOG_INF);
		}

		OPENSSL_free(name);
		OPENSSL_free(header);
		OPENSSL_free(data);
		length = 0;
	}

	log_verbose("%s::%s(%d) : %d items in PEM list", LOG_INF, 
		(*pPemList)->item_count);
	log_verbose("%s::%s(%d) : Checking for matching private keys", LOG_INF);
	for(int i = 0; i < (*pPemList)->item_count; ++i)
	{
		log_verbose("%s::%s(%d) : Thumbprint: %s", LOG_INF, 
			(*pPemList)->items[i]->thumbprint_string);

		for(int k = 0; k < keyList->key_count; ++k)
		{
			/* Use the x509array to grab the X509 certificate associated with */
			/* the (*pPemList)->items[i]->cert.  Since *pPemList has the cert */
			/* stored as an ASCII encoded string instead of an X509 cert.     */
			/*                                                                */
			/* Remember, the x509array is a 1:1 match with the items array    */
			/* in the *pPemList.                                              */
			/*                                                                */ 
			if(is_cert_key_match(x509array->certs[i], keyList->keys[k]))
			{
				log_verbose("%s::%s(%d) : Found matching cert and private key", 
					LOG_INF);
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
			log_trace("%s::%s(%d) : Freeing x509array", LOG_INF);
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
		log_trace("%s::%s(%d) : Freeing *pPemList", LOG_INF);
		PemInventoryList_free(*pPemList);
		*pPemList = NULL;
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
/* Append to a store a new cert                                               */
/*                                                                            */
/* @param  - [Input] : storePath = the stores location                        */
/* @param  - [Input] : cert = the X509 certificate                            */
/* @return - success = 0;                                                     */
/*           failure = Any other integer                                      */
/*                                                                            */
static int store_append_cert(const char* storePath, X509* cert)
{
	FILE* fpAdd = fopen(storePath, "a");
	int ret = 0;
	if(!fpAdd)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s::%s(%d) : Unable to open store at %s: %s", 
			LOG_INF, storePath, errStr);
	}
	else
	{
		if(!PEM_write_X509(fpAdd, cert))
		{
			char errBuf[120];
			unsigned long errNum = ERR_peek_last_error();
			ERR_error_string(errNum, errBuf);
			log_error("%s::%s(%d) : Unable to write certificate to store: %s", 
				LOG_INF, errBuf);
			ret = -1;
		}

		if(fpAdd) fclose(fpAdd);
	}
	return ret;
} /* store_append_cert */

#if defined(__TPM__)
/**                                                                           */
/* Generate an RSA key using the TPM module                                   */
/*                                                                            */
/* This function calls out to generate an RSA key using the TPM.              */
/*  @param exp exponent for key                                               */
/*	@param rsa the rsa key structure                                          */
/*	@param keySize the size of the keyBIO                                     */
/*	@param tpm2Data a pointer to the tpm2Data structure                       */
/*  @returns success : EVP_PKEY * for use with the SSL engine                 */
/*	       failure : NULL                                                     */
/*                                                                            */
/*                                                                            */
static EVP_PKEY* genkey_rsa_using_TPM( BIGNUM *exp,  RSA *rsa, 
	int keySize, TPM2_DATA *tpm2Data )
{
	log_verbose("%s::%s(%d) : Generating RSA key using TPM", LOG_INF);
	char *password = "";
	TPM2_HANDLE parent = 0;

	log_trace("%s::%s(%d) : Calling tpm2tss_rsa_genkey", LOG_INF);
    if ( !tpm2tss_rsa_genkey(rsa, keySize, exp, password, parent) ) 
    {
        log_error("%s::%s(%d) : Error: RSA key generation failed", LOG_INF);
        return NULL;
    }

    /* export the encrypted BLOB into a tpm2Data structure */
	log_trace("%s::%s(%d) : Copy rsa into tpm2Data format", LOG_INF);
    memcpy(tpm2Data, RSA_get_app_data(rsa), sizeof(*tpm2Data));

	log_verbose("%s::%s(%d) : Key generated converting BLOB to openSSL format", 
		LOG_INF);
	/* convert the encrypted BLOB into something the openSSL engine can use */
	EVP_PKEY *keyPair = NULL;
	log_trace("%s::%s(%d) : Calling tpm2tss_rsa_makekey", LOG_INF);
    keyPair = tpm2tss_rsa_makekey( tpm2Data ); /* docs wrong this is **  */
    if ( NULL == keyPair ) 
    {
        log_error("%s::%s(%d) : Error: tpm2tss_rsa_makekey.", LOG_INF);
        return NULL;
    }
    log_verbose("%s::%s(%d) : Successfully created openSSL compatible "
    	"keyPair in memory.", LOG_INF);
    return keyPair;
} //genkey_rsa
#endif

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**                                                                           */
/* Take the ASCII entropy sent by the platform & seed the RNG for openSSL     */
/*                                                                            */
/* @param  - [Input] : b64entropy is the string to use to seed the RNG        */
/* @return - success : 0                                                      */
/*         - failure : -1                                                     */
/*                                                                            */
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

/**                                                                           */
/* Generate an RSA keypair & store it into tempKeypair                        */
/*                                                                            */
/* @param  - [Input] : keySize = the size of the RSA key                      */
/* @param  - [Input] : path = path to the keyfile (if we are using a TPM)     */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
#if defined(__TPM__)
bool ssl_generate_rsa_keypair(int keySize, const char* path)
#else
bool ssl_generate_rsa_keypair(int keySize)
#endif
{
	char errBuf[120];
	BIGNUM* exp = NULL;
	unsigned long errNum = 0;
	int setWordResult = 0;
	bool bResult = false;

	log_trace("%s::%s(%d) : Assigning space for big number", LOG_INF);
	exp = BN_new();
	if (!exp) {
        log_error("%s::%s(%d) : out of memory when creating exponent "
        	"in genkey_rsa", LOG_INF);
        return NULL;
    }

    log_trace("%s::%s(%d) : Generating big number exp for RSA keygen", LOG_INF);
	setWordResult = BN_set_word(exp, RSA_DEFAULT_EXP);
	if ( 0 == setWordResult ) {
		log_error("%s::%s(%d) : Failed assigning exp for RSA keygen", LOG_INF);
		return NULL;
	}

	if (keyPair) 
	{
		log_trace("%s::%s(%d) : Freeing newRsa & EVP keyPair", LOG_INF);
		EVP_PKEY_free(keyPair); /* Note this frees both structures */
		newRsa = NULL;
		keyPair = NULL;
	}

	log_trace("%s::%s(%d) : Creating new RSA space", LOG_INF);
	newRsa = RSA_new();
	if (!newRsa) {
        log_error("%s::%s(%d) : out of memory when creating RSA variable "
        	"in genkey_rsa", LOG_INF);
        if ( exp ) 
        { 
        	BN_free(exp); 
        }
        return NULL;
    }

#ifdef __TPM__
	/**************************************************************************/
	/* Create RSA keypair using TPM                                           */
	/**************************************************************************/
    if (NULL == path) 
    {
    	log_error("%s::%s(%d) : Defaulting Cert to /home/pi/temp.blob", LOG_INF);
    	ConfigData->AgentCert = strdup("/home/pi/temp.blob");
    }
	TPM2_DATA *tpm2Data = calloc(1, sizeof(*tpm2Data));
	if ( NULL == tpm2Data ) 
	{
	     log_error("%s::%s(%d) : out of memory for tpm2Data", LOG_INF);
	     return NULL;
	}
	keyPair = genkey_rsa_using_TPM( exp, newRsa, keySize, tpm2Data );
	if ( NULL == keyPair ) 
	{
		char errBuf[120];
		unsigned long errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error("%s::%s(%d) : Unable to generate key pair: %s", 
			LOG_INF, errBuf);
		return NULL;
	}

	log_verbose("%s::%s(%d) : Write encrypted BLOB to disk - %s", 
		LOG_INF, path);
	if ( !tpm2tss_tpm2data_write(tpm2Data, path) )
	{
		log_error("%s::%s(%d) : Error writing file %s",	LOG_INF, path);
		return NULL;
	}
	log_verbose("%s::%s(%d) : Successfully wrote BLOB to disk", LOG_INF);
	bResult = true;
	/**************************************************************************/
	/* END Create RSA keypair using TPM                                       */
	/**************************************************************************/
#else /* __TPM__ not defined, so use standard engine */
	/**************************************************************************/
	/* Create keypair using standard openSSL engine                           */
	/**************************************************************************/
	log_trace("%s::%s(%d) : Generating the RSA key", LOG_INF);
	if(RSA_generate_key_ex(newRsa, keySize, exp, NULL))	
	{
		log_trace("%s::%s(%d) : RSA Key generated, converting to EVP structure",
			LOG_INF);
		if ( keyPair ) 
		{
			log_warn("%s::%s(%d) : EVP keyPair wasn't freed possible "
				"memory leak", LOG_INF);			
			keyPair = NULL;
		}
		
		keyPair = EVP_PKEY_new();
		if (!keyPair) 
		{
			log_error("%s::%s(%d) : Out of memory allocating keypair", LOG_INF);
			goto exit;
		}

		log_trace("%s::%s(%d) : Assigning newRsa to keyPair", LOG_INF);
		EVP_PKEY_assign_RSA(keyPair, newRsa);
		bResult = true;
	}
	else
	{
		errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error("%s::%s(%d) : Unable to generate key pair: %s", 
			LOG_INF, errBuf);
	}
#endif

exit:
	if ( exp ) 
	{
		log_trace("%s::%s(%d) : Freeing big number", LOG_INF);
		BN_free(exp); 
	}
	/* NOTE: Do NOT free newRsa, it will corrupt EVP_PKEY */
	return bResult;
} /* generate_rsa_keypair */

/**                                                                           */
/* Generate an ECC keypair & store it into tempKeypair                        */
/*                                                                            */
/* @param  - [Input] : keySize = the size of the ECC key                      */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
bool ssl_generate_ecc_keypair(int keySize)
{
	char errBuf[120];
	int eccNid = -1;
	unsigned long errNum = 0;
	bool bResult = false;

#if defined(__TPM__)
	log_error("%s::%s(%d) : Infineon SLB9670 on a Raspberry Pi currently "
		"does not support ECC key generation", LOG_INF);
	return false;
#endif

	switch(keySize)
		{
		case 256:
			log_trace("%s::%s(%d) : Setting ECC curve to NID_X9_62_prime256v1",	
				LOG_INF);
			eccNid = NID_X9_62_prime256v1;
			break;
		case 384:
			log_trace("%s::%s(%d) : Setting ECC curve to NID_secp384r1", 
				LOG_INF);
			eccNid = NID_secp384r1;
			break;
		case 521:
			log_trace("%s::%s(%d) : Setting ECC curve to NID_secp521r1", 
				LOG_INF);
			eccNid = NID_secp521r1;
			break;
		default:
			log_error("%s::%s(%d) : Invalid ECC key length: %d. Falling "
				"back to default curve", LOG_INF, keySize);
			eccNid = NID_X9_62_prime256v1;
			break;
		}

		/**********************************************************************/
		/* Create keypair using standard openSSL engine                       */
	    /**********************************************************************/

		if (keyPair) 
		{
			log_trace("%s::%s(%d) : Freeing newEcc & EVP keyPair", LOG_INF);
			EVP_PKEY_free(keyPair); /* Note this frees both structures */
			newEcc = NULL;
			keyPair = NULL;
		}
		log_trace("%s::%s(%d) : Creating new ECC structure with named curve", 
			LOG_INF);
		newEcc = EC_KEY_new_by_curve_name(eccNid);
		log_trace("%s::%s(%d) : set asn1 flag to Named Curve", LOG_INF);
		EC_KEY_set_asn1_flag(newEcc, OPENSSL_EC_NAMED_CURVE);
		log_trace("%s::%s(%d) : Generating new ECC key", LOG_INF);
		if(EC_KEY_generate_key(newEcc))
		{

			if( keyPair )
			{
				log_warn("%s::%s(%d) : keyPair was not freed, possible "
					"memory leak", LOG_INF);
				keyPair = NULL;
			}
			log_trace("%s::%s(%d) : Creating EVP keyPair structure", LOG_INF);
			keyPair = EVP_PKEY_new();
			
			log_trace("%s::%s(%d) : New keypair created, assigning to EVP "
				"keyPair", LOG_INF);
			if(0 == EVP_PKEY_assign_EC_KEY(keyPair, newEcc))
			{
				log_error("%s::%s(%d) : Error assigning keyPair", LOG_INF);
				return NULL;
			}
			else
			{
				log_trace("%s::%s(%d) : Successfully assigned ECC keypair", 
					LOG_INF);
				bResult = true;
			}
		}
		else
		{
			errNum = ERR_peek_last_error();
			ERR_error_string(errNum, errBuf);
			log_error("%s::%s(%d) : Unable to generate key pair: %s", 
				LOG_INF, errBuf);
		}
		
	return bResult;
} /* generate_ecc_keypair */

/**                                                                           */
/* Create a CSR using the subject provided and the temporary key keyPair.     */
/* Return an ASCII CSR (minus the header and footer).                         */
/*                                                                            */
/* @param  - [Input]  : asciiSubject string with the subject line             */
/*                      e.g., CN=1234,OU=NA,O=Keyfactor,C=US                  */
/* @param  - [Output] : csrLen the # of ASCII characters in the csr           */
/* @param  - [Output]: pMessage = a string array containing any messages      */
/*                     we want to pass back to the calling function           */
/* @return - success : the CSR string minus the header and footer             */
/*           failure : NULL                                                   */
/*                                                                            */
char* ssl_generate_csr(const char* asciiSubject, size_t* csrLen,
	char** pMessage)
{
	X509_REQ* req = NULL;
	X509_NAME* subject = NULL;
	unsigned char reqBytes[MAX_CSR_SIZE] = {0};
	char* csrString = NULL;
	int result = SSL_SUCCESS;
	char errBuf[120];
	int errNum = 0;
	
	/*************************************************************************/
	/* 1.) Set up the CSR as a new x509 request by creating a blank request  */
	/*     then adding in the public key, setting the subject, and signing   */
	/*     it with the private key.                                          */
	/*************************************************************************/
	log_verbose("%s::%s(%d) : Setting up a CSR", LOG_INF);
	req = X509_REQ_new();	// Ask for the new structure
	if ( NULL == req )
	{
		log_error("%s::%s(%d) : Out of memory",	LOG_INF);
		append_linef(pMessage, "%s::%s(%d) : Out of memory", LOG_INF);
		return NULL;
	}

	result = X509_REQ_set_version(req, 1);
	if ( SSL_SUCCESS != result )
	{
		log_error("%s::%s(%d) : Failed to set REQ version",	LOG_INF);
		append_linef(pMessage, "%s::%s(%d) : Failed to set REQ version", 
			LOG_INF);
		X509_REQ_free(req);
		return NULL;
	}

	log_trace("%s::%s(%d) : Converting subject %s into openSSL structure", 
		LOG_INF, asciiSubject);
	subject = parse_subject(asciiSubject); 
	/* Add the X509_NAME to the req */
	result = X509_REQ_set_subject_name(req, subject); 
	if ( SSL_SUCCESS == result )
	{
		log_trace("%s::%s(%d) : Adding the public key to the CSR", LOG_INF);
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
				log_error("%s::%s(%d) : CSR signing failed with code, "
					"0x%X = %s", LOG_INF, result, errBuf);
				append_linef(pMessage, "CSR signing failed with code, "
					"0x%X = %s", result, errBuf);
				csrString = NULL;
			}
			else
			{
				log_trace("%s::%s(%d) : Successfully signed CSR", LOG_INF);
				result = SSL_SUCCESS;
			}
		}
		else
		{
			errNum = ERR_peek_last_error();
			ERR_error_string(errNum, errBuf);
			log_error("%s::%s(%d) : CSR set of public key failed with code, "
				"0x%X = %s", LOG_INF, result, errBuf);
			append_linef(pMessage, "CSR set of public key failed with code, "
				"0x%X = %s", result, errBuf);
			csrString = NULL;
		}
	}
	else
	{
		errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error("%s::%s(%d) : CSR subject name set failed with code, "
			"0x%X = %s", LOG_INF, result, errBuf);
		append_linef(pMessage, "CSR subject name set failed with code, "
			"0x%X = %s", result, errBuf);
		csrString = NULL;
	}

	/*************************************************************************/
	/* 2.) Take the resulting DER, encode it and convert it to a             */
	/*     string; the result is a PEM without the BEGIN CERTIFICATE REQUEST */
	/*     and END CERTIFICATE REQUEST                                       */
	/*************************************************************************/
	if( SSL_SUCCESS == result )	{
		log_verbose("%s::%s(%d) : Encoding the CSR and converting it to a base 64 encoded string.", LOG_INF);
        unsigned char* tempReqBytes = reqBytes;
        /* Encode the CSR request as a PKCS#10 certificate request */
        int writeLen = i2d_X509_REQ(req, &tempReqBytes);
        /* Now convert this structure to an ASCII string */
        csrString = base64_encode(reqBytes, (size_t)writeLen, false, NULL);
        *csrLen = (size_t)writeLen; // GM Specific Code
        log_trace("%s::%s(%d) : csrString=%s", LOG_INF, csrString);
        log_trace("%s::%s(%d) : csrLen = %ld", LOG_INF, *csrLen);
        if (MAX_CSR_SIZE < *csrLen) {
            log_error("%s::%s(%d) : The length of the CSR = %ld which is longer than the maximum defined "
                      "length of %d -- ABORTING, please increase the maximum CSR length above %ld and re-compile",
                      LOG_INF, *csrLen, MAX_CSR_SIZE, *csrLen);
            exit(EXIT_FAILURE);
        }
	}

    log_trace("%s::%s(%d) : Freeing req via X509_REQ_free", LOG_INF);
	if ( req ) X509_REQ_free(req);
    log_trace("%s::%s(%d) : Freeing subject via X509_NAME_free", LOG_INF);
	if ( subject ) X509_NAME_free(subject);
    subject = NULL;
	return csrString;
} /* ssl_generate_csr */

/**                                                                           */
/* Save the cert and key to the locations requested                           */
/* Store the locally global variable keyPair to the location requested        */
/*                                                                            */
/* @param  - [Input] : storePath = the store location for the cert            */
/* @param  - [Input] : keyPath = the location to save the key, if NULL or     */
/*                     blank, store the encoded key appended to the cert.     */
/* @param  - [Input] : password = the password for the private key            */
/* @param  - [Input] : cert = The cert in an ASCII encoded string             */
/* @param  - [Output]: pMessage = a string array containing any messages      */
/*                     we want to pass back to the calling function           */
/* @return - unsigned long error code                                         */
/*                                                                            */
unsigned long ssl_save_cert_key(const char* storePath, const char* keyPath,	
	const char* password, const char* cert, char** pMessage)
{
	BIO* certBIO = NULL;
	BIO* keyBIO = NULL;
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
	} else {
		/* Write the cert as a full PEM into memory */
		certBIO = BIO_new(BIO_s_mem());
		keyBIO = NULL;

		err = write_cert_bio(certBIO, cert);
		if(err)	
		{
			ERR_error_string(err, errBuf);
			log_error("%s::%s(%d) : Unable to write certificate to BIO: %s", 
				LOG_INF, errBuf);
			append_linef(pMessage, "Unable to write certificate to BIO: %s", 
				errBuf);
		}
	}

#ifndef __TPM__
	/* If there isn't a TPM store the key from memory into a file */
	/* If there is a TPM, this got stored to a file during key creation */
	if(!err)
	{
		if(keyPath)	
		{
			keyBIO = BIO_new(BIO_s_mem());
			err = write_key_bio(keyBIO, password, NULL); 
		}
		else 
		{
			err = write_key_bio(certBIO, password, NULL); 
		}

		if(err)	
		{
			ERR_error_string(err, errBuf);
			log_error("%s::%s(%d) : Unable to write key to BIO: %s", LOG_INF, 
				errBuf);
			append_linef(pMessage, "Unable to write key to BIO: %s", errBuf);
		}
	}
#endif

	if(!err) 
	{
		char* data = NULL;
		long len = BIO_get_mem_data(certBIO, &data);
		err = replace_file(storePath, data, len, true);

		if(err)	
		{
			char* errStr = strerror(err);
			log_error("%s::%s(%d) : Unable to write store at %s: %s", 
				LOG_INF, storePath, errStr);
			append_linef(pMessage, "Unable to write store at %s: %s", storePath,
				errStr);
		}
	}

#ifndef __TPM__
	if(!err && keyPath)
	{
		char* data = NULL;
		long len = BIO_get_mem_data(keyBIO, &data);
		err = replace_file(keyPath, data, len, true);

		if(err)
		{
			char* errStr = strerror(err);
			log_error("%s::%s(%d) : Unable to write key at %s: %s", LOG_INF, 
				keyPath, errStr);
			append_linef(pMessage, "Unable to write key at %s: %s", keyPath, 
				errStr);
		}
	}
#endif

	if ( certBIO ) BIO_free(certBIO);
	if ( keyBIO  ) BIO_free(keyBIO);
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
int ssl_read_store_inventory(const char* path, const char* password, 
	PemInventoryList** pPemList)
{
	return get_inventory(path, password, pPemList, NULL, false, NULL, false);
} /* ssl_read_store_inventory */


/**                                                                           */
/* Create a PemInventoryItem (with has_private_key set to false) from an      */
/* ASCII cert.  Verify the cert is valid & compute its thumbprint.            */
/*                                                                            */
/* NOTE: The PemInventoryItem must be freed by the calling function by        */
/*       invoking PemInventoryItem_free(pem);                                 */
/*                                                                            */
/* @param  - [Output] : pem = the variable which points to the new item       */
/* @param  - [Input] : certASCII = the b64 encoded NULL terminated certificate*/
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
bool ssl_PemInventoryItem_create(struct PemInventoryItem** pem, const char* certASCII)
{
	bool bResult = false;
	X509* cert = NULL;
	size_t certLen = 0;
	BIO* cbio = NULL;
	char* certDER = NULL;

	/* Convert the naked PEM to a DER */
	log_trace("%s::%s(%d) : Converting PEM to DER:\n%s", LOG_INF, certASCII);
	certDER = base64_decode(certASCII, -1, &certLen);

	/* Convert the DER to an internal structure */
	const unsigned char** tempPtrPtr = (const unsigned char**)&certDER;
	log_trace("%s::%s(%d) : Converting DER to internal cert", LOG_INF);
	if (d2i_X509(&cert, tempPtrPtr, certLen)) {
		log_trace("%s::%s(%d) : Converting cert to X509", LOG_INF);
		cbio = BIO_new(BIO_s_mem());
        if (NULL == cbio) {
            log_error("%s::%s(%d) : cbio is NULL -- error in SSL call to BIO_new(BIO_s_mem())", LOG_INF);
            goto exit;
        }
		PEM_write_bio_X509(cbio, cert);
        if (NULL == cbio) {
            log_error("%s::%s(%d) : cbio is NULL -- error in SSL call to PEM_write_bio_X509", LOG_INF);
            goto cleanup;
        }
	}

    cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
    if ( NULL == cert ) {
        log_error("%s::%s(%d) : This is not a valid X509 cert: \n%s", LOG_INF, certASCII);
        goto exit;
    }
    /* cert now contains the X509 cert */
    if ( NULL == (*pem = PemInventoryItem_new()) ) {
        log_error("%s::%s(%d) : Out of memory",	LOG_INF);
        goto cleanup;
    }
    /* Populate the PemInventoryItem with a thumbprint */
    if ( PemInventoryItem_populate(*pem, cert) ) {
        bResult = true;
    } else {
        log_error("%s::%s(%d) : Error populating cert", LOG_INF);
    }

cleanup:
	if (certDER) {
		log_trace("%s::%s(%d) : Freeing certDER", LOG_INF);
		certDER -= certLen; /* Remember d2i forwarded this, so set it back */
		free(certDER); 
	}
	if (cert) {
		log_trace("%s::%s(%d) : Freeing cert", LOG_INF);
		X509_free(cert); 
	}
	if (cbio) {
		log_trace("%s::%s(%d) : Freeing cbio", LOG_INF);
		BIO_free(cbio); 
	}

exit:
    return bResult;
} /* ssl_PemInventoryItem_create */

/**                                                                           */
/* Append the certificate provided to the store.                              */
/*                                                                            */
/* @param  - [Input] : storePath = where to find the store                    */
/* @param  - [Input] : certASCII = the b64 encoded PEM string of the cert     */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
bool ssl_Store_Cert_add(const char* storePath, const char* certASCII)
{
	bool bResult = false;
	int ret = 0;
	X509* cert = NULL;
	size_t certLen;
	BIO *cbio = NULL;

	/* Convert the naked PEM to a DER */
	log_trace("%s::%s(%d) : Converting PEM to DER:\n%s", LOG_INF, certASCII);
	char* certDER = base64_decode(certASCII, -1, &certLen);

	/* Convert the DER to an internal structure */
	const unsigned char** tempPtrPtr = (const unsigned char**)&certDER;
	log_trace("%s::%s(%d) : Converting DER to internal cert", LOG_INF);
	if (d2i_X509(&cert, tempPtrPtr, certLen))
	{
		log_trace("%s::%s(%d) : Converting cert to X509", LOG_INF);
		cbio = BIO_new(BIO_s_mem());
		PEM_write_bio_X509(cbio, cert);
	}

	if (cbio && certDER)
	{
		cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
		if ( NULL == cert )
		{
			log_error("%s::%s(%d) : This is not a valid cert:\n%s", 
				LOG_INF, certASCII);
			return bResult;
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
			ret = store_append_cert(storePath, cert);
			if ( 0 != ret )
			{
				log_error("%s::%s(%d) : Unable to append cert to store at %s", 
					LOG_INF, storePath);
			}
			else
			{
				bResult = true;
			}
		}
	}
	else
	{
		log_error("%s::%s(%d) : Out of memory",	LOG_INF);
	}

	if (certDER) 
	{ 
		log_trace("%s::%s(%d) : Freeing certDER", LOG_INF);
		certDER -= certLen; /* Remember d2i forwarded this, so set it back */
		free(certDER); 
	}
	if (cert) 
	{ 
		log_trace("%s::%s(%d) : Freeing cert", LOG_INF);
		X509_free(cert); 
	}
	if (cbio) 
	{ 
		log_trace("%s::%s(%d) : Freeing cbio", LOG_INF);
		BIO_free(cbio); 
	}

	return bResult;
} /* ssl_Store_Cert_add */

/**                                                                           */
/* Remove a cert (and associated key) from a store/keystore                   */
/*                                                                            */
/* @param  - [Input] : storePath = the path for the certificate store         */
/* @param  - [Input] : searchThumb = the sha1 hash of the cert to remove      */
/* @param  - [Input] : keyPath = the path of the keystore.                    */
/*                     if NULL an use storePath                               */
/* @param  - [Input] : password = password for any encrypted keys             */
/* @return - success : true                                                   */
/*           failure : false                                                  */
/*                                                                            */
bool ssl_remove_cert_from_store(const char* storePath, const char* searchThumb, const char* keyPath, const char* password)
{
	bool bResult = false;
	PemInventoryList* pemList = NULL;
	PEMx509List* pemX509Array = NULL;
	PrivKeyList* keyArray = NULL;
	/* Write the modified store into memory */
	BIO* bio = NULL;
	char* data = NULL;
    char* pem = NULL;
	size_t len = 0;
	int ret = 0;

	/**************************************************************************/
	/* 1.) Get the PEM inventory, X509 PEM, and list of private keys          */
	/*     in the store                                                       */
	/**************************************************************************/
	log_trace("%s::%s(%d) : Get PEM inventory",	LOG_INF);
	if ( 0 != get_inventory(storePath, password, &pemList, &pemX509Array, true, 
		&keyArray, true) )	{
		if ( pemList )	{
			PemInventoryList_free(pemList);
			pemList = NULL;
		}
		if ( pemX509Array )	{
			PEMx509List_free(pemX509Array);
			pemX509Array = NULL;
		}
		if ( keyArray )	{
			PrivKeyList_free(keyArray);
			keyArray = NULL;
		}
		log_error("%s::%s(%d) : Failed to get inventory", LOG_INF);
		return bResult;
	}

	/**************************************************************************/
	/* 2.) Search for the certificate in the store by sha1 hash               */
	/**************************************************************************/
	log_trace("%s::%s(%d) : Search for matching hash to remove in inventory", LOG_INF);
	bool certFound = false;
	int i = pemList->item_count-1;
	while ( (!certFound) && (0 <= i) )	{
		log_trace("%s::%s(%d) : thumb #%d compared", LOG_INF, i);
		if (0 == strcasecmp(searchThumb, pemList->items[i]->thumbprint_string) ) {
			certFound = true;
		} else {
			i--;
		}
	}
	log_verbose("%s::%s(%d) : Found cert: %s", LOG_INF, (certFound ? "yes" : "no"));

	/**************************************************************************/
	/* 3.) Update the store, but skip the cert we want to remove              */
	/**************************************************************************/
	if ( certFound ) {
		/**************************/
		/* 3a.) Add all the certs */
		/**************************/
		log_trace("%s::%s(%d) : Writing certs to store", LOG_INF);
		bio = BIO_new(BIO_s_mem()); /* Get new memory to store the bio */
        log_trace("%s::%s(%d) : bio returned %s", LOG_INF, (NULL == bio) ? "NULL" : "a memory location");
		/* At this point i points to the pemList & */
		/* PEMx509List of the cert to delete */
		for (int j = 0; pemList->item_count > j; j++) {
			if (i != j)	{
                log_trace("%s::%s(%d) : Attempting to write cert #%d of #%d to bio",
                          LOG_INF, j+1, (pemList->item_count));
                len = strlen(pemList->items[j]->cert) + 1;
                if (NULL != pem) free(pem);
                pem = calloc(len, sizeof(*pem)); // get some memory to store the eventual PEM file
                if (NULL == pem) {
                    log_error("%s::%s(%d) : Out of memory", LOG_INF);
                    goto cleanup;
                } else {
                    memcpy(pem, pemList->items[j]->cert, len); // Copy the single string
                    if (false == pemify(&pem, x509PEMHeader, x509PEMFooter)) {
                        log_error("%s::%s(%d) : Failed to add cert to store %s", LOG_INF, storePath);
                        goto cleanup;
                    } else {
                        if (0 >= BIO_puts(bio, pem)) {
                            log_error("%s::%s(%d) : Failed to write PEM into BIO", LOG_INF);
                            goto cleanup;
                        } else {
                            log_trace("%s::%s(%d) : Successfully wrote PEM into BIO", LOG_INF);
                        }
                    }
                }
			} else {
                log_trace("%s::%s(%d) : Skipping bio write of cert #%d of #%d", LOG_INF, j+1, (pemList->item_count));
            }
		}
		/**********************************************************************/
		/* 3b.) Add all the keys found but the one for the cert we don't want */
		/**********************************************************************/
		/* Now, loop through all the private keys & */
		/* save them too, except the one */
		for (int k = 0; keyArray->key_count > k; k++) {
			if ( !is_cert_key_match(pemX509Array->certs[i], keyArray->keys[k]) ) {
				ret = write_key_bio(bio, password, keyArray->keys[k]);
				if ( 0 > ret ) {
					log_error("%s::%s(%d) : Failed to add key to store %s",
						LOG_INF, storePath);
					goto cleanup;
				}
			}
		}

		/**********************/
		/* 3c.) Write to disk */
		/**********************/
		data = NULL;
		len = BIO_get_mem_data(bio, &data);
		ret = replace_file(storePath, data, len, true);
		if( 0 != ret) {
			char* errStr = strerror(ret);
			log_error("%s::%s(%d) : Unable to write key at %s: %s", 
				LOG_INF, storePath, errStr);
			goto cleanup;
		}

		/**************************************************************/
		/* 3d.) Optional: if a keystore was provided, remove that key */
		/*      from the keystore                                     */
		/**************************************************************/
		if ( keyPath ) {
			BIO_free(bio);
			free(data);
			if ( keyArray ) {
				PrivKeyList_free(keyArray); /* Free this bit of keys */
			}
			/* And populate it with the keystore located at keyPath */
			ret = get_key_inventory(keyPath, password, &keyArray);
			if ( 0 != ret ) {
				log_error("%s::%s(%d) : Error reading keystore %s",	
					LOG_INF, keyPath);
				goto cleanup;
			}
			bio = BIO_new(BIO_s_mem()); /* Get new memory to store the bio */
			/* Write the keys to bio memory */
			for (int x = keyArray->key_count; 0 < x; x--) {
				ret = write_key_bio(bio, password, keyArray->keys[x]);
				if ( 0 != ret ) {
					log_error("%s::%s(%d) : Failed to add key to store %s", 
						LOG_INF, keyPath);
					goto cleanup;
				}
			}

			/*******************************/
			/* 3e.) Write keystore to disk */
			/*******************************/
			data = NULL;
			len = BIO_get_mem_data(bio, &data);
            log_trace("%s::%s(%d) : Writing data %s", LOG_INF, data);
			ret = replace_file(keyPath, data, len, true);
			if( 0 != ret) {
				char* errStr = strerror(ret);
				log_error("%s::%s(%d) : Unable to write key at %s: %s", 	LOG_INF, keyPath, errStr);
				goto cleanup;
			}
		} /* end separate keystore */
	} else	{
		log_error("%s::%s(%d) Cert not found in PEM store %s", 	LOG_INF, storePath);
		goto cleanup;
	}

cleanup:
	if ( pemList ) {
		PemInventoryList_free(pemList);
		pemList = NULL;
	}
	if ( pemX509Array )	{
		PEMx509List_free(pemX509Array);
		pemX509Array = NULL;
	}
	if ( keyArray )	{
		PrivKeyList_free(keyArray);
		keyArray = NULL;
	}
	if ( bio ) 	{
		BIO_free(bio);
		bio = NULL;
	}
	if ( 0 == ret )	{
		bResult = true;
	}
	return bResult;
} /* ssl_remove_cert_from_store */

/**                                                                           */
/* Check to see if a certificate is within its active dates                   */
/*                                                                            */
/* @param  - certFile = path/filename of certificate to check                 */
/* @return - true  = Certificate is within its active window                  */
/*           false = Certificate has an issue or is not active yet or is      */
/*                   expired.                                                 */
/*                                                                            */
bool ssl_is_cert_active(char* certFile) {
    bool bResult = false;
    X509* x509 = NULL;

    char errBuf[256];
    int length = 0;
    const ASN1_TIME* start_date = NULL;
    const ASN1_TIME* end_date = NULL;
    static const uint8_t bufLen = 30;
    char notBeforeString[bufLen];
    char notAfterString[bufLen];
    char nowASN1string[bufLen];
    ASN1_TIME* now_asn1 = NULL;
    time_t now = 0;

    do {
        log_info("%s::%s(%d) : Verify certificate is active", LOG_INF);
        log_trace("%s::%s(%d) : Reading PEM file %s", LOG_INF, certFile);
        x509 = get_single_cert(certFile);
        if (NULL == x509) {
            log_error("%s::%s(%d) : Error getting certificate from file %s", LOG_INF, certFile);
            break;
        }

        log_trace("%s::%s(%d) : Getting certificate start date", LOG_INF);
        start_date = X509_get0_notBefore(x509);
        if(!start_date) {
            log_warn("%s::%s(%d) : Cannot get start date of the certificate", LOG_INF);
            break;
        }
        else {
            if (get_datestring_ASN1(notBeforeString, bufLen, start_date)) {
                log_trace("%s::%s(%d) : Successfully converted notBeforeDate = %s", LOG_INF, notBeforeString);
            }
            else {
                log_error("%s::%s(%d) : Error converting notBeforeDate, assuming cert is bad", LOG_INF);
                break;
            }
        }

        log_trace("%s::%s(%d) : Getting certificate end date", LOG_INF);
        end_date = X509_get0_notAfter(x509);
        if(!end_date) {
            log_warn("%s::%s(%d) : Cannot get end date of the certificate", LOG_INF);
            break;
        }
        else {
            if (get_datestring_ASN1(notAfterString, bufLen, end_date)) {
                log_trace("%s::%s(%d) : Successfully converted notAfterString = %s", LOG_INF, notAfterString);
            }
            else {
                log_error("%s::%s(%d) : Error converting notAfterString, assuming cert is bad", LOG_INF);
                break;
            }
        }

        if(start_date && end_date) {
            log_verbose("%s::%s(%d) : Certificate is valid from %s to %s", LOG_INF, notBeforeString, notAfterString);
        }

        log_trace("%s::%s(%d) : Getting current GMT time", LOG_INF);
        now = time(&now);
        if( (time_t)-1 == now ) {
            log_error("%s::%s(%d) : Failed to get local time", LOG_INF);
            break;
        }
        now = mktime(gmtime(&now));
        if( (time_t)-1 == now ) {
            log_error("%s::%s(%d) : Failed to convert local time to GMT", LOG_INF);
            break;
        }
        log_debug("%s::%s(%d) : Current GMT time %ld", LOG_INF, now);
        log_debug("%s::%s(%d) : ctime = %s", LOG_INF, ctime(&now));
        /* Convert the time to ASN1 format */
        now_asn1 = ASN1_TIME_adj(now_asn1, now, 0, 0);
        if(get_datestring_ASN1(nowASN1string, bufLen, now_asn1)) {
            log_trace("%s::%s(%d) : Successfully converted nowASN1string = %s", LOG_INF, nowASN1string);
        }
        else {
            log_warn("%s::%s(%d) : Couldn't decode now_asn1; not fatal, continuing", LOG_INF);
        }

        int day = 0;
        int sec = 0;
        log_trace("%s::%s(%d) : Comparing start times FROM = %s and TO = %s", LOG_INF, nowASN1string, notBeforeString);
        ASN1_TIME_diff(&day, &sec, now_asn1, start_date);
        log_debug("%s::%s(%d) : day = %d    sec = %d", LOG_INF, day, sec);
        if( (0 < day) || (0 < sec) ) {
            log_error("%s::%s(%d) : Error certificate is NOT active yet", LOG_INF);
            break;
        }

        log_trace("%s::%s(%d) : Comparing end times FROM = %s and TO = %s", LOG_INF, nowASN1string, notAfterString);
        ASN1_TIME_diff(&day, &sec, now_asn1, end_date);
        log_debug("%s::%s(%d) : day = %d    sec = %d", LOG_INF, day, sec);
        if( (0 > day) || (0 > sec) ) {
            log_error("%s::%s(%d) : Error certificate is EXPIRED", LOG_INF);
            break;
        }

        log_info("%s::%s(%d) : Certificate dates are ok", LOG_INF);
        bResult = true;
    } while(false);

    if (!bResult) {
        log_info("%s::%s(%d) : Certificate dates are not ok", LOG_INF);
    }
    if (x509) X509_free(x509);

    return bResult;
} /* ssl_is_cert_active */

/**                                                                           */
/* Clean up all of the openSSL items that are outstanding                     */
/*                                                                            */
/* @param  - none                                                             */
/* @return - none                                                             */
/*                                                                            */
void ssl_cleanup(void)
{
	log_trace("%s::%s(%d) : Cleaning up openssl", LOG_INF);
	if (keyPair) EVP_PKEY_free(keyPair);
	/* NOTE: The RSA and ECC key are freed by this call */
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return;
} /* ssl_cleanup */

/**                                                                           */
/* Initialize the platform to use openssl                                     */
/*                                                                            */
/* @param  - none                                                             */
/* @return - none                                                             */
/*                                                                            */
void ssl_init(void)
{
	log_trace("%s::%s(%d) : Adding openSSL algorithms", LOG_INF);
	OpenSSL_add_all_algorithms();
	log_trace("%s::%s(%d) : Loading Crypto error strings", LOG_INF);
	ERR_load_crypto_strings();
	return;
} /* ssl_init */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
