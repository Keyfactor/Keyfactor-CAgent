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
#ifndef __OPENSSL_WRAPPER_H__
#define __OPENSSL_WRAPPER_H__

#include <stdbool.h>

/**************************************************************************/
/****************** GLOBAL STRUCTURE PROTOTYPES ***************************/
/**************************************************************************/

/**                                                                           */
/* These are the AGENT versions of the ssl_PemInventoryItems and are          */
/* allocated this ssl abstraction layer.  They are freed in the AGENT layer.  */
/*                                                                            */

/**                                                                           */
/* Define a PEM for use by the platform, the PEM may have                     */
/* an encoded private key stored with it (or not).  If not,                   */
/* there is an encoded file with the private key that is                      */
/* separate from the cert.                                                    */
/*                                                                            */
/* The thumbprint is an ASCII sha1 hash of the cert                           */
/*                                                                            */
struct PemInventoryItem
{
	char* cert;
	char* thumbprint_string;
	bool has_private_key;
};
typedef struct PemInventoryItem PemInventoryItem;

/**                                                                           */
/* Define a list of PEM certs held inside of a certificate store.             */
/* This is for use by the platform's inventory function.                      */
/*                                                                            */
struct PemInventoryList
{
	int item_count;
	PemInventoryItem** items;
};
typedef struct PemInventoryList PemInventoryList;

/**************************************************************************/
/******************* GLOBAL FUNCTION PROTOTYPES ***************************/
/**************************************************************************/
void PemInventoryItem_free(PemInventoryItem* pem);

void PemInventoryList_free(PemInventoryList* list);

int ssl_seed_rng(const char* b64entropy);

#if defined(__TPM__)
	bool ssl_generate_rsa_keypair(int keySize, const char* file);
#else
	bool ssl_generate_rsa_keypair(int keySize);
#endif

bool ssl_generate_ecc_keypair(int keySize);

char* ssl_generate_csr(const char* asciiSubject, size_t* csrLen, 
	char** pMessage);

unsigned long ssl_save_cert_key(const char* storePath, const char* keyPath,	
	const char* password, const char* cert, char** pMessage);

int ssl_read_store_inventory(const char* path, const char* password, 
	PemInventoryList** pPemList);

bool ssl_PemInventoryItem_create(struct PemInventoryItem** pem, 
	const char* certASCII);

bool ssl_Store_Cert_add(const char* storePath, const char* certASCII);

bool ssl_remove_cert_from_store(const char* storePath, const char* searchThumb,\
	const char* keyPath, const char* password);

void ssl_init(void);

void ssl_cleanup(void);


#endif /* OPENSSL_WRAPPER_H */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/