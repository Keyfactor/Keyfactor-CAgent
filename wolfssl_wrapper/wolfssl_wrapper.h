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
/** @file wolfssl_wrapper.h */
#ifndef __OPENSSL_WRAPPER_H__
#define __OPENSSL_WRAPPER_H__

#include <stdbool.h>

/* These two must be the first wolf includes */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/types.h>

/**************************************************************************/
/****************** GLOBAL STRUCTURE PROTOTYPES ***************************/
/**************************************************************************/
struct PemInventoryItem
{
	char* cert; /* the naked pem */
	char* thumbprint_string;
	bool has_private_key;
};
typedef struct PemInventoryItem PemInventoryItem;

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

bool ssl_generate_rsa_keypair(int keySize);
bool ssl_generate_ecc_keypair(int keySize);

char* ssl_generate_csr(const char* asciiSubject, size_t* csrLen, 
	char** pMessage);

unsigned long ssl_save_cert_key(const char* storePath, const char* keyPath,	
	const char* password, const char* cert, char** pMessage);

int ssl_read_store_inventory(const char* path, const char* password, 
	PemInventoryList** ppPemList);

bool ssl_PemInventoryItem_create(struct PemInventoryItem** pem, 
	const char* certASCII);

bool ssl_PemInventoryItem_create(struct PemInventoryItem** ppPEMout, 
	const char* pCertASCII);

bool ssl_Store_Cert_add(const char* storePath, const char* certASCII);

bool ssl_remove_cert_from_store(const char* storePath, const char* searchThumb,\
	const char* keyPath, const char* password);

bool ssl_init(void);

bool ssl_cleanup(void);

/* This is required to allow us to seed the wolfssl random with supplied data */
#define CUSTOM_RAND_TYPE byte /* Our custom function returns a byte at a time */
extern byte custom_rng_seed_generator(void);
#undef CUSTOM_RAND_GENERATE  /* remove the default function */
#define CUSTOM_RAND_GENERATE custom_rng_seed_generator /* Point to our func */

#endif

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/