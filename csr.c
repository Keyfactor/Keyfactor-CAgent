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
#include "csr.h"
#include "logging.h"
#include "global.h"

#ifdef __WOLF_SSL__
	#include "wolfssl_wrapper/wolfssl_wrapper.h"
#else
	#ifdef __OPEN_SSL__
		#include "openssl_wrapper/openssl_wrapper.h"
	#else
		#ifdef __TPM__
		#else
		#endif
	#endif
#endif

/******************************************************************************/
/*************************** GLOBAL VARIABLES *********************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* Generate a new keypair by calling the correct function in the              */
/* SSL wrapper layer                                                          */
/*                                                                            */
/* @param  - [Input] keyType: The type of key (ECC or RSA)                    */
/* @param  - [Input] keySize: The size of the key (192, 256, etc.)            */
/* @return - success: true                                                    */
/*           failure: false                                                   */
/*                                                                            */
#if defined(__TPM__)
bool generate_keypair(const char* keyType, int keySize, const char* path)
#else
bool generate_keypair(const char* keyType, int keySize)
#endif
{
	bool bResult = false;

	log_verbose("%s::%s(%d) : Generating key pair with type %s and length %d",	
		LOG_INF, keyType, keySize);
	
	if(strcasecmp(keyType, "RSA") == 0)
	{
	#if defined(__TPM__)
		if ( (NULL == path) || (0 == strcasecmp("",path)) ) 
		{
			log_error("%s::%s(%d) : Error, you must specify a private key "
				"path when using a TPM", LOG_INF);
			return false;
		}
		bResult = ssl_generate_rsa_keypair(keySize, path);
	#else
		bResult = ssl_generate_rsa_keypair(keySize);
	#endif
	}
	else if(strcasecmp(keyType, "ECC") == 0)
	{
#if defined(__TPM__)
		log_error("%s::%s(%d) : Error, SLB9670 with tpm2tss engine does "
			"not support ECC keygen", LOG_INF);
#else
		bResult = ssl_generate_ecc_keypair(keySize);
#endif
	}
	else
	{
		log_error("%s::%s(%d) : Invalid key type %s", 
			LOG_INF, keyType);
	}

	return bResult;
} /* generate_keypair */

/**                                                                           */
/* Request the crypto layer to generate a new CSR using the subject provided. */
/* This request expects an ASCII CSR to be returned.                          */
/*                                                                            */
/* @param  - [Input]  : asciiSubject string with the subject line             */
/*                      e.g., CN=1234,OU=NA,O=Keyfactor,C=US                  */
/* @param  - [Output] : csrLen the # of ASCII characters in the csr           */
/* @return - success : the CSR string minus the header and footer             */
/*           failure : NULL                                                   */
/*                                                                            */
char* generate_csr(const char* asciiSubject, size_t* csrLen, char** pMessage, 
	enum AgentApiResultStatus* pStatus) 
{
	char* csrString = NULL;
	*pStatus = STAT_UNK;
	csrString = ssl_generate_csr(asciiSubject, csrLen, pMessage);
	if ( NULL != csrString )
	{
		*pStatus = STAT_SUCCESS;
	}
	else
	{
		*pStatus = STAT_ERR;
	}
	return csrString;
} /* generate_csr */

/**                                                                           */
/* Request the crypto layer to save the cert and key to the locations         */
/* requested. The crypto layer uses the temporary key it has generated        */
/* to store into the location requested.                                      */
/*                                                                            */
/* @param  - [Input] : storePath = the store location for the cert            */
/* @param  - [Input] : keyPath = the location to save the key, if NULL or     */
/*                     blank, store the encoded key appended to the cert.     */
/* @param  - [Input] : password = the password for the private key            */
/* @param  - [Input] : cert = The cert in an ASCII encoded string             */
/* @param  - [Output]: pMessage = a string array containing any messages      */
/*                     we want to pass back to the calling function           */
/* @param  - [Output]: pStatus = The status code to report back to the API    */
/* @return - success : 0                                                      */
/*           failure : an unsigned long error code                            */
/*                                                                            */
unsigned long save_cert_key(const char* storePath, const char* keyPath,	
							const char* password, const char* cert, 
							char** pMessage, enum AgentApiResultStatus* pStatus)
{
	unsigned long err = 0;
	err = ssl_save_cert_key(storePath, keyPath, password, cert, pMessage);
	if ( 0 != err )
	{
		*pStatus = STAT_ERR;
	}
	else
	{
		*pStatus = STAT_SUCCESS;
	}
	return err;
} /* save_cert_key */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/