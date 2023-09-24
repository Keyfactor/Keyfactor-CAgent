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

#ifndef __CSR_H__
#define __CSR_H__

#include "dto.h"
#include "config.h"

#if defined(__TPM__)
	bool generate_keypair(const char* keyType, int keySize, const char* path);
#else
	bool generate_keypair(const char* keyType, int keySize);
#endif

char* generate_csr(const char* asciiSubject, size_t* csrLen, 
	char** pMessage, enum AgentApiResultStatus* pStatus); 


unsigned long save_cert_key(const char* storePath, const char* keyPath, 
	const char* password, const char* cert, char** pMessage, 
	enum AgentApiResultStatus* pStatus);

#endif /* __CSR_H__ */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/