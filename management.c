/*
This C Agent Reference Implementation uses the OpenSSL encryption libraries, 
which are not included as a part of this distribution.  For hardware key storage 
or TPM support, libraries such as WolfSSL may also be used in place of OpenSSL.

NOTE: usage of this file and the SDK is subject to the 
following SOFTWARE DEVELOPMENT KIT LICENSE: 

THIS IS A LICENSE AGREEMENT between you and Certified Security Solutions, Inc.,
 6050 Oak Tree Boulevard, Suite 450, Independence, Ohio 44131 (“CSS”).  This 
 License Agreement accompanies the Software Development Kit(s) (“SDK,” as 
 defined below) for CSS Products (defined below) licensed to you by CSS.  This 
 copy of the SDK is licensed to You as the end user or the representative of 
 your employer.  You represent that CSS, a licensee of one or more CSS Products
 , or a third-party working on behalf of such a licensee has authorized you to
 download this SDK.  YOU AGREE THAT THIS LICENSE AGREEMENT IS ENFORCEABLE AND 
 THAT YOUR USE OF THE SDK CONSTITUTES ACCEPTANCE OF THE AGREEMENT TERMS.  If 
 you do not agree to the terms of this Agreement, do not use this SDK.  
1. DEFINITIONS.
In this License Agreement: 
(a) “SDK” means the CSS software development kit, including any sample code, 
tools, utilities, documentation, and related explanatory materials and 
includes any upgrades, modified versions, updates, additions, and copies of 
the SDK;  
(b) “CSS Products” means[ CSS’s CMS application programs, technologies and 
software, including but not limited to CMS Enterprise, CMS Sapphire, CMS 
Topaz, and CMS VerdeTTo,] that are or may be made available for licensing, 
including any modified versions or upgrades thereof.  This License Agreement
 does not govern use of CSS Products, which are governed by separate written
 license agreements; and
(c) “You” and “your” refer to any person or entity acquiring or using the 
SDK under the terms of this License Agreement.
2. ROYALTY-FREE DEVELOPMENT LICENSE. Subject to the restrictions contained 
in this Section 2, CSS grants you limited a nonexclusive, nontransferable, 
royalty-free license to use the items in the SDK only for the purpose of 
development of software designed to interoperate with licensed CSS Products 
either on Your own behalf or on behalf of a licensee of one or more CSS
 Products.
(a) Under this License Agreement, you may use, modify, or merge all or 
portions of any sample code included in the SDK with your software .  Any 
modified or merged portion of sample code is subject to this License 
Agreement.  You are required to include CSS’s copyright notices in your 
software. You may make a reasonable, limited number of copies of the SDK to 
be used by your employees or contractors as provided herein, and not for 
general business purposes, and such employees or contractors shall be 
subject to the obligations and restrictions in this License Agreement.  
Except in accordance with the preceding sentence, you may not assign, 
sublicense, or otherwise transfer your rights or obligations granted under 
this License Agreement without the prior written consent of CSS. Any 
attempted assignment, sublicense, or transfer without such prior written 
consent shall be void and of no effect.  CSS may assign or transfer this 
License Agreement in whole or in part, and it will inure to the benefit of 
any successor or assign of CSS.
(b) Under this License Agreement, if you use, modify, or merge all or 
portions of any sample code included in the SDK with your software, you may
distribute it as part of your products solely on a royalty-free 
non-commercial basis.  Any right to distribute any part of the SDK or any 
modified, merged, or derivative version on a royalty-bearing or other 
commercial basis is subject to separate approval, and possibly the 
imposition of a royalty, by CSS.
(c) Except as expressly permitted in paragraphs 2(a) and 2(b), you may not
 sell, sublicense, rent, loan, or lease any portion of the SDK to any third
 party. You may not decompile, reverse engineer, or otherwise access or 
 attempt to access the source code for any part of the SDK not made
 available to you in source code form, nor make or attempt to make any
 modification to the SDK or remove, obscure, interfere with, or circumvent 
 any feature of the SDK, including without limitation any copyright or 
 other intellectual property notices, security, or access control mechanism.
 
3. PROPRIETARY RIGHTS. The items contained in the SDK are the intellectual
 property of CSS and are protected by United States and international 
 copyright and other intellectual property law. You agree to protect all 
 copyright and other ownership interests of CSS  in all items in the SDK 
 supplied to you under this License Agreement. You agree that all copies 
 of the items in the SDK, reproduced for any reason by you, will contain 
 the same copyright notices, and other proprietary notices as appropriate,
 as appear on or in the master items delivered by CSS in the SDK. CSS 
 retains title and ownership of the items in the SDK, the media on which 
 it is recorded, and all subsequent copies, regardless of the form or media
 in or on which the original and other copies may exist.  You may use CSS’s
 trade names, trademarks and service marks only as may be required to 
 accurately describe your products and to provide copyright notice as 
 required herein.
Except as expressly granted above, this License Agreement does not grant 
you any rights under any patents, copyrights, trade secrets, trademarks or 
any other rights in respect to the items in the SDK.
4. FEEDBACK. You are encouraged to provide CSS with comments, bug reports, 
feedback, enhancements, or modifications proposed or suggested by you for 
the SDK or any CSS Product (“Feedback”). If provided, CSS will treat such 
Feedback as non-confidential notwithstanding any notice to the contrary you 
may include in any accompanying communication, and CSS shall have the right
 to use such Feedback at its discretion, including, but not limited to, the
 incorporation of such suggested changes into the SDK or any CSS Product. 
 You hereby grant CSS a perpetual, irrevocable, transferable, sublicensable,
 royalty-free, worldwide, nonexclusive license under all rights necessary to
 so incorporate and use your Feedback for any purpose, including to make 
 and sell products and services.  
5. TERM. This License Agreement is effective until terminated.  CSS has 
the right to terminate this License Agreement immediately, without judicial
 intervention, if you fail to comply with any term herein. Upon any such
 termination you must remove all full and partial copies of the items in 
 the SDK from your computer and discontinue the use of the items in the 
 SDK.
6. DISCLAIMER OF WARRANTY. CSS licenses the SDK to you on an “AS-IS” basis.
 CSS makes no representation with respect to the adequacy of any items in
 the SDK, whether or not used by you in the development of any products, 
 for any particular purpose or with respect to their adequacy to produce 
 any particular result. CSS shall not be liable for loss or damage arising
 out of this License Agreement or from the distribution or use of your 
 products containing portions of the SDK. TO THE FULLEST EXTENT PERMITTED 
 BY LAW, CSS DISCLAIMS ALL WARRANTIES, EITHER EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO IMPLIED CONDITIONS OR WARRANTIES OF MERCHANTABILITY AND
 FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT OF ANY THIRD PARTY 
 RIGHT IN RESPECT OF THE ITEMS IN THE SDK.
CSS is under no obligation to provide any support under this License 
Agreement, including upgrades or future versions of the SDK or any portions
 thereof, to you, any end user or to any other party. 
7. LIMITATION OF LIABILITY. Notwithstanding any other provisions of this 
License Agreement, CSS’s liability to you under this License Agreement 
shall be limited to the amount you paid for the SDK or $10, whichever is 
less.
IN NO EVENT WILL CSS BE LIABLE TO YOU FOR ANY CONSEQUENTIAL, INDIRECT, 
INCIDENTAL, PUNITIVE, OR SPECIAL DAMAGES, INCLUDING DAMAGES FOR ANY LOST 
PROFITS, LOST SAVINGS, LOSS OF DATA, COSTS, FEES OR EXPENSES OF ANY KIND OR
 NATURE, ARISING OUT OF ANY PROVISION OF THIS LICENSE AGREEMENT OR THE USE
 OR INABILITY TO USE THE ITEMS IN THE SDK, EVEN IF A CSS REPRESENTATIVE HAS
 BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES, OR FOR ANY CLAIM BY ANY 
 PARTY. 
8. INDEMNIFICATION. You agree to indemnify, hold harmless, and defend CSS
 from and against any claims or lawsuits, including attorneys’ fees, that 
 arise or result from the use and distribution of your products that 
 contain or are based upon any portion of the SDK, provided that CSS gives
 you prompt written notice of any such claim, tenders the defense or 
 settlement of such a claim to you at your expense, and cooperates with 
 you, at your expense, in defending or settling any such claim.
9. CHOICE OF LAW. This Agreement will be governed by and construed in 
accordance with the substantive laws of the United States and the State of
 Ohio.  Federal and state courts located in Cuyahoga County, Ohio shall 
 have exclusive jurisdiction over all disputes relating to this Agreement.
 This Agreement will not be governed by the conflict of law rules of any 
 jurisdiction or the United Nations Convention on Contracts for the 
 International Sale of Goods, the application of which is expressly 
 excluded.
10. COMPLIANCE WITH EXPORT CONTROL LAWS. You agree that any of your 
products that include any part of the SDK will not be shipped, transferred
 or exported into any country or used in any manner prohibited by the 
 United States Export Administration Act and that you will comply with 
 all applicable export control laws. All rights to use the SDK are granted 
 on condition that such rights are forfeited if you fail to comply with the
 terms of this Agreement.
11. NON-BLOCKING OF CSS DEVELOPMENT. You acknowledge that CSS is currently 
developing or may develop technologies and products in the future that have
 or may have design and/or functionality similar to products that you may
 develop based on your license herein. Nothing in this Agreement shall
 impair, limit or curtail CSS’s right to continue with its development, 
 maintenance and/or distribution of CSS’s technology or products. You agree
 that you shall not assert any patent that you own against CSS, its 
 subsidiaries or affiliates, or their customers, direct or indirect, 
 agents and contractors for the manufacture, use, import, licensing, offer
 for sale or sale of any CSS Products.
12. OPEN SOURCE SOFTWARE. Notwithstanding anything to the contrary, you
 are not licensed to (and you agree that you will not) integrate or use 
 this SDK with any Viral Open Source Software or otherwise take any action
 that could require disclosure, distribution, or licensing of all or any 
 part of the SDK in source code form, for the purpose of making derivative
 works, or at no charge. For the purposes of this Section 12, “Viral Open
 Source Software” shall mean software licensed under the GNU General 
 Public License, the GNU Lesser General Public License, or any other 
 license terms that could require, or condition your use, modification, or
 distribution of such software on, the disclosure, distribution, or 
 licensing of any other software in source code form, for the purpose of
 making derivative works, or at no charge. Any violation of the foregoing
 provision shall immediately terminate all of your licenses and other 
 rights to the SDK granted under this Agreement.
13. WAIVER. None of the provisions of this License Agreement shall be 
deemed to have been waived by any act or acquiescence on the part of CSS, 
its agents or employees, but only by an instrument in writing signed by an 
officer of CSS.
14.  INTEGRATION. When conflicting language exists between this License 
Agreement and any other agreement included in the SDK, this License 
Agreement shall supersede. If either you or CSS employ attorneys to enforce
 any rights arising out of or relating to this License Agreement, the 
 prevailing party shall be entitled to recover reasonable attorneys’ fees. 
 You acknowledge that you have read this License Agreement, understand it
 and that it is the complete and exclusive statement of your agreement 
 with CSS that supersedes any prior agreement, oral or written, between 
 CSS and you with respect to the licensing of the SDK. No variation of 
 the terms of this License Agreement will be enforceable against CSS unless
 CSS gives its express consent, in writing signed by an officer of CSS. 
15.  GOVERNMENT LICENSE.  If the SDK is licensed to the U.S. Government
 or any agency thereof, it will be considered to be “commercial computer 
 software” or “commercial computer software documentation,” as those terms 
 are used in 48 CFR § 12.212 or 48 CFR § 227.7202, and is being licensed 
 with only those rights as are granted to all other licensees as set forth 
 in this Agreement.*/

#include "management.h"
#include "httpclient.h"
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib/base64.h"
#include <errno.h>
#include "utils.h"
#include "logging.h"

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/pkcs12.h>
#include <wolfssl/openssl/rsa.h>
#else
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#endif

#define MODULE "management-"

static int get_management_config(const char* sessionToken, const char* jobId, const char* endpoint, \
		struct ConfigData* config, struct ManagementConfigResp** pManConf)
{
	#undef FUNCTION
	#define FUNCTION "get_management_config-"
	char* url = NULL;

	log_verbose("%s%sSending management config request: %s", MODULE, FUNCTION, jobId);
	struct CommonConfigReq* req = CommonConfigReq_new();
	req->JobId = strdup(jobId);
	req->SessionToken = strdup(sessionToken);

	char* jsonReq = CommonConfigReq_toJson(req);

	char* jsonResp = NULL;
	
	url = config_build_url(config, endpoint, true);

	int res = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, \
		config->ClientKey, config->ClientKeyPassword, jsonReq, &jsonResp);
	
	if(res == 0)
	{
		*pManConf = ManagementConfigResp_fromJson(jsonResp);
	}
	else
	{
		log_error("%s%sConfig retrieval failed with error code %d", MODULE, FUNCTION, res);
	}

	free(jsonReq);
	free(jsonResp);
	free(url);
	CommonConfigReq_free(req);

	return res;
}

static int send_management_job_complete(const char* sessionToken, const char* jobId, const char* endpoint, \
		struct ConfigData* config, int jobStatus, long auditId, const char* message, struct ManagementCompleteResp** pManComp)
{
	#undef FUNCTION
	#define FUNCTION "send_management_job_complete-"
	char* url = NULL;

	log_verbose("%s%sSending management complete request: %ld for session: %s", MODULE, FUNCTION, auditId, sessionToken);
	struct CommonCompleteReq* req = CommonCompleteReq_new();
	req->SessionToken = strdup(sessionToken);
	req->JobId = strdup(jobId);
	req->Status = jobStatus;
	req->AuditId = auditId;
	req->Message = strdup(message);

	char* jsonReq = CommonCompleteReq_toJson(req);

	char* jsonResp = NULL;

	url = config_build_url(config, endpoint, true);

	int res = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, \
		config->ClientKey, config->ClientKeyPassword, jsonReq, &jsonResp);
	if(res == 0)
	{
		*pManComp = ManagementCompleteResp_fromJson(jsonResp);
	}
	else
	{
		log_error("%s%sJob completion failed with error code %d", MODULE, FUNCTION, res);
	}

	free(jsonReq);
	free(jsonResp);
	free(url);
	CommonCompleteReq_free(req);

	return res;
}

static int add_cert_to_store(const char* storePath, const unsigned char* certBytes, int certLen, char** pMessage, enum AgentApiResultStatus* pStatus)
{
	#undef FUNCTION
	#define FUNCTION "add_cert_to_store-"
	int ret = 0;
	char* newThumb = NULL;
	X509* cert = NULL;

	// TODO - File locks
	FILE* fpRead = fopen(storePath, "r");
	if(!fpRead)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s%sUnable to open store at %s: %s", MODULE, FUNCTION, storePath, errStr);
		append_linef(pMessage, "Unable to open store at %s: %s", storePath, errStr);
		*pStatus = STAT_ERR;
	}
	else if(d2i_X509(&cert, &certBytes, certLen)) // Make sure we have an actual cert
	{
		newThumb = compute_thumbprint(cert);
		log_verbose("%s%sNew cert thumbprint: %s", MODULE, FUNCTION, newThumb);

		bool foundCert = false;
	
		char* name = NULL;
		char* header = NULL;
		unsigned char* data = NULL;
		long length = 0;
		while(!foundCert && PEM_read(fpRead, &name, &header, &data, &length))
		{
			X509* storeCert = NULL;

			const unsigned char* tempData = data; // Don't lose the pointer so it can be freed

			if(strcmp(name, "CERTIFICATE") == 0 && d2i_X509(&storeCert, &tempData, length))
			{
				char* thumb = compute_thumbprint(storeCert);
				if(strcasecmp(thumb, newThumb) == 0)
				{
					foundCert = true;
				}

				free(thumb);
			}

			OPENSSL_free(name);
			OPENSSL_free(header);
			OPENSSL_free(data);


			X509_free(storeCert);
		}

		log_verbose("%s%sFound cert: %s", MODULE, FUNCTION, (foundCert ? "yes" : "no"));

		if(fpRead)
		{
			fclose(fpRead);
			fpRead = NULL;
		}

		if(!foundCert)
		{
			ret = backup_file(storePath);
			if(ret != 0 && ret != ENOENT)
			{
				char* errStr = strerror(ret);
				log_error("%s%sUnable to backup store at %s: %s\n", MODULE, FUNCTION, storePath, errStr);
				append_linef(pMessage, "Unable to open store at %s: %s", storePath, errStr);
				*pStatus = STAT_ERR;
			}
			else
			{
				FILE* fpAdd = fopen(storePath, "a");
				if(!fpAdd)
				{
					ret = errno;
					char* errStr = strerror(errno);
					log_error("%s%sUnable to open store at %s: %s", MODULE, FUNCTION, storePath, errStr);
					append_linef(pMessage, "Unable to open store at %s: %s", storePath, errStr);
					*pStatus = STAT_ERR;
				}
				else
				{
					if(!PEM_write_X509(fpAdd, cert))
					{
						char errBuf[120];
						unsigned long errNum = ERR_peek_last_error();
						ERR_error_string(errNum, errBuf);
						log_error("%s%sUnable to write certificate to store: %s", MODULE, FUNCTION, errBuf);
						append_linef(pMessage, "Unable to write certificate to store: %s", errBuf);
						*pStatus = STAT_ERR;
					}

					if(fpAdd)
					{
						fclose(fpAdd);
					}
				}
			}
		}
		else
		{
			log_info("%s%sWarning: Certificate with thumbprint %s was already present in store %s", MODULE, FUNCTION, newThumb, storePath);
			append_linef(pMessage, "Warning: Certificate with thumbprint %s was already present in store %s", newThumb, storePath);
			*pStatus = STAT_WARN;
		}
	}
	else
	{
		log_error("%s%sInvalid certificate bytes", MODULE, FUNCTION);
		append_line(pMessage, "Invalid certificate bytes");
		*pStatus = STAT_ERR;
		ret = EINVAL;
	}

	if(fpRead)
	{
		fclose(fpRead);
		fpRead = NULL;
	}

	free(newThumb);
	X509_free(cert);

	return ret;
}

static bool prepare_cert_key_removal(FILE* fp, char** pBytesOut, int* pStoreLen, X509* searchCert, const char* password, char** pMessage, enum AgentApiResultStatus* pStatus)
{
	#undef FUNCTION
	#define FUNCTION "prepare_cert_key_removal-"
	bool didRemove = false;

	char* name = NULL;
	char* header = NULL;
	unsigned char* data = NULL;
	long length = 0;

	char* searchThumb = compute_thumbprint(searchCert);

	// Write the modified store into memory
	BIO* bio = BIO_new(BIO_s_mem());

	while(PEM_read(fp, &name, &header, &data, &length))
	{
		bool excludeFromNewStore = false;

		X509* cert = NULL;
		EVP_PKEY* key = NULL;
		const unsigned char* tempData = data; // Don't lose the pointer so it can be freed

		if(strcmp(name, "CERTIFICATE") == 0 && d2i_X509(&cert, &tempData, length))
		{
			char* thumb = compute_thumbprint(cert);

			if(strcasecmp(thumb, searchThumb) == 0)
			{
				excludeFromNewStore = true;
			}
			free(thumb);
		}
		else if(strcmp(name, "PRIVATE KEY") == 0 && d2i_AutoPrivateKey(&key, &tempData, length))
		{
			excludeFromNewStore = is_cert_key_match(searchCert, key);
		}
		else if(strcmp(name, "ENCRYPTED PRIVATE KEY") == 0)
		{
			BIO* keyBio = BIO_new_mem_buf(data, length);
			if(d2i_PKCS8PrivateKey_bio(keyBio, &key, NULL, (char*)(password ? password : "")))
			{
				excludeFromNewStore = is_cert_key_match(searchCert, key);
			}
			else
			{
				char errBuf[120];
				unsigned long errNum = ERR_peek_last_error();
				ERR_error_string(errNum, errBuf);
				log_error("%s%sUnable to decrypt private key: %s", MODULE, FUNCTION, errBuf);
				append_linef(pMessage, "Unable to decrypt private key: %s", errBuf);
				*pStatus = STAT_WARN;
			}
			BIO_free(keyBio);
		}

		if(!excludeFromNewStore)
		{
			PEM_write_bio(bio, name, header, data, length);
		}
		else
		{
			didRemove = true;
		}

		OPENSSL_free(name);
		OPENSSL_free(header);
		OPENSSL_free(data);
		X509_free(cert);
		EVP_PKEY_free(key);
	}

	if(didRemove)
	{
		// Copy data into non-OpenSSL structure for return
		char* tmp = NULL;
		*pStoreLen = BIO_get_mem_data(bio, &tmp);
		*pBytesOut = malloc(*pStoreLen);
		memcpy(*pBytesOut, tmp, *pStoreLen);
	}

	free(searchThumb);
	BIO_free(bio);

	return didRemove;
}

static int remove_cert_from_store(const char* storePath, const char* searchThumb, const char* keyPath, const char* password, char** pMessage, enum AgentApiResultStatus* pStatus)
{
	#undef FUNCTION
	#define FUNCTION "remove_cert_from_store-"
	int ret = 0;

	// TODO - File locks
	FILE* fpRead = fopen(storePath, "r");
	if(!fpRead)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s%sUnable to read store at %s: %s", MODULE, FUNCTION, storePath, errStr);
		append_linef(pMessage, "Unable to read store at %s: %s", storePath, errStr);
		*pStatus = STAT_ERR;
	}
	else
	{
		X509* foundCert = NULL;
		char* name = NULL;
		char* header = NULL;
		unsigned char* data = NULL;
		long length = 0;

		// Read through once to find the cert
		while(PEM_read(fpRead, &name, &header, &data, &length))
		{
			X509* cert = NULL;
			const unsigned char* tempData = data; // Don't lose the pointer so it can be freed

			if(strcmp(name, "CERTIFICATE") == 0 && d2i_X509(&cert, &tempData, length))
			{
				char* thumb = compute_thumbprint(cert);
				if(strcasecmp(thumb, searchThumb) == 0)
				{
					foundCert = X509_dup(cert);
				}
				free(thumb);
			}

			OPENSSL_free(name);
			OPENSSL_free(header);
			OPENSSL_free(data);
			X509_free(cert);
		}

		log_verbose("%s%sFound cert: %s", MODULE, FUNCTION, (foundCert ? "yes" : "no"));

		if(foundCert)
		{
			fseek(fpRead, 0, SEEK_SET); // Rewind the file

			char* bytesOut = NULL;
			int storeLen;
			bool removedCert = prepare_cert_key_removal(fpRead, &bytesOut, &storeLen, foundCert, password, pMessage, pStatus);

			if(fpRead)
			{
				fclose(fpRead);
				fpRead = NULL;
			}

			if(removedCert && *pStatus != STAT_ERR)
			{
				ret = replace_file(storePath, bytesOut, storeLen, true);
				if(ret != 0)
				{
					char* errStr = strerror(ret);
					log_error("%s%sUnable to replace store at %s: %s", MODULE, FUNCTION, storePath, errStr);
					append_linef(pMessage, "Unable to replace store at %s: %s", storePath, errStr);
					*pStatus = STAT_ERR;
				}
			}

			if(keyPath && *pStatus != STAT_ERR)
			{
				log_verbose("%s%sChecking for keys to be removed from %s", MODULE, FUNCTION, keyPath);

				FILE* fpKey = fopen(keyPath, "r");
				if(!fpKey)
				{
					ret = errno;
					char* errStr = strerror(errno);
					log_error("%s%sUnable to read store at %s: %s", MODULE, FUNCTION, storePath, errStr);
					append_linef(pMessage, "Unable to read store at %s: %s", storePath, errStr);
					*pStatus = STAT_ERR;
				}
				else
				{
					char* keyBytesOut = NULL;
					int keyLen;
					bool removedKey = prepare_cert_key_removal(fpKey, &keyBytesOut, &keyLen, foundCert, password, pMessage, pStatus);

					if(fpKey)
					{
						fclose(fpKey);
						fpKey = NULL;
					}

					if(removedKey && *pStatus != STAT_ERR)
					{
						ret = replace_file(keyPath, keyBytesOut, keyLen, true);
						if(ret != 0)
						{
							char* errStr = strerror(ret);
							log_error("%s%sUnable to replace store at %s: %s", MODULE, FUNCTION, keyPath, errStr);
							append_linef(pMessage, "Unable to replace store at %s: %s", keyPath, errStr);
							*pStatus = STAT_ERR;
						}
					}
				}

				if(fpKey)
				{
					fclose(fpKey);
					fpKey = NULL;
				}
			}
		}
		else
		{
			log_info("%s%sWarning: Certificate with thumbprint %s was not found in store %s", MODULE, FUNCTION, searchThumb, storePath);
			append_linef(pMessage, "Warning: Certificate with thumbprint %s was not found in store %s", searchThumb, storePath);
			*pStatus = STAT_WARN;
		}

		if(fpRead)
		{
			fclose(fpRead);
			fpRead = NULL;
		}
	}

	return ret;
}

int cms_job_manage(struct SessionJob* jobInfo, struct ConfigData* config, char* sessionToken, char** chainJob)
{
	#undef FUNCTION
	#define FUNCTION "cms_job_manage-"
	int res = 0;
	struct ManagementConfigResp* manConf = NULL;
	char* statusMessage = strdup("");
	enum AgentApiResultStatus status = STAT_UNK;
	int returnable = 0;
	log_info("%s%sStarting inventory job %s", MODULE, FUNCTION, jobInfo->JobId);

	res = get_management_config(sessionToken, jobInfo->JobId, jobInfo->ConfigurationEndpoint, config, &manConf);

	if(res == 0 && manConf && AgentApiResult_log(manConf->Result, &statusMessage, &status))
	{
		if(manConf->JobCancelled)
		{
			returnable = 1;
			log_info("%s%sJob has been cancelled and will not be run", MODULE, FUNCTION);
		}
		else
		{
			long auditId = manConf->AuditId;
			log_verbose("%s%sAudit Id: %ld", MODULE, FUNCTION, auditId);

			int opType = manConf->Job.OperationType;
			switch(opType)
			{
			case OP_ADD:
				log_verbose("%s%smanagement-cms_job_manage-Add certificate operation", MODULE, FUNCTION);

				if(manConf->Job.PrivateKeyEntry)
				{
					const char* msg = "Adding a PFX is not supported at this time";
					log_verbose("%s%s%s", MODULE, FUNCTION, msg);
					status = STAT_ERR;
					append_line(&statusMessage, msg);
				}
				else
				{
					size_t certLen;
					unsigned char* certBytes = base64_decode(manConf->Job.EntryContents, -1, &certLen);
					res = add_cert_to_store(manConf->Job.StorePath, certBytes, certLen, &statusMessage, &status);
					free(certBytes);
				}
				break;
			case OP_REM:
				log_verbose("%s%sRemove certificate operation", MODULE, FUNCTION);
				res = remove_cert_from_store(manConf->Job.StorePath, manConf->Job.Alias, manConf->Job.PrivateKeyPath, manConf->Job.StorePassword, &statusMessage, &status);
				break;
			default:
				log_error("%s%sUnsupported operation type: %d", MODULE, FUNCTION, opType);
				append_linef(&statusMessage, "Unsupported operation type: %d", opType);
				status = STAT_ERR;
				break;
			}

			struct ManagementCompleteResp* manComp = NULL;
			res = send_management_job_complete(sessionToken, jobInfo->JobId, jobInfo->CompletionEndpoint, config, status+1, auditId, statusMessage, &manComp);
			if(manComp)
			{
				if(AgentApiResult_log(manComp->Result, NULL, NULL) && manComp->InventoryJob && chainJob)
				{
					*chainJob = strdup(manComp->InventoryJob);
				}
			}

			if(status >= STAT_ERR)
			{
				log_info("%s%sManagement job %s failed with error: %s", MODULE, FUNCTION, jobInfo->JobId, statusMessage);
			}
			else if(status == STAT_WARN)
			{
				log_info("%s%sManagement job %s completed with warning: %s", MODULE, FUNCTION, jobInfo->JobId, statusMessage);
			}
			else
			{
				log_info("%s%sManagement job %s completed successfully", MODULE, FUNCTION, jobInfo->JobId);
			}

			ManagementCompleteResp_free(manComp);
		}
	}

	ManagementConfigResp_free(manConf);
	free(statusMessage);

	return returnable;
}
