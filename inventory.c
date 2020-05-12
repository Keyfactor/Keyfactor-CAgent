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
#include "inventory.h"
#include <stdio.h>
#include "httpclient.h"
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "lib/base64.h"
#include "utils.h"
#include "constants.h"
#include "logging.h"
#include "config.h"

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/evp.h>
#else
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#endif

#define MODULE "inventory-"


struct PemInventoryItem
{
	X509* cert;
	char* thumbprint_string;
	bool has_private_key;
};
typedef struct PemInventoryItem PemInventoryItem;

PemInventoryItem* PemInventoryItem_new()
{
	#undef FUNCTION
	#define FUNCTION "PemInventoryItem_new-"
	PemInventoryItem* pem = (PemInventoryItem*)malloc(sizeof(PemInventoryItem));
	if(pem)
	{
		pem->cert = NULL;
		pem->thumbprint_string = NULL;
		pem->has_private_key = false;
	}
	return pem;
}

void PemInventoryItem_free(PemInventoryItem* pem)
{
	#undef FUNCTION
	#define FUNCTION "PemInventoryItem_free-"
	if(pem)
	{
		X509_free(pem->cert);
		pem->cert = NULL;
		free(pem->thumbprint_string);
		pem->thumbprint_string = NULL;
		
		free(pem);
	}
}

struct PemInventoryList
{
	int item_count;
	PemInventoryItem** items;
};
typedef struct PemInventoryList PemInventoryList;

static PemInventoryList* PemInventoryList_new()
{
	#undef FUNCTION
	#define FUNCTION "PemInventoryList_new-"
	PemInventoryList* list = (PemInventoryList*)malloc(sizeof(PemInventoryList));
	if(list)
	{
		list->item_count = 0;
		list->items = NULL;
	}
	return list;
}

static void PemInventoryList_free(PemInventoryList* list)
{
	#undef FUNCTION
	#define FUNCTION "PemInventoryList_free-"
	if(list && list->items)
	{
		int i = 0;
		for(i = 0; i < list->item_count; ++i)
		{
			PemInventoryItem_free(list->items[i]);
		}
		
		free(list);
	}
}

static void PemInventoryList_add(PemInventoryList* list, PemInventoryItem* item)
{
	#undef FUNCTION
	#define FUNCTION "PemInventoryList_add-"
	if(list && item)
	{
		list->items = realloc(list->items, (1 + list->item_count) * sizeof(PemInventoryItem*));
		list->items[list->item_count] = item;
		list->item_count++;
	}
}

static int get_inventory_config(const char* sessionToken, const char* jobId, const char* endpoint, \
		struct ConfigData* config, struct InventoryConfigResp** pInvConf)
{
	#undef FUNCTION
	#define FUNCTION "get_inventory_config-"
	char* url = NULL;

	log_verbose("%s%sSending inventory config request: %s", MODULE, FUNCTION, jobId);
	struct CommonConfigReq* req = CommonConfigReq_new();
	req->JobId = strdup(jobId);
	req->SessionToken = strdup(sessionToken);

	char* jsonReq = CommonConfigReq_toJson(req);
	
	char* jsonResp = NULL;

	url = config_build_url(config, endpoint, false);
	int res = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, \
		config->ClientKey, config->ClientKeyPassword, jsonReq, &jsonResp);

	if(res == 0)
	{
		*pInvConf = InventoryConfigResp_fromJson(jsonResp);
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

static int send_inventory_update(const char* sessionToken, const char* jobId, const char* endpoint, \
		struct ConfigData* config, struct InventoryUpdateList* newInv, struct InventoryUpdateResp** pUpdResp)
{
	#undef FUNCTION
	#define FUNCTION "send_inventory_update-"
	char* url = NULL;

	log_verbose("%s%sSending inventory update request: %s", MODULE, FUNCTION, jobId);
	struct InventoryUpdateReq* updReq = calloc(1, sizeof(struct InventoryUpdateReq));
	updReq->SessionToken = strdup(sessionToken);
	updReq->JobId = strdup(jobId);
	updReq->Inventory = *newInv;

	char* jsonReq = InventoryUpdateReq_toJson(updReq);
	
	char* jsonResp = NULL;

	url = config_build_url(config, endpoint, false);
	int res = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, \
		config->ClientKey, config->ClientKeyPassword, jsonReq, &jsonResp);
	if(res == 0)
	{
		*pUpdResp = InventoryUpdateResp_fromJson(jsonResp);
	}
	else
	{
		log_error("%s%sUpdate submission failed with error code %d", MODULE, FUNCTION, res);
	}
	
	free(jsonReq);
	free(jsonResp);
	free(url);
	InventoryUpdateReq_free(updReq);
	
	return res;
}

static int send_inventory_job_complete(const char* sessionToken, const char* jobId, const char* endpoint, \
		struct ConfigData* config, int jobStatus, long auditId, const char* message, struct CommonCompleteResp** pInvComp)
{
	#undef FUNCTION
	#define FUNCTION "send_inventory_job_complete-"
	char* url = NULL;

	log_verbose("%s%sSending inventory complete request: %ld for session: %s", MODULE, FUNCTION, auditId, sessionToken);

	struct CommonCompleteReq* req = CommonCompleteReq_new();
	req->SessionToken = strdup(sessionToken);
	req->JobId = strdup(jobId);
	req->Status = jobStatus;
	req->AuditId = auditId;
	req->Message = strdup(message);

	char* jsonReq = CommonCompleteReq_toJson(req);
	
	char* jsonResp = NULL;

	url = config_build_url(config, endpoint, false);
	int res = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, \
		config->ClientKey, config->ClientKeyPassword, jsonReq, &jsonResp);
	if(res == 0)
	{
		*pInvComp = CommonCompleteResp_fromJson(jsonResp);
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

static int read_store_inventory(const char* path, const char* password, PemInventoryList** pPemList)
{
	#undef FUNCTION
	#define FUNCTION "read_store_inventory-"
	int ret = 0;
	EVP_PKEY* keyList[20]; // TODO - Dynamic growth
	int keyCount = 0;

	FILE* fp = fopen(path, "r");
	if(!fp)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s%sUnable to open store at %s: %s", MODULE, FUNCTION, path, errStr);
	}
	else
	{
		char* name = NULL;
		char* header = NULL;
		unsigned char* data = NULL;
		long length = 0;
		*pPemList = PemInventoryList_new();
		log_verbose("%s%s%d items in PEM list", MODULE, FUNCTION, (*pPemList)->item_count);

		while(PEM_read(fp, &name, &header, &data, &length))
		{
			PemInventoryItem* pem = NULL;
			X509* cert = NULL;
			EVP_PKEY* key = NULL;
			const unsigned char* tempData = data; // Don't lose the pointer so it can be freed

			if(strcmp(name, "CERTIFICATE") == 0 && d2i_X509(&cert, &tempData, length))
			{
				pem = PemInventoryItem_new();

				char* thumb = compute_thumbprint(cert);
				log_verbose("%s%sThumbprint: %s", MODULE, FUNCTION, thumb);

				pem->cert = cert;
				pem->thumbprint_string = thumb;

				PemInventoryList_add(*pPemList, pem);
			}
			else if(strcmp(name, "PRIVATE KEY") == 0 && d2i_AutoPrivateKey(&key, &tempData, length))
			{
				log_verbose("%s%sEntry is a private key", MODULE, FUNCTION);
				keyList[keyCount++] = key;
			}
			else if(strcmp(name, "ENCRYPTED PRIVATE KEY") == 0)
			{
				BIO* keyBio = BIO_new_mem_buf(data, length);
				if(d2i_PKCS8PrivateKey_bio(keyBio, &key, NULL, (char*)(password ? password : "")))
				{
					log_verbose("%s%sEntry is an encrypted private key", MODULE, FUNCTION);
					keyList[keyCount++] = key;
				}
				else
				{
					char errBuf[120];
					unsigned long errNum = ERR_peek_last_error();
					ERR_error_string(errNum, errBuf);
					log_error("%s%sUnable to decrypt private key: %s", MODULE, FUNCTION, errBuf);
				}
				BIO_free(keyBio);
			}
			else
			{
				log_verbose("%s%sEntry is not a certificate, and will be skipped", MODULE, FUNCTION);
			}

			OPENSSL_free(name);
			OPENSSL_free(header);
			OPENSSL_free(data);
		}

		log_verbose("%s%sChecking for matching private keys", MODULE, FUNCTION);
		for(int i = 0; i < (*pPemList)->item_count; ++i)
		{
			log_verbose("%s%sThumbprint: %s", MODULE, FUNCTION, (*pPemList)->items[i]->thumbprint_string);

			for(int k = 0; k < keyCount; ++k)
			{
				if(is_cert_key_match((*pPemList)->items[i]->cert, keyList[k]))
				{
					log_verbose("%s%sFound matching cert and private key", MODULE, FUNCTION);
					(*pPemList)->items[i]->has_private_key = true;
				}
			}
		}

		for(int j = 0; j < keyCount; ++j)
		{
			EVP_PKEY_free(keyList[j]);
		}
	}

	if(fp)
	{
		fclose(fp);
	}

	return ret;
}

static void InventoryUpdateList_add(struct InventoryUpdateList* list, struct InventoryUpdateItem* item)
{
	#undef FUNCTION
	#define FUNCTION "InventoryUpdateList_add-"
	if(list && item)
	{
		list->items = realloc(list->items, (list->count + 1) * sizeof(struct InventoryUpdateItem*));
		list->items[list->count] = item;
		list->count++;
	}
}

static int compute_inventory_update(struct InventoryCurrentItem** cmsItems, int cmsItemCount, struct PemInventoryList* fileItemList, struct InventoryUpdateList** updateList)
{
	#undef FUNCTION
	#define FUNCTION "compute_inventory_update-"
	*updateList = calloc(1, sizeof(struct InventoryUpdateList));

	for(int i = 0; i < fileItemList->item_count; ++i)
	{
		PemInventoryItem* currentPem = fileItemList->items[i];
		bool inCms = false;
		for(int j = 0; j < cmsItemCount; ++j)
		{
			if(strcasecmp(currentPem->thumbprint_string, cmsItems[j]->Alias) == 0)
			{
				log_verbose("%s%sAlias %s is UNCHANGED", MODULE, FUNCTION, currentPem->thumbprint_string);
				inCms = true;

				struct InventoryUpdateItem* updateItem = calloc(1, sizeof(struct InventoryUpdateItem));
				updateItem->Alias = strdup(cmsItems[j]->Alias);
				updateItem->ItemStatus = INV_STAT_UNCH;
				updateItem->PrivateKeyEntry = cmsItems[j]->PrivateKeyEntry;
				updateItem->UseChainLevel = false;

				InventoryUpdateList_add(*updateList, updateItem);
				break;
			}
		}

		if(!inCms)
		{
			log_verbose("%s%sAlias %s is ADDED", MODULE, FUNCTION, currentPem->thumbprint_string);

			struct InventoryUpdateItem* updateItem = calloc(1, sizeof(struct InventoryUpdateItem));
			updateItem->Alias = strdup(currentPem->thumbprint_string);
			updateItem->ItemStatus = INV_STAT_ADD;
			updateItem->PrivateKeyEntry = currentPem->has_private_key;
			updateItem->UseChainLevel = false;

			unsigned char* certContent = NULL;
			int contLen = i2d_X509(currentPem->cert, &certContent);
			if(contLen > 0)
			{
				updateItem->Certificates = malloc(sizeof(char*));
				updateItem->Certificates[0] = base64_encode(certContent, contLen, false, NULL);
				updateItem->Certificates_count = 1;

				OPENSSL_free(certContent);
			}
			InventoryUpdateList_add(*updateList, updateItem);
		}
	}

	for(int m = 0; m < cmsItemCount; ++m)
	{
		bool inFile = false;
		for(int n = 0; n < fileItemList->item_count; ++n)
		{
			PemInventoryItem* currentPem = fileItemList->items[n];

			if(strcasecmp(currentPem->thumbprint_string, cmsItems[m]->Alias) == 0)
			{
				inFile = true;
				break;
			}
		}

		if(!inFile)
		{
			log_verbose("%s%sAlias %s is DELETED", MODULE, FUNCTION, cmsItems[m]->Alias);

			struct InventoryUpdateItem* updateItem = calloc(1, sizeof(struct InventoryUpdateItem));
			updateItem->Alias = strdup(cmsItems[m]->Alias);
			updateItem->ItemStatus = INV_STAT_REM;
			updateItem->PrivateKeyEntry = false;
			updateItem->UseChainLevel = false;

			InventoryUpdateList_add(*updateList, updateItem);
		}
	}

	return 0;
}

int cms_job_inventory(struct SessionJob* jobInfo, struct ConfigData* config, char* sessionToken)
{
	#undef FUNCTION
	#define FUNCTION "cms_job_inventory-"
	int res = 0;
	struct InventoryConfigResp* invConf = NULL;
	char* statusMessage = strdup("");
	enum AgentApiResultStatus status = STAT_UNK;
	int returnable = 0;
	log_info("%s%sStarting inventory job %s", MODULE, FUNCTION, jobInfo->JobId);

	res = get_inventory_config(sessionToken, jobInfo->JobId, jobInfo->ConfigurationEndpoint, config, &invConf);

	if(res == 0 && invConf && AgentApiResult_log(invConf->Result, &statusMessage, &status))
	{
		if(invConf->JobCancelled)
		{
			log_info("%s%sJob has been cancelled and will not be run", MODULE, FUNCTION);
			returnable = 1;
		}
		else
		{
			long auditId = invConf->AuditId;
			log_verbose("%s%sAudit Id: %ld", MODULE, FUNCTION, auditId);

			PemInventoryList* pemList = NULL;
			res = read_store_inventory(invConf->Job.StorePath, invConf->Job.StorePassword, &pemList);

			if(res == 0)
			{
				struct InventoryUpdateList* updateList = NULL;
				compute_inventory_update(invConf->Job.Inventory, invConf->Job.Inventory_count, pemList, &updateList);

				struct InventoryUpdateResp* updResp = NULL;
				res = send_inventory_update(sessionToken, jobInfo->JobId, invConf->InventoryEndpoint, config, updateList, &updResp);
				if(res == 0 && updResp)
				{
					AgentApiResult_log(updResp->Result, &statusMessage, &status);
				}

				InventoryUpdateResp_free(updResp);
			}
			else
			{
				status = STAT_ERR;
				append_line(&statusMessage, strerror(res));
			}

			PemInventoryList_free(pemList);


			struct CommonCompleteResp* invComp = NULL;
			res = send_inventory_job_complete(sessionToken, jobInfo->JobId, jobInfo->CompletionEndpoint, config, (status + 1), auditId, statusMessage, &invComp);
			if(res == 0 && invComp)
			{
				AgentApiResult_log(invComp->Result, NULL, NULL);
			}

			if(status >= STAT_ERR)
			{
				log_info("%s%sInventory job %s failed with error: %s", MODULE, FUNCTION, jobInfo->JobId, statusMessage);
			}
			else if(status == STAT_WARN)
			{
				log_info("%s%sInventory job %s completed with warning: %s", MODULE, FUNCTION, jobInfo->JobId, statusMessage);
			}
			else
			{
				log_info("%s%sInventory job %s completed successfully", MODULE, FUNCTION, jobInfo->JobId);
			}

			CommonCompleteResp_free(invComp);
		}
	}

	InventoryConfigResp_free(invConf);
	free(statusMessage);
	
	return returnable;
}
