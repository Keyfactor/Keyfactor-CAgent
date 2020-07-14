/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
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
	if ( NULL == req )
	{
		log_error("%s%s-Out of memory in CommonConfigReq_new()", MODULE, FUNCTION);
		return -1;
	}

	req->JobId = strdup(jobId);
	log_trace("%s%s-Set job ID to %s", MODULE, FUNCTION, jobId);
	req->SessionToken = strdup(sessionToken);
	log_trace("%s%s-Set session token to %s", MODULE, FUNCTION, sessionToken);

	char* jsonReq = CommonConfigReq_toJson(req);
	log_trace("%s%s-Set Common Config Request to %s", MODULE, FUNCTION, jsonReq);
	
	char* jsonResp = NULL;

	url = config_build_url(config, endpoint, true);
	log_trace("%s%s-Attempting a POST to %s", MODULE, FUNCTION, url);
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

	url = config_build_url(config, endpoint, true);
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

	url = config_build_url(config, endpoint, true);
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
