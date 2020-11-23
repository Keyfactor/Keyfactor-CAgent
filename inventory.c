/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file inventory.c */
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

static int get_inventory_config(const char* sessionToken, const char* jobId, \
	const char* endpoint, struct ConfigData* config, \
	struct InventoryConfigResp** pInvConf)
{
	char* url = NULL;

	log_verbose("%s::%s(%d) : Sending inventory config request: %s", \
		__FILE__, __FUNCTION__, __LINE__, jobId);
	struct CommonConfigReq* req = CommonConfigReq_new();
	if ( NULL == req )
	{
		log_error("%s::%s(%d) : Out of memory in CommonConfigReq_new()", \
			 __FILE__, __FUNCTION__, __LINE__);
		return -1;
	}

	req->JobId = strdup(jobId);
	log_trace("%s::%s(%d) : Set job ID to %s", \
		__FILE__, __FUNCTION__, __LINE__, jobId);
	req->SessionToken = strdup(sessionToken);
	log_trace("%s::%s(%d) : Set session token to %s", \
		__FILE__, __FUNCTION__, __LINE__, sessionToken);

	char* jsonReq = CommonConfigReq_toJson(req);
	log_trace("%s::%s(%d) : Set Common Config Request to %s", \
		__FILE__, __FUNCTION__, __LINE__, jsonReq);
	
	char* jsonResp = NULL;

	url = config_build_url(config, endpoint, true);
	log_trace("%s::%s(%d) : Attempting a POST to %s", \
		__FILE__, __FUNCTION__, __LINE__, url);

	int res = http_post_json(url, config->Username, config->Password, \
		config->TrustStore, config->AgentCert, config->AgentKey, \
		config->AgentKeyPassword, jsonReq, &jsonResp \
		,config->httpRetries,config->retryInterval); // BL-20654

	if(res == 0)
	{
		*pInvConf = InventoryConfigResp_fromJson(jsonResp);
	}
	else
	{
		log_error("%s::%s(%d) : Config retrieval failed with error code %d", \
			__FILE__, __FUNCTION__, __LINE__, res);
	}
	
	free(jsonReq);
	free(jsonResp);
	free(url);
	CommonConfigReq_free(req);

	return res;
} /* get_inventory_config */

static int send_inventory_update(const char* sessionToken, const char* jobId, \
	const char* endpoint, struct ConfigData* config, \
	struct InventoryUpdateList* newInv, struct InventoryUpdateResp** pUpdResp)
{
	char* url = NULL;

	log_verbose("%s::%s(%d) : Sending inventory update request: %s", \
		__FILE__, __FUNCTION__, __LINE__, jobId);
	struct InventoryUpdateReq* updReq = calloc(1, sizeof(*updReq));
	updReq->SessionToken = strdup(sessionToken);
	updReq->JobId = strdup(jobId);
	updReq->Inventory = *newInv;

	char* jsonReq = InventoryUpdateReq_toJson(updReq);
	
	char* jsonResp = NULL;

	url = config_build_url(config, endpoint, true);

	int res = http_post_json(url, config->Username, config->Password, \
		config->TrustStore, config->AgentCert, config->AgentKey, \
		config->AgentKeyPassword, jsonReq, &jsonResp \
		,config->httpRetries,config->retryInterval); // BL-20654

	if(res == 0)
	{
		*pUpdResp = InventoryUpdateResp_fromJson(jsonResp);
	}
	else
	{
		log_error("%s::%s(%d) : Update submission failed with error code %d", \
			__FILE__, __FUNCTION__, __LINE__, res);
	}
	
	free(jsonReq);
	free(jsonResp);
	free(url);
	InventoryUpdateReq_free(updReq);
	
	return res;
} /* send_inventory_update */

static int send_inventory_job_complete(const char* sessionToken, \
	const char* jobId, const char* endpoint, struct ConfigData* config, \
	int jobStatus, long auditId, const char* message, \
	struct CommonCompleteResp** pInvComp)
{
	char* url = NULL;

	log_verbose("%s::%s(%d) : Sending inventory complete request: "
		        "%ld for session: %s",\
		 		__FILE__, __FUNCTION__, __LINE__, auditId, sessionToken);

	struct CommonCompleteReq* req = CommonCompleteReq_new();
	req->SessionToken = strdup(sessionToken);
	req->JobId = strdup(jobId);
	req->Status = jobStatus;
	req->AuditId = auditId;
	req->Message = strdup(message);

	char* jsonReq = CommonCompleteReq_toJson(req);
	
	char* jsonResp = NULL;

	url = config_build_url(config, endpoint, true);

	int res = http_post_json(url, config->Username, config->Password, \
		config->TrustStore, config->AgentCert, config->AgentKey, \
		config->AgentKeyPassword, jsonReq, &jsonResp \
		,config->httpRetries,config->retryInterval); // BL-20654

	if(res == 0)
	{
		*pInvComp = CommonCompleteResp_fromJson(jsonResp);
	}
	else
	{
		log_error("%s::%s(%d) : Job completion failed with error code %d", \
			__FILE__, __FUNCTION__, __LINE__, res);
	}
	
	free(jsonReq);
	free(jsonResp);
	free(url);
	CommonCompleteReq_free(req);

	return res;
} /* send_inventory_job_complete */

static void InventoryUpdateList_add(struct InventoryUpdateList* list, \
	struct InventoryUpdateItem* item)
{
	if(list && item)
	{
		list->items = realloc(list->items, \
			(list->count + 1) * sizeof(struct InventoryUpdateItem*));
		if (list->items)
		{
			list->items[list->count] = item;
			list->count++;
		}
		else
		{
			log_error("%s::%s(%d) : Out of memory", \
				__FILE__, __FUNCTION__, __LINE__);
		}
	}
	return;
} /* InventoryUpdateList_add */

/**
 * Free an inventory item list
 *
 * @param  - [Input] : list = the list to free
 * @return - none
 */
static void InventoryUpdateList_free(struct InventoryUpdateList* list)
{
	if (list)
	{
		for(int i = 0; i < list->count; i++)
		{
			if (list->items[i])
			{
				if(list->items[i]->Alias) free (list->items[i]->Alias);
				if(list->items[i]->Certificates)
				{
					for(int j = 0; j < list->items[i]->Certificates_count; j++)
					{
						if (list->items[i]->Certificates[j]) \
							free(list->items[i]->Certificates[j]);
					}
				}
				free(list->items[i]);
			}
		}
		if (list->items) free(list->items);
		free(list);
	}
	return;
} /* InventoryUpdateList_free */

/**
 * The the inventory job configuration returned a list of inventory items the
 * platform knows about.  The inventory item contains an "Alias" which is the
 * sha1 hash (aka: thumbprint) of the certificate.  It also passes this same 
 * information in the "Thumbprints" json structure.  
 *
 * Loop through the list of thumbprints pulled from the PEM store & compare them
 * to the thumbprints downloaded from the platform.  
 * If we find the thumbprint, then respond with a Status of "INV_STAT_UNCH".
 * If the PEM file contains a new certificate, respond with a status of 
 * "INV_STAT_ADD" and include the ASCII version of the certificate in the 
 * response for that cert.
 *
 * The platform then adds that certificate to its list for this machine & 
 * this store.
 *
 * NOTE: updateList is allocated in this function and must be freed by the
 *       calling function
 *
 * @param  - [Input] cmsItems - a list of all items the Platform knows about
 *                              in this data store
 * @param  - [Input] cmsItemCount - The # of items in the list cmsItems
 * @param  - [Input] fileItemList - a list of all items the Agent knows about
 *                                  in this data store
 * @param  - [Output] updateList - The list of items to ADD or DELETE from
 *                                  the platform
 * @return - success : 0
 *           failure : 0
 *
 */
static int compute_inventory_update(struct InventoryCurrentItem** cmsItems, \
	int cmsItemCount, struct PemInventoryList* fileItemList, \
	struct InventoryUpdateList** updateList)
{
	*updateList = calloc(1, sizeof(struct InventoryUpdateList));
	struct InventoryUpdateItem* updateItem = NULL;
	PemInventoryItem* currentPem = NULL;
	bool inFile = false;
	bool inCms = false;

	for(int i = 0; i < fileItemList->item_count; ++i)
	{
		currentPem = fileItemList->items[i];
		inCms = false;
		for(int j = 0; j < cmsItemCount; ++j)
		{
			/* if the thumbprints match, we don't have to do anything */
			if(
				strcasecmp(currentPem->thumbprint_string, cmsItems[j]->Alias) \
				== 0)
			{
				log_verbose("%s::%s(%d) : Alias %s is UNCHANGED", \
					__FILE__, __FUNCTION__, __LINE__, \
					currentPem->thumbprint_string);
				inCms = true;

				struct InventoryUpdateItem* updateItem = \
					calloc(1, sizeof(*updateItem));
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
			log_verbose("%s::%s(%d) : Alias %s is ADDED", \
			   __FILE__, __FUNCTION__, __LINE__, currentPem->thumbprint_string);

			updateItem = calloc(1, sizeof(*updateItem));
			updateItem->Alias = strdup(currentPem->thumbprint_string);
			updateItem->ItemStatus = INV_STAT_ADD;
			updateItem->PrivateKeyEntry = currentPem->has_private_key;
			updateItem->UseChainLevel = false;
			updateItem->Certificates = calloc(1,sizeof(char*));
			updateItem->Certificates[0] = strdup(currentPem->cert);
			updateItem->Certificates_count = 1;

			InventoryUpdateList_add(*updateList, updateItem);
		}
	}

	for(int m = 0; m < cmsItemCount; ++m)
	{
		inFile = false;
		for(int n = 0; n < fileItemList->item_count; ++n)
		{
			currentPem = fileItemList->items[n];

			if(
				strcasecmp(currentPem->thumbprint_string, cmsItems[m]->Alias) \
				== 0)
			{
				inFile = true;
				break;
			}
		}

		if(!inFile)
		{
			log_verbose("%s::%s(%d) : Alias %s is DELETED", \
				__FILE__, __FUNCTION__, __LINE__, cmsItems[m]->Alias);

			updateItem = calloc(1, sizeof(struct InventoryUpdateItem));
			updateItem->Alias = strdup(cmsItems[m]->Alias);
			updateItem->ItemStatus = INV_STAT_REM;
			updateItem->PrivateKeyEntry = false;
			updateItem->UseChainLevel = false;

			InventoryUpdateList_add(*updateList, updateItem);
		}
	}

	return 0;
} /* compute_inventory_update */

/**
 * Run the control flow for an inventory job.
 * The control flow is:
 *		1.) Ask the platform for the Inventory Job details (aka config)
 *      2.) Read the PEM inventory from the store requested.
 *      3.) Compare the thumbprints in #2 to the thumbprints downloaded in
 *          #1.
 *      4.) Inform the platform if:
 *               a.) The thumbprint is not found (Platform Deletes its cert)
 *               b.) A new thumbprint is found (Platform adds the cert)
 * For 4b) the cert is uploaded to the platform as a naked PEM
 *
 * @param  - [Input] : jobInfo = The ID and other params for the inventory job
 * @param  - [Input] : config = the config.json file decoded as a structure
 * @param  - [Input] : sessionToken = the session token for the Platform
 * @return - job not canceled by platform : 0
 *           job was canceled by platform : 1
 */
int cms_job_inventory(struct SessionJob* jobInfo, struct ConfigData* config, \
	char* sessionToken)
{
	int res = 0;
	struct InventoryConfigResp* invConf = NULL;
	char* statusMessage = strdup("");
	enum AgentApiResultStatus status = STAT_UNK;
	
	int returnable = 0;
	log_info("%s::%s(%d) : Starting inventory job %s", 
		__FILE__, __FUNCTION__, __LINE__, jobInfo->JobId);

	res = get_inventory_config(sessionToken, jobInfo->JobId, \
		jobInfo->ConfigurationEndpoint, config, &invConf);

	if( (res == 0) && \
		(invConf) && \
		AgentApiResult_log(invConf->Result, &statusMessage, &status) )
	{
		if(invConf->JobCancelled)
		{
			log_info("%s::%s(%d) : Job has been cancelled and will not be run",\
				__FILE__, __FUNCTION__, __LINE__);
			returnable = 1;
		}
		else
		{
			long auditId = invConf->AuditId;
			log_verbose("%s::%s(%d) : Audit Id: %ld", \
				__FILE__, __FUNCTION__, __LINE__, auditId);

			PemInventoryList* pemList = NULL;
			log_trace("%s::%s(%d) : Reading inventory store located at %s",
				__FILE__, __FUNCTION__, __LINE__, invConf->Job.StorePath);
			res = ssl_read_store_inventory(invConf->Job.StorePath, \
				invConf->Job.StorePassword, &pemList);

			if(res == 0)
			{
				struct InventoryUpdateList* updateList = NULL;
				compute_inventory_update(invConf->Job.Inventory, \
					invConf->Job.Inventory_count, pemList, &updateList);

				struct InventoryUpdateResp* updResp = NULL;
				res = send_inventory_update(sessionToken, jobInfo->JobId, \
					invConf->InventoryEndpoint, config, updateList, &updResp);
				if(res == 0 && updResp)
				{
				   AgentApiResult_log(updResp->Result, &statusMessage, &status);
				}

				if (updateList) InventoryUpdateList_free(updateList);
				if (updResp) InventoryUpdateResp_free(updResp);
			}
			else
			{
				status = STAT_ERR;
				append_line(&statusMessage, strerror(res));
			}

			if (pemList) {
				log_trace("%s::%s(%d) : Freeing pemList containing %d items", \
					__FILE__, __FUNCTION__, __LINE__, pemList->item_count);
				PemInventoryList_free(pemList);
			}

			struct CommonCompleteResp* invComp = NULL;
			res = send_inventory_job_complete(sessionToken, jobInfo->JobId, \
				jobInfo->CompletionEndpoint, config, (status + 1), auditId, \
				statusMessage, &invComp);
			if(res == 0 && invComp)
			{
				AgentApiResult_log(invComp->Result, NULL, NULL);
			}

			if(status >= STAT_ERR)
			{
				log_info("%s::%s(%d) : Inventory job %s failed with error: %s",\
				 __FILE__, __FUNCTION__, __LINE__, \
				 jobInfo->JobId, statusMessage);
			}
			else if(status == STAT_WARN)
			{
				log_info("%s::%s(%d) : Inventory job %s completed "
					     "with warning: %s", \
					     __FILE__, __FUNCTION__, __LINE__, \
					     jobInfo->JobId, statusMessage);
			}
			else
			{
				log_info("%s::%s(%d) : Inventory job %s completed "
					     "successfully", \
					     __FILE__, __FUNCTION__, __LINE__, jobInfo->JobId);
			}

			CommonCompleteResp_free(invComp);
		}
	}

	InventoryConfigResp_free(invConf);
	free(statusMessage);
	
	return returnable;
} /* cms_job_inventory */
