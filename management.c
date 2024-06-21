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
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************* LOCAL GLOBAL VARIABLES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* Ask the platform for the detailed configuration for the management job     */
/*                                                                            */
/* @param  - [Input] sessionToken = the GUID for the curl session             */
/* @param  - [Input] jobId = the platform's GUID for this job                 */
/* @param  - [Input] endpoint = the relative URL to hit for the config request*/
/* @param  - [Output] pManConf = The platform's response is placed into this  */
/* @return - success : 0                                                      */
/*           failure : an HTTP response code                                  */
/*                                                                            */
static int get_management_config(const char* sessionToken, const char* jobId, 
	const char* endpoint, struct ManagementConfigResp** pManConf)
{
	char* url = NULL;

	log_verbose("%s::%s(%d) : Sending management config request: %s", LOG_INF, jobId);
	struct CommonConfigReq* req = CommonConfigReq_new();
    if (!req) {
        log_error("%s::%s(%d) : Error creating new request structure", LOG_INF);
        return 999;
    }
	req->JobId = strdup(jobId);
	req->SessionToken = strdup(sessionToken);

	char* jsonReq = CommonConfigReq_toJson(req);

	char* jsonResp = NULL;
	
	url = config_build_url(endpoint, true);

	int res = http_post_json(url, ConfigData->Username, ConfigData->Password, 
		ConfigData->TrustStore, ConfigData->AgentCert, ConfigData->AgentKey, 
		ConfigData->AgentKeyPassword, jsonReq, &jsonResp, 
		ConfigData->httpRetries,ConfigData->retryInterval); 
	
	if(res == 0) {
		*pManConf = ManagementConfigResp_fromJson(jsonResp);
	} else {
		log_error("%s::%s(%d) : Config retrieval failed with error code %d", LOG_INF, res);
	}

	if (jsonReq) free(jsonReq);
	if (jsonResp) free(jsonResp);
	if (url) free(url);
	if (req) CommonConfigReq_free(req);

	return res;
} /* get_management_config */

/**                                                                           */
/* Send the job status (success/failure) and any associated data to the       */
/* platform.                                                                  */
/*                                                                            */
/* @param  - [Input] sessionToken = the GUID for the curl session             */
/* @param  - [Input] jodId = the platform GUID reference for the job          */
/* @param  - [Input] endpoint = the                                           */
/*                                                                            */
static int send_management_job_complete(const char* sessionToken, 
	const char* jobId, const char* endpoint, int jobStatus, long auditId, 
	const char* message, struct ManagementCompleteResp** pManComp)
{
	char* url = NULL;

	log_verbose("%s::%s(%d) : Sending management complete request: %ld "
		"for session: %s", LOG_INF, auditId, sessionToken);
	struct CommonCompleteReq* req = CommonCompleteReq_new();
    if (!req) {
        log_error("%s::%s(%d) : Error creating new request structure", LOG_INF);
        return 999;
    }

	req->SessionToken = strdup(sessionToken);
	req->JobId = strdup(jobId);
	req->Status = jobStatus;
	req->AuditId = auditId;
	req->Message = strdup(message);

	char* jsonReq = CommonCompleteReq_toJson(req);

	char* jsonResp = NULL;

	url = config_build_url(endpoint, true);

	int res = http_post_json(url, ConfigData->Username, ConfigData->Password, 
		ConfigData->TrustStore, ConfigData->AgentCert, ConfigData->AgentKey, 
		ConfigData->AgentKeyPassword, jsonReq, &jsonResp, 
		ConfigData->httpRetries,ConfigData->retryInterval); 
	
	if(res == 0)
	{
		*pManComp = ManagementCompleteResp_fromJson(jsonResp);
	}
	else
	{
		log_error("%s::%s(%d) : Job completion failed with error code %d", 
			LOG_INF, res);
	}

    if (jsonReq) free(jsonReq);
    if (jsonResp) free(jsonResp);
    if (url) free(url);
    if (req) CommonCompleteReq_free(req);

	return res;
} /* send_management_job_complete */

/**                                                                           */
/* Perform the management job to add the certificate downloaded from the      */
/* platform into a certificate store.                                         */
/*                                                                            */
/* @param  - [Input] : storePath = the store's location                       */
/* @param  - [Input] : certASCII = the naked PEM                              */
/* @param  - [Output] : pMessage = An array of messages we want to pass back  */
/*                                 to the calling function                    */
/* @param  - [Output] : pStatus = the result of the add operation             */
/* @return - success : 0                                                      */
/*         - failure : any other integer                                      */
/*                                                                            */
static int add_cert_to_store(const char* storePath, const char* certASCII, 
	char** pMessage, enum AgentApiResultStatus* pStatus)
{
	int ret = 0;
	int i;
	bool foundCert;
	PemInventoryItem* certToAdd = NULL;
	PemInventoryList* pemList = NULL;

	/* 1.) Convert the cert to a PemInventoryItem, */
	/*     which has a cert & thumbprint */

	log_trace("%s::%s(%d) : Creating a new PemInventoryItem for certificate", 
		LOG_INF);
	if ( !ssl_PemInventoryItem_create(&certToAdd, certASCII) )
	{
		log_error("%s::%s(%d) : Error creating cert thumbprint or invalid cert",
			LOG_INF);
		append_linef(pMessage, "%s::%s(%d) : Error creating cert thumbprint"
			" or invalid cert", LOG_INF);
		*pStatus = STAT_ERR;
		return -1;
	}
	log_trace("%s::%s(%d) : New certificate has a thumbprint of %s", 
		LOG_INF, certToAdd->thumbprint_string);
	
	/* 2.) Read all the certs in the cert store */
	log_trace("%s::%s(%d) : Reading cert store %s's inventory", 
		LOG_INF, storePath);
	if ( 0 != ssl_read_store_inventory(storePath, NULL, &pemList) )
	{
		log_error("%s::%s(%d) : Error reading PEM store at %s", 
			LOG_INF, storePath);
		append_linef(pMessage, "%s::%s(%d) : Error reading PEM store at %s", 
			LOG_INF, storePath);
		if ( certToAdd )
		{
			PemInventoryItem_free(certToAdd);
		}
		if ( pemList )
		{
			PemInventoryList_free(pemList);
		}
		*pStatus = STAT_ERR;
		return -1;
	}
	log_trace("%s::%s(%d) : Found %d certs in store", 
		LOG_INF, pemList->item_count);
	for(i = 0; pemList->item_count > i; i++)
	{
		log_trace("%s::%s(%d) : Thumbprint #%d found: %s", 
			LOG_INF, i, pemList->items[i]->thumbprint_string);
	}

	/* 3.) Does the cert exist in the store already? */
	foundCert = false;
	i = 0;
	log_trace("%s::%s(%d) : Checking if cert to add is already in the store", 
		LOG_INF);
	while ( (pemList->item_count > i) && 
		    (false == foundCert) && 
		    (certToAdd) )
	{
		log_trace("%s::%s(%d) : comparing thubmprints\n%s\n%s",
			LOG_INF, certToAdd->thumbprint_string, 
			pemList->items[i]->thumbprint_string);
		if ( 0 == strcasecmp(certToAdd->thumbprint_string, 
			                 pemList->items[i]->thumbprint_string) )
		{
			foundCert = true;
		}
		i++;
	}

	log_verbose("%s::%s(%d) : Found cert: %s", 
		LOG_INF, (foundCert ? "yes" : "no"));

	/* 4.) If the cert doesn't exist, add it too the store */	
	if( false == foundCert )
	{
		log_trace("%s::%s(%d) : Adding cert with thumbprint %s to store %s", 
			LOG_INF, certToAdd->thumbprint_string, storePath);
		if ( !ssl_Store_Cert_add(storePath, certASCII) )
		{
			log_error("%s::%s(%d) Error writing cert to store", LOG_INF);
			append_linef(pMessage, "%s::%s(%d) Error writing cert to store", 
				LOG_INF);
			*pStatus = STAT_ERR;
			ret = -1;
		}
		else
		{
			log_verbose("%s::%s(%d) Certificate successfully written to store", 
				LOG_INF);
			*pStatus = STAT_SUCCESS;
			ret = 0;
		}
	}
	else
	{
		log_warn("%s::%s(%d) : WARNING: Certificate with thumbprint %s "
			"was already present in store %s", LOG_INF, 
			certToAdd->thumbprint_string, storePath);
		append_linef(pMessage, "%s::%s(%d) : WARNING: Certificate with "
			"thumbprint %s was already present in store %s", 
			LOG_INF, certToAdd->thumbprint_string, storePath);
		*pStatus = STAT_WARN;
		ret = 0;
	}

	/* 5.) Cleanup */
	if ( certToAdd ) PemInventoryItem_free(certToAdd);
	if ( pemList ) PemInventoryList_free(pemList);
	
	return ret;
} /* add_cert_to_store */

/**                                                                           */
/* Remove a certificate (and any associated stored key) from a store          */
/*                                                                            */
/* @param  - [Input] : storePath = the location of the store                  */
/* @param  - [Input] : searchThumb = the sha1 hash of the certificate to      */
/*                      remove                                                */
/* @param  - [Input] : keyPath = (optional) the path to the key for the       */
/*                      certificate. If NULL, the key is assumed to live      */
/*                      inside the store                                      */
/* @param  - [Input] : password = the password for an encrypted key           */
/* @param  - [Output] : pMessage = An array of messages we want to pass       */
/*                                 back to the calling function               */
/* @param  - [Output] : pStatus = The result of the certificate removal       */
/* @return - success : 0                                                      */
/*         - failure : Any other integer                                      */
/*                                                                            */
static int remove_cert_from_store(const char* storePath, 
	const char* searchThumb, const char* keyPath, const char* password, 
	char** pMessage, enum AgentApiResultStatus* pStatus)
{
	int ret = 0;

	if (!ssl_remove_cert_from_store(storePath, searchThumb, keyPath, password))
	{
		log_error("%s::%s(%d) : Unable to remove cert from store at %s", 
			LOG_INF, storePath);
		append_linef(pMessage, "Unable to remove cert from store at %s", 
			storePath);
		*pStatus = STAT_ERR;
	}
	return ret;
} /* remove_cert_from_store */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* The management job flow:                                                   */
/* 		1.) Ask the platform for the details on the managment job (get config)*/
/*		2.) Based on the response:                                            */
/*				a.) If the job was canceled, you finish                       */
/*				b.) If the job was an ADD, run the ADD workflow               */
/*				c.) If the job was a REMOVE, run the REMOVE workflow          */
/*		3.) Respond to the platform as to the job's success                   */
/*                                                                            */
/* @param  - [Input] : jobInfo = the details of the job from the platform     */
/* @param  - [Input] : sessionToken = the GUID for the curl session           */
/* @param  - [Input] : chainJob = any additional jobs required to run after   */
/*                                this one -- typically an Inventory job      */
/* @return - job was run : 0                                                  */
/*		   - job was canceled : 1                                             */
/*                                                                            */
int cms_job_manage(struct SessionJob* jobInfo, char* sessionToken, 
	char** chainJob)
{
	int res = 0;
	struct ManagementConfigResp* manConf = NULL;
	char* statusMessage = strdup("");
	enum AgentApiResultStatus status = STAT_UNK;
	int returnable = 0;
	log_info("%s::%s(%d) : Starting management job %s", LOG_INF, 
		jobInfo->JobId);

	res = get_management_config(sessionToken, jobInfo->JobId, 
		jobInfo->ConfigurationEndpoint, &manConf);

	/* Validate data */
	if (manConf)
	{
		bool failed = false;
		if (manConf->Job.StorePath)
		{
			/* Is the target store a directory and not a file? */
			if (is_directory(manConf->Job.StorePath))
			{
				log_error("%s::%s(%d) : The store path must be a file and "
					"not a directory.", LOG_INF);
				append_linef(&statusMessage, "The store path must be a file "
					"and not a directory.");
				failed = true;
			}
			/* Is the target store the Agent store? */
			if (0 == strcasecmp(ConfigData->AgentCert, manConf->Job.StorePath))
			{		
				log_warn("%s::%s(%d) : Attempting a Management job on the "
					"agent cert store is not allowed.", LOG_INF);
				append_linef(&statusMessage, "Attempting a Management job the"
					" agent cert store is not allowed.");
				failed = true;
			}
			/* Verify the target store exists */
			if (!file_exists(manConf->Job.StorePath))
			{
				log_warn("%s::%s(%d) : Attempting to manage a certificate"
					" store that does not exist yet.", LOG_INF);
				append_linef(&statusMessage, "Attempting to manage a "
					"certificate store that does not exist yet.");
				failed = true;
			}
		}
		else
		{
			log_error("%s::%s(%d) : Job doesn't contain a target store "
				"to manage.", LOG_INF);
			append_linef(&statusMessage, "Job doesn't contain a target "
				"store to manage.");
			failed = true;
		}
		/* if any test failed, then let the platform know about it. */
		if (failed) 
		{
			struct ManagementCompleteResp* manComp = NULL;
			send_management_job_complete(sessionToken, jobInfo->JobId, 
				jobInfo->CompletionEndpoint, STAT_ERR, manConf->AuditId, 
				statusMessage, &manComp);
			ManagementCompleteResp_free(manComp);
			goto exit;
		}
	}
	else 
	{
		log_error("%s::%s(%d) : No managment configuration was returned"
			" from the platform.", LOG_INF);
		goto exit;
	}

	/* Data ok, process job */
	if(res == 0 && AgentApiResult_log(manConf->Result, &statusMessage, &status))
	{
		if(manConf->JobCancelled)
		{
			returnable = 1;
			log_info("%s::%s(%d) : Job has been cancelled and will not be run",
				LOG_INF);
		}
		else
		{
			long auditId = manConf->AuditId;
			log_verbose("%s::%s(%d) : Audit Id: %ld", LOG_INF, auditId);

			int opType = manConf->Job.OperationType;
			switch(opType)
			{
			case OP_ADD:
				log_verbose("%s::%s(%d) : Add certificate operation", LOG_INF);

				if(manConf->Job.PrivateKeyEntry)
				{
					const char* msg = "Adding a PFX is not supported at"
					" this time";
					log_info("%s::%s(%d) :  %s", LOG_INF, msg);
					status = STAT_ERR;
					append_line(&statusMessage, msg);
				}
				else
				{
					log_info("%s::%s(%d) : Attempting to add certificate"
						" to the store:\n%s", LOG_INF, 
						manConf->Job.EntryContents);
					res = add_cert_to_store(manConf->Job.StorePath, 
						manConf->Job.EntryContents, &statusMessage, &status);
				}
				break;
			case OP_REM:
				log_verbose("%s::%s(%d) : Remove certificate operation", 
					LOG_INF);
				res = remove_cert_from_store(manConf->Job.StorePath, 
					manConf->Job.Alias, manConf->Job.PrivateKeyPath, 
					manConf->Job.StorePassword, &statusMessage, &status);
				break;
			default:
				log_error("%s::%s(%d) : Unsupported operation type: %d", 
					LOG_INF, opType);
				append_linef(&statusMessage, "Unsupported operation type: %d", 
					opType);
				status = STAT_ERR;
				break;
			}

			struct ManagementCompleteResp* manComp = NULL;
			res = send_management_job_complete(sessionToken, 
				jobInfo->JobId, jobInfo->CompletionEndpoint, status+1, 
				auditId, statusMessage, &manComp);
			/* NOTE: Removed chain job due to inventory job running twice */

			if(status >= STAT_ERR)
			{
				log_error("%s::%s(%d) : Management job %s failed with "
					"error: %s", LOG_INF, jobInfo->JobId, statusMessage);
			}
			else if(status == STAT_WARN)
			{
				log_warn("%s::%s(%d) : Management job %s completed"
					" with warning: %s",LOG_INF, jobInfo->JobId, statusMessage);
			}
			else
			{
				log_info("%s::%s(%d) : Management job %s completed"
					" successfully", LOG_INF, jobInfo->JobId);
			}	

			ManagementCompleteResp_free(manComp);
		}
	}

exit:
	ManagementConfigResp_free(manConf);
	free(statusMessage);

	return returnable;
} /* cms_job_manage */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/