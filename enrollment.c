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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib/base64.h"
#include "enrollment.h"
#include "httpclient.h"
#include "utils.h"
#include "logging.h"
#include "csr.h"
#include "config.h"

#if defined(__WOLF_SSL__)
	#include "wolfssl_wrapper/wolfssl_wrapper.h"
#else
	#if defined(__OPEN_SSL__)
		#include "openssl_wrapper/openssl_wrapper.h"
	#else
		#if defined(__TPM__)
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

/**                                                                           */
/* Ask the platform to provide the details for the reenrollment job.          */
/*                                                                            */
/* @param  [Input] sessionToken The session GUID currently established between*/
/*                 the agent and the platform.                                */
/* @param  [Input] jobId is the GUID for the reenrollment job                 */
/* @param  [Input] endpoint is the relative URL to retrieve the config from   */
/* @param  [Output] pManConf is the enrollment job configuration response     */
/*                  from the platform.                                        */
/* @return http response                                                      */
/*                                                                            */
static int get_enroll_config(const char* sessionToken, const char* jobId, 
	const char* endpoint, struct EnrollmentConfigResp** pManConf)
{
	char* url = NULL;

	log_verbose("%s::%s(%d) : Sending enrollment config request: %s", LOG_INF, jobId);
	struct CommonConfigReq* req = CommonConfigReq_new();
    if (!req) {
        log_error("%s::%s(%d) : Error creating common config request structure", LOG_INF);
        return 999;
    }

	req->JobId = strdup(jobId);
	req->SessionToken = strdup(sessionToken);
	char* jsonReq = CommonConfigReq_toJson(req);
	char* jsonResp = NULL;
	url = config_build_url(endpoint, true);
	
	int res = http_post_json(url, ConfigData->Username, ConfigData->Password, 
		ConfigData->TrustStore, ConfigData->AgentCert, ConfigData->AgentKey, 
		ConfigData->AgentKeyPassword, jsonReq, &jsonResp
		,ConfigData->httpRetries,ConfigData->retryInterval); 

	if(res == 0) {
		*pManConf = EnrollmentConfigResp_fromJson(jsonResp);
	}
	else {
		log_error("%s::%s(%d) : Config retrieval failed with error code %d", 
			LOG_INF, res);
	}

	if (jsonReq) free(jsonReq);
	if (jsonResp) free(jsonResp);
	if (url) free(url);
	if (req) CommonConfigReq_free(req);

	return res;
} /* get_enroll_config */

/**                                                                           */
/* Send the reenrollment data to the platform.  This includes the CSR for     */
/* the platform to sign.                                                      */
/*                                                                            */
/* @param  [Input] sessionToken The session GUID currently established between*/
/*                 the agent and the platform.                                */
/* @param  [Input] jobId is the GUID for the reenrollment job                 */
/* @param  [Input] Endpoint is the relative URL to send the reenrollment to   */
/* @param  [Input] csr is the naked PEM for the CSR                           */
/* @param  [Output] pEnrResp is the response from the platform to the         */
/*                  reenrollment data sent by the agent.                      */
/* @return http response                                                      */
/*                                                                            */
static int send_enrollment(const char* sessionToken, const char* jobId, 
	const char* endpoint, const char* csr, 
	struct EnrollmentEnrollResp** pEnrResp)
{
	char* url = NULL;

	log_verbose("%s::%s(%d) : Sending enrollment request: %s", LOG_INF, jobId);
	struct EnrollmentEnrollReq* enrReq = calloc(1, sizeof(*enrReq));
    if (!enrReq) {
        log_error("%s::%s(%d) : Error creating enrollment request", LOG_INF);
        return 999;
    }

	enrReq->SessionToken = strdup(sessionToken);
	enrReq->JobId = strdup(jobId);
	enrReq->CSRText = strdup(csr);
	char* jsonReq = EnrollmentEnrollReq_toJson(enrReq);
	char* jsonResp = NULL;
    url = config_build_url(endpoint, true);

	int res = http_post_json(url, ConfigData->Username, ConfigData->Password, 
		ConfigData->TrustStore, ConfigData->AgentCert, ConfigData->AgentKey, 
		ConfigData->AgentKeyPassword, jsonReq, &jsonResp, 
		ConfigData->httpRetries, ConfigData->retryInterval); 

	if(res == 0) {
		*pEnrResp = EnrollmentEnrollResp_fromJson(jsonResp);
	} else {
		log_error("%s::%s(%d) : Enrollment failed with error code %d",	LOG_INF, res);
	}

	if (jsonReq) free(jsonReq);
	if (jsonResp) free(jsonResp);
	if (url) free(url);
	if (enrReq) EnrollmentEnrollReq_free(enrReq);

	return res;
} /* send_enrollment */

/**                                                                           */
/* Tell the platform that the reenrollment job has completed.                 */
/*                                                                            */
/*                                                                            */
/* @param  [Input] sessionToken The session GUID currently established between*/
/*                 the agent and the platform.                                */
/* @param  [Input] jobId is the GUID for the reenrollment job                 */
/* @param  [Input] Endpoint is the relative URL to send the complete to       */
/* @param  [Input] jobStatus is an enum JobCompleteStatus result              */
/* @param  [Input] auditId is the audit number from the platform              */
/* @param  [Input] message contains details info to send to the platform      */
/*                 typically associated with errors encountered during the    */
/*                 reenrollment job                                           */
/* @param  [Output] pEnrComp is the response from the platform to the         */
/*                  reenrollment complete message sent by the agent.          */
/* @return http response                                                      */
/*                                                                            */
static int send_enroll_job_complete(const char* sessionToken, const char* jobId,
 const char* endpoint, int jobStatus, long auditId, const char* message, 
 struct EnrollmentCompleteResp** pEnrComp)
{
	char* url = NULL;

	log_verbose("%s::%s(%d) : Sending enrollment complete request: %ld for"
		" session: %s", LOG_INF, auditId, sessionToken);
	struct CommonCompleteReq* req = CommonCompleteReq_new();
    if (!req) {
        log_error("%s::%s(%d) : Error creating common complete request structure", LOG_INF);
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

	if(res == 0) {
		*pEnrComp = EnrollmentCompleteResp_fromJson(jsonResp);
	} else {
		log_error("%s::%s(%d) : Job completion failed with error code %d", LOG_INF, res);
	}

	if (jsonReq) free(jsonReq);
	if (jsonResp) free(jsonResp);
	if (url) free(url);
	if (req) CommonCompleteReq_free(req);

	return res;
} /* send_enroll_job_complete */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**                                                                           */
/* The control flow for a reenrollment job.  This flow consists of:           */
/*     1.) Ask the platform for the job configuration details.                */
/*     2.) Generate a keypair                                                 */
/*     3.) Create a CSR                                                       */
/*     4.) Send that information to the platform.                             */
/*     5.) If there is a cert that comes back:                                */
/*              a.) Store the private key                                     */
/*              b.) Store the cert                                            */
/*     6.) Tell the platform we have finished the job                         */
/*                                                                            */
/* @param  [Input] jobInfo is the basic job id and call-in endpoint           */
/* @param  [Input] sessionToken is the current session GUID                   */
/* @param  [Output] the job to run next (provided by the platform)            */
/* @return 0 if job is finished                                               */
/*         1 if job is canceled                                               */
/*                                                                            */
int cms_job_enroll(struct SessionJob* jobInfo, char* sessionToken, 
	char** chainJob)
{
	int res = 0;
	int returnable = 0;
	struct EnrollmentConfigResp* enrConf = NULL;
	char* statusMessage = strdup("");
	enum AgentApiResultStatus status = STAT_UNK;

	log_info("%s::%s(%d) : Starting enrollment job %s", 
		LOG_INF, jobInfo->JobId);

	res = get_enroll_config(sessionToken, jobInfo->JobId, 
		jobInfo->ConfigurationEndpoint, &enrConf);

	log_verbose("%s::%s(%d) : KeyType: %s", LOG_INF, enrConf->KeyType);
	log_verbose("%s::%s(%d) : Store to reenroll = %s", 
		LOG_INF, enrConf->StorePath);

	/* Validate returned data */
	if (enrConf)
	{
		bool failed = false;
		/* Verify the target store isn't a directory */
		if (is_directory(enrConf->StorePath))
		{
			log_error("%s::%s(%d) : The store path must be a file and"
				" not a directory.", LOG_INF);
			append_linef(&statusMessage, "The store path must be a file"
				" and not a directory.");
			failed = true;
		}
		/* Verify the target store isn't the Agent store */
		if (enrConf->StorePath)
		{
			if (0 == strcasecmp(ConfigData->AgentCert, enrConf->StorePath))
			{
				
				log_warn("%s::%s(%d) : Attempting to re-enroll the agent "
					"cert is not allowed.", LOG_INF);
				append_linef(&statusMessage, "Attempting to re-enroll the "
					"agent cert is not allowed.");
				failed = true;
			}
		}
		/* Send failure to platform */
		if (failed)
		{
			struct EnrollmentCompleteResp* enrComp = NULL;
			send_enroll_job_complete(sessionToken, jobInfo->JobId, 
				jobInfo->CompletionEndpoint, STAT_ERR, enrConf->AuditId, 
				statusMessage, &enrComp);
			EnrollmentCompleteResp_free(enrComp);
			goto exit;
		}
	}
	else
	{
		log_error("%s::%s(%d) : Error, no enrollment configuration "
			"returned by platform", LOG_INF);
		goto exit;
	}

	if(	res == 0 && 
		AgentApiResult_log(enrConf->Result, &statusMessage, &status) )
	{
		if(enrConf->JobCancelled)
		{
			returnable = 1;
			log_info("%s::%s(%d) : Job has been cancelled and will not be run", 
				LOG_INF);
		}
		else
		{
			char* csrString = NULL;
			struct EnrollmentEnrollResp* enrResp = NULL;
			struct EnrollmentCompleteResp* enrComp = NULL;

			long auditId = enrConf->AuditId;
			log_verbose("%s::%s(%d) : Audit Id: %ld", LOG_INF, auditId);

			log_trace("%s::%s(%d) : Checking for supplied entropy from"
				" the platform", LOG_INF);
			if (enrConf->Entropy) 
			{
				if((0 != strcasecmp("",enrConf->Entropy)) && 
				   (0 < strlen(enrConf->Entropy)))
				{
					log_verbose("%s::%s(%d) : Seeding RNG with provided"
						" entropy", LOG_INF);
					ssl_seed_rng(enrConf->Entropy);
				}
			}

			if(status < STAT_ERR)
			{
				/* Generate the keypair and store it in a temp location in */
				/* the SSL wrapper function */
			#if defined(__TPM__)
				if ( (NULL == enrConf->PrivateKeyPath) ||
				     (0 == strcasecmp("",enrConf->PrivateKeyPath)) ) 
				{
					log_error("%s::%s(%d) : A TPM requires a PrivateKeyPath", 
						LOG_INF);
					status = STAT_ERR;
					append_linef(&statusMessage, "%s::%s(%d) : A TPM "
						"requires a PrivateKeyPath", LOG_INF);
				}
				if ( !(generate_keypair(enrConf->KeyType, enrConf->KeySize, 
					enrConf->PrivateKeyPath)) )
			#else
				if( !(generate_keypair(enrConf->KeyType, enrConf->KeySize)) )
			#endif
				{
					log_error("%s::%s(%d) : Unable to generate key pair "
						"with type %s and length %d", LOG_INF, enrConf->KeyType,
						 enrConf->KeySize);
					status = STAT_ERR;
					append_linef(&statusMessage, "Unable to generate key "
						"pair with type %s and length %d", enrConf->KeyType, 
						enrConf->KeySize);
				}
			}

			if(status < STAT_ERR)
			{
				/* Generate a CSR based on the keypair in the wrapper */
				size_t csrLen; 
				log_trace("%s::%s(%d) : Generating CSR", LOG_INF);
				csrString = ssl_generate_csr(enrConf->Subject, &csrLen, 
					&statusMessage); 
				if(!csrString)
				{
					log_error("%s::%s(%d) : Out of memory", LOG_INF);
					append_linef(&statusMessage, "%s::%s(%d) : Out of memory", 
						LOG_INF);
					status = STAT_ERR;
				}
				else
				{
					log_verbose("%s::%s(%d) : Successfully created CSR", 
						LOG_INF);
				}
			}

			if(status < STAT_ERR)
			{
				/* Send the CSR to the Platform for signing */
				res = send_enrollment(sessionToken, jobInfo->JobId, 
					enrConf->EnrollEndpoint, csrString, &enrResp);
				if(res == 0 && enrResp)
				{
					AgentApiResult_log(enrResp->Result, &statusMessage, &status);
				}
				else
				{
					log_error("%s::%s(%d) : Enrollment failed with error"
						" code %d", LOG_INF, res);
					status = STAT_ERR;
					append_linef(&statusMessage, "Enrollment failed with "
						"error code %d", res);
				}
			}

			if(status < STAT_ERR && enrResp && enrResp->Certificate)
			{
				/* Save the temporary keypair (stored in the SSL wrapper) */
				/* into a location */
				res = save_cert_key(enrConf->StorePath, enrConf->PrivateKeyPath,
					enrConf->StorePassword, enrResp->Certificate, 
					&statusMessage, &status);
			}

			/* Send the normal job complete */
			res = send_enroll_job_complete(sessionToken, jobInfo->JobId, 
				jobInfo->CompletionEndpoint, status+1, auditId, 
				statusMessage, &enrComp);

#if defined(__RUN_CHAIN_JOBS__)
			if(enrComp)
			{
				if(	AgentApiResult_log(enrComp->Result, NULL, NULL) && 
					enrComp->InventoryJob && 
					chainJob)
				{
					*chainJob = strdup(enrComp->InventoryJob);
				}
			}
#endif

			if(status >= STAT_ERR) 
			{
				log_info("%s::%s(%d) : Enrollment job %s failed with error: %s",
					LOG_INF, jobInfo->JobId, statusMessage);
			}
			else if(status == STAT_WARN) 
			{
				log_warn("%s::%s(%d) : Enrollment job %s completed with"
					" warning: %s", LOG_INF, jobInfo->JobId, statusMessage);
			}
			else 
			{
				log_info("%s::%s(%d) : Enrollment job %s completed "
					"successfully", LOG_INF, jobInfo->JobId);
			}

			if (csrString)
			{
				free(csrString);
			}
			if (enrResp)
			{
				EnrollmentEnrollResp_free(enrResp);
			}
			if (enrComp)
			{
				EnrollmentCompleteResp_free(enrComp);
			}
		}
	}

exit:
	if (enrConf)
	{
		EnrollmentConfigResp_free(enrConf);
	}
	if (statusMessage)
	{
		free(statusMessage);
	}

	return returnable;
} /* cms_job_enroll */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/