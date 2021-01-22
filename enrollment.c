/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file enrollment.c */
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
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * Ask the platform to provide the details for the reenrollment job.
 *
 * @param  [Input] sessionToken The session GUID currently established between
 *                 the agent and the platform.
 * @param  [Input] jobId is the GUID for the reenrollment job 
 * @param  [Input] endpoint is the relative URL to retrieve the config from
 * @param  [Input] config is the config.json file converted to a structure
 * @param  [Output] pManConf is the enrollment job configuration response
 *                  from the platform.
 * @return http response
 */
static int get_enroll_config(const char* sessionToken, const char* jobId, \
		const char* endpoint, struct ConfigData* config, \
		struct EnrollmentConfigResp** pManConf)
{
	char* url = NULL;

	log_verbose("%s::%s(%d) : Sending enrollment config request: %s", \
		__FILE__, __FUNCTION__, __LINE__, jobId);
	struct CommonConfigReq* req = CommonConfigReq_new();
	req->JobId = strdup(jobId);
	req->SessionToken = strdup(sessionToken);

	char* jsonReq = CommonConfigReq_toJson(req);

	char* jsonResp = NULL;

	url = config_build_url(config, endpoint, true);
	
	int res = http_post_json(url, config->Username, config->Password, \
		config->TrustStore, config->AgentCert, config->AgentKey, \
		config->AgentKeyPassword, jsonReq, &jsonResp
		,config->httpRetries,config->retryInterval); // BL-20654

	if(res == 0) {
		*pManConf = EnrollmentConfigResp_fromJson(jsonResp);
	}
	else {
		log_error("%s::%s(%d) : Config retrieval failed with error code %d", \
			__FILE__, __FUNCTION__, __LINE__, res);
	}

	free(jsonReq);
	free(jsonResp);
	free(url);
	CommonConfigReq_free(req);

	return res;
} /* get_enroll_config */

/**
 * Send the reenrollment data to the platform.  This includes the CSR for
 * the platform to sign.
 *
 * @param  [Input] sessionToken The session GUID currently established between
 *                 the agent and the platform.
 * @param  [Input] jobId is the GUID for the reenrollment job
 * @param  [Input] Endpoint is the relative URL to send the reenrollment to
 * @param  [Input] config is the config.json converted to a data structure
 * @param  [Input] csr is the naked PEM for the CSR
 * @param  [Output] pEnrResp is the response from the platform to the
 *                  reenrollment data sent by the agent.
 * @return http response
 */
static int send_enrollment(const char* sessionToken, const char* jobId, \
	const char* endpoint, struct ConfigData* config, const char* csr, \
	struct EnrollmentEnrollResp** pEnrResp)
{
	char* url = NULL;

	log_verbose("%s::%s(%d) : Sending enrollment request: %s", \
		__FILE__, __FUNCTION__, __LINE__, jobId);
	struct EnrollmentEnrollReq* enrReq = calloc(1, sizeof(*enrReq));
	enrReq->SessionToken = strdup(sessionToken);
	enrReq->JobId = strdup(jobId);
	enrReq->CSRText = strdup(csr);

	char* jsonReq = EnrollmentEnrollReq_toJson(enrReq);

	char* jsonResp = NULL;


	url = config_build_url(config, endpoint, true);

	int res = http_post_json(url, config->Username, config->Password, \
		config->TrustStore, config->AgentCert, config->AgentKey, \
		config->AgentKeyPassword, jsonReq, &jsonResp, \
		config->httpRetries, config->retryInterval); // BL-20654

	if(res == 0)
	{
		*pEnrResp = EnrollmentEnrollResp_fromJson(jsonResp);
	}
	else
	{
		log_error("%s::%s(%d) : Enrollment failed with error code %d", \
			__FILE__, __FUNCTION__, __LINE__, res);
	}

	free(jsonReq);
	free(jsonResp);
	free(url);
	EnrollmentEnrollReq_free(enrReq);

	return res;
} /* send_enrollment */

/**
 * Tell the platform that the reenrollment job has completed.
 *
 * 
 * @param  [Input] sessionToken The session GUID currently established between
 *                 the agent and the platform.
 * @param  [Input] jobId is the GUID for the reenrollment job
 * @param  [Input] Endpoint is the relative URL to send the complete to
 * @param  [Input] config is the config.json converted to a data structure
 * @param  [Input] jobStatus is an enum JobCompleteStatus result
 * @param  [Input] auditId is the audit number from the platform
 * @param  [Input] message contains details info to send to the platform
 *                 typically associated with errors encountered during the
 *                 reenrollment job
 * @param  [Output] pEnrComp is the response from the platform to the
 *                  reenrollment complete message sent by the agent.
 * @return http response
 */
static int send_enroll_job_complete(const char* sessionToken, \
	const char* jobId, const char* endpoint, struct ConfigData* config, \
	int jobStatus, long auditId, const char* message, \
	struct EnrollmentCompleteResp** pEnrComp)
{
	char* url = NULL;

	log_verbose("%s::%s(%d) : Sending enrollment complete "
		        "request: %ld for session: %s", \
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
		config->AgentKeyPassword, jsonReq, &jsonResp, \
		config->httpRetries,config->retryInterval); // BL-20654

	if(res == 0)
	{
		*pEnrComp = EnrollmentCompleteResp_fromJson(jsonResp);
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
} /* send_enroll_job_complete */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * The control flow for a reenrollment job.  This flow consists of:
 *     1.) Ask the platform for the job configuration details.
 *     2.) Generate a keypair
 *     3.) Create a CSR
 *     4.) Send that information to the platform.
 *     5.) If there is a cert that comes back:
 *              a.) Store the private key
 *              b.) Store the cert
 *     6.) Tell the platform we have finished the job
 *
 * @param  [Input] jobInfo is the basic job id and call-in endpoint
 * @param  [Input] config is the persistent/modifable config.json data
 * @param  [Input] sessionToken is the current session GUID
 * @param  [Output] the job to run next (provided by the platform)
 * @return 0 if job is finished
 *         1 if job is canceled
 */
int cms_job_enroll(struct SessionJob* jobInfo, struct ConfigData* config, \
	char* sessionToken, char** chainJob)
{
	int res = 0;
	int returnable = 0;
	struct EnrollmentConfigResp* enrConf = NULL;
	char* statusMessage = strdup("");
	enum AgentApiResultStatus status = STAT_UNK;

	log_info("%s::%s(%d) : Starting enrollment job %s", \
		__FILE__, __FUNCTION__, __LINE__, jobInfo->JobId);

	res = get_enroll_config(sessionToken, jobInfo->JobId, \
		jobInfo->ConfigurationEndpoint, config, &enrConf);

	log_verbose("%s::%s(%d) : KeyType: %s", \
		__FILE__, __FUNCTION__, __LINE__, enrConf->KeyType);
	log_verbose("%s::%s(%d) : Store to reenroll = %s", \
		__FILE__, __FUNCTION__, __LINE__, enrConf->StorePath);

	if(
		res == 0 && 
		enrConf && 
		AgentApiResult_log(enrConf->Result, &statusMessage, &status))
	{
		if(enrConf->JobCancelled)
		{
			returnable = 1;
			log_info("%s::%s(%d) : Job has been cancelled and will not be run",\
			 	__FILE__, __FUNCTION__, __LINE__);
		}
		else
		{
			char* csrString = NULL;
			struct EnrollmentEnrollResp* enrResp = NULL;
			struct EnrollmentCompleteResp* enrComp = NULL;

			long auditId = enrConf->AuditId;
			log_verbose("%s::%s(%d) : Audit Id: %ld", \
				__FILE__, __FUNCTION__, __LINE__, auditId);

			log_verbose("%s::%s(%d) : Seeding RNG with provided entropy", \
				__FILE__, __FUNCTION__, __LINE__);
			ssl_seed_rng(enrConf->Entropy);

			if(status < STAT_ERR)
			{
				/* Generate the keypair and store it in a temp location in */
				/* the SSL wrapper function */
			#if defined(__TPM__)
				if ( (NULL == enrConf->PrivateKeyPath) ||
				     (0 == strcasecmp("",enrConf->PrivateKeyPath)) ) {
					log_error("%s::%s(%d) : A TPM requires a PrivateKeyPath", \
						__FILE__, __FUNCTION__, __LINE__);
					status = STAT_ERR;
					append_linef(&statusMessage, "%s::%s(%d) : A TPM requires a PrivateKeyPath", \
						__FILE__, __FUNCTION__, __LINE__);
				}
				if ( !(generate_keypair(enrConf->KeyType, enrConf->KeySize, enrConf->PrivateKeyPath)) )
			#else
				if( !(generate_keypair(enrConf->KeyType, enrConf->KeySize)) )
			#endif
				{
					log_error("%s::%s(%d) : Unable to generate key pair "
						      "with type %s and length %d", \
							__FILE__, __FUNCTION__, __LINE__, \
							enrConf->KeyType, enrConf->KeySize);
					status = STAT_ERR;
					append_linef(&statusMessage, "Unable to generate key pair "
						         "with type %s and length %d", \
							      enrConf->KeyType, enrConf->KeySize);
				}
			}

			if(status < STAT_ERR)
			{
				/* Generate a CSR based on the keypair in the wrapper */
				size_t csrLen; // GM Specific
				csrString = ssl_generate_csr(enrConf->Subject, &csrLen, \
					&statusMessage); // GM Specific
				if(!csrString)
				{
					log_error("%s::%s(%d) : Out of memory", \
						__FILE__, __FUNCTION__, __LINE__);
					append_linef(&statusMessage, "%s::%s(%d) : Out of memory",
						__FILE__, __FUNCTION__, __LINE__);
					status = STAT_ERR;
				}
				else
				{
					log_trace("%s::%s(%d) : Successfully created CSR", \
						__FILE__, __FUNCTION__, __LINE__);
				}
			}

			if(status < STAT_ERR)
			{
				/* Send the CSR to the Platform for signing */
				res = send_enrollment(sessionToken, jobInfo->JobId, \
					enrConf->EnrollEndpoint, config, csrString, &enrResp);
				if(res == 0 && enrResp)
				{
					AgentApiResult_log(enrResp->Result, &statusMessage, \
						&status);
				}
				else
				{
					log_error("%s::%s(%d) : Enrollment failed with error "
						"code %d", \
						__FILE__, __FUNCTION__, __LINE__, res);
					status = STAT_ERR;
					append_linef(&statusMessage, "Enrollment failed with error "
						"code %d", res);
				}
			}

			if(status < STAT_ERR && enrResp && enrResp->Certificate)
			{
				/* Save the temporary keypair (stored in the SSL wrapper) */
				/* into a location */
				res = save_cert_key(enrConf->StorePath, \
					enrConf->PrivateKeyPath, enrConf->StorePassword, \
					enrResp->Certificate, &statusMessage, &status);
			}

			/* Send the normal job complete */
			res = send_enroll_job_complete(sessionToken, jobInfo->JobId, \
				jobInfo->CompletionEndpoint, config, status+1, auditId, \
				statusMessage, &enrComp);

			if(enrComp)
			{
				if(
					AgentApiResult_log(enrComp->Result, NULL, NULL) && \
					enrComp->InventoryJob && \
					chainJob)
				{
					*chainJob = strdup(enrComp->InventoryJob);
				}
			}

			if(status >= STAT_ERR) {
				log_info("%s::%s(%d) : Enrollment job %s failed with "
					"error: %s", \
					__FILE__, __FUNCTION__, __LINE__, \
					jobInfo->JobId, statusMessage);
			}
			else if(status == STAT_WARN) {
				log_info("%s::%s(%d) : Enrollment job %s completed with "
					"warning: %s", \
					__FILE__, __FUNCTION__, __LINE__, \
					jobInfo->JobId, statusMessage);
			}
			else {
				log_info("%s::%s(%d) : Enrollment job %s completed "
					"successfully", \
					__FILE__, __FUNCTION__, __LINE__, jobInfo->JobId);
			}

			free(csrString);
			EnrollmentEnrollResp_free(enrResp);
			EnrollmentCompleteResp_free(enrComp);
		}
	}

	EnrollmentConfigResp_free(enrConf);
	free(statusMessage);

	return returnable;
} /* cms_job_enroll */
