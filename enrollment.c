/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
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

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/rand.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/x509.h>
#else
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

static int get_enroll_config(const char* sessionToken, const char* jobId, const char* endpoint, \
		struct ConfigData* config, struct EnrollmentConfigResp** pManConf)
{
	char* url = NULL;

	log_verbose("enrollment-get_enroll_config-Sending enrollment config request: %s", jobId);
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
		*pManConf = EnrollmentConfigResp_fromJson(jsonResp);
	}
	else
	{
		log_error("enrollment-get_enroll_config-Config retrieval failed with error code %d", res);
	}

	free(jsonReq);
	free(jsonResp);
	free(url);
	CommonConfigReq_free(req);

	return res;
}

static int send_enrollment(const char* sessionToken, const char* jobId, const char* endpoint, \
		struct ConfigData* config, const char* csr, struct EnrollmentEnrollResp** pEnrResp)
{
	char* url = NULL;

	log_verbose("enrollment-send_enrollment-Sending enrollment request: %s", jobId);
	struct EnrollmentEnrollReq* enrReq = calloc(1, sizeof(struct EnrollmentEnrollReq));
	enrReq->SessionToken = strdup(sessionToken);
	enrReq->JobId = strdup(jobId);
	enrReq->CSRText = strdup(csr);

	char* jsonReq = EnrollmentEnrollReq_toJson(enrReq);

	char* jsonResp = NULL;


	url = config_build_url(config, endpoint, true);
	int res = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, \
		config->ClientKey, config->ClientKeyPassword, jsonReq, &jsonResp);
	if(res == 0)
	{
		*pEnrResp = EnrollmentEnrollResp_fromJson(jsonResp);
	}
	else
	{
		log_error("enrollment-send_enrollment-Enrollment submission failed with error code %d", res);
	}

	free(jsonReq);
	free(jsonResp);
	free(url);
	EnrollmentEnrollReq_free(enrReq);

	return res;
}

static int send_enroll_job_complete(const char* sessionToken, const char* jobId, const char* endpoint, \
		struct ConfigData* config, int jobStatus, long auditId, const char* message, struct EnrollmentCompleteResp** pEnrComp)
{
	char* url = NULL;

	log_verbose("enrollment-send_enroll_job_complete-Sending enrollment complete request: %ld for session: %s", auditId, sessionToken);
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
		*pEnrComp = EnrollmentCompleteResp_fromJson(jsonResp);
	}
	else
	{
		log_error("enrollment-send_enroll_job_complete-Job completion failed with error code %d", res);
	}

	free(jsonReq);
	free(jsonResp);
	free(url);
	CommonCompleteReq_free(req);

	return res;
}

static int seed_rng(const char* b64entropy)
{
	if(b64entropy)
	{
		size_t outLen;
		unsigned char* entBytes = base64_decode(b64entropy, -1, &outLen);
		RAND_seed(entBytes, outLen);

		return 0;
	}
	else
	{
		return -1;
	}
}

int cms_job_enroll(struct SessionJob* jobInfo, struct ConfigData* config, char* sessionToken, char** chainJob)
{
	int res = 0;
	int returnable = 0;
	struct EnrollmentConfigResp* enrConf = NULL;
	char* statusMessage = strdup("");
	enum AgentApiResultStatus status = STAT_UNK;

	log_info("enrollment-cms_job_enroll-Starting enrollment job %s", jobInfo->JobId);

	res = get_enroll_config(sessionToken, jobInfo->JobId, jobInfo->ConfigurationEndpoint, config, &enrConf);

	log_verbose("KeyType: %s", enrConf->KeyType);
	log_verbose("PrivateKeyPath: %s", enrConf->PrivateKeyPath);

	if(res == 0 && enrConf && AgentApiResult_log(enrConf->Result, &statusMessage, &status))
	{
		if(enrConf->JobCancelled)
		{
			returnable = 1;
			log_info("enrollment-cms_job_enroll-Job has been cancelled and will not be run\n");
		}
		else
		{
			X509_NAME* subjName = NULL;
			EVP_PKEY* keyPair = NULL;
			char* csrString = NULL;
			struct EnrollmentEnrollResp* enrResp = NULL;
			struct EnrollmentCompleteResp* enrComp = NULL;

			long auditId = enrConf->AuditId;
			log_verbose("enrollment-cms_job_enroll-Audit Id: %ld", auditId);

			log_verbose("enrollment-cms_job_enroll-Seeding RNG with provided entropy");
			seed_rng(enrConf->Entropy);

			subjName = parse_subject(enrConf->Subject);
			if(!subjName)
			{
				log_error("enrollment-cms_job_enroll-Unable to parse subject name '%s'", enrConf->Subject);
				status = STAT_ERR;
				append_linef(&statusMessage, "Unable to parse subject name '%s'", enrConf->Subject);
			}

			if(status < STAT_ERR)
			{
				keyPair = generate_keypair(enrConf->KeyType, enrConf->KeySize);
				if(!keyPair)
				{
					log_error("enrollment-cms_job_enroll-Unable to generate key pair with type %s and length %d", \
							enrConf->KeyType, enrConf->KeySize);
					status = STAT_ERR;
					append_linef(&statusMessage, "Unable to generate key pair with type %s and length %d", \
							enrConf->KeyType, enrConf->KeySize);
				}
			}

			if(status < STAT_ERR)
			{
				csrString = generate_csr(keyPair, subjName);
				if(!csrString)
				{
					char errBuf[120];
					unsigned long errNum = ERR_peek_last_error();
					ERR_error_string(errNum, errBuf);
					log_error("enrollment-cms_job_enroll-Unable to generate CSR: %s", errBuf);
					status = STAT_ERR;
					append_linef(&statusMessage, "Unable to generate CSR: %s", errBuf);
				}
			}

			if(status < STAT_ERR)
			{
				res = send_enrollment(sessionToken, jobInfo->JobId, enrConf->EnrollEndpoint, config, csrString, &enrResp);
				if(res == 0 && enrResp)
				{
					AgentApiResult_log(enrResp->Result, &statusMessage, &status);
				}
				else
				{
					log_error("enrollment-cms_job_enroll-Enrollment failed with error code %d", res);
					status = STAT_ERR;
					append_linef(&statusMessage, "Enrollment failed with error code %d", res);
				}
			}

			if(status < STAT_ERR && enrResp && enrResp->Certificate)
			{
				res = save_cert_key(enrConf->StorePath, enrConf->PrivateKeyPath, enrConf->StorePassword, enrResp->Certificate, keyPair, &statusMessage, &status);
			}

			res = send_enroll_job_complete(sessionToken, jobInfo->JobId, jobInfo->CompletionEndpoint, config, status+1, auditId, statusMessage, &enrComp);
			if(enrComp)
			{
				if(AgentApiResult_log(enrComp->Result, NULL, NULL) && enrComp->InventoryJob && chainJob)
				{
					*chainJob = strdup(enrComp->InventoryJob);
				}
			}

			if(status >= STAT_ERR)
			{
				log_info("enrollment-cms_job_enroll-Enrollment job %s failed with error: %s", jobInfo->JobId, statusMessage);
			}
			else if(status == STAT_WARN)
			{
				log_info("enrollment-cms_job_enroll-Enrollment job %s completed with warning: %s", jobInfo->JobId, statusMessage);
			}
			else
			{
				log_info("enrollment-cms_job_enroll-Enrollment job %s completed successfully", jobInfo->JobId);
			}

			X509_NAME_free(subjName);
			EVP_PKEY_free(keyPair);
			free(csrString);
			EnrollmentEnrollResp_free(enrResp);
			EnrollmentCompleteResp_free(enrComp);
		}
	}

	EnrollmentConfigResp_free(enrConf);
	free(statusMessage);

	return returnable;
}
