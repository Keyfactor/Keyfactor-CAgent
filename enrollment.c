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
#include <strings.h>
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

/**
 * @brief Requests the enrollment job configuration from the platform.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobId         Platform GUID identifying this job.
 * @param[in]  endpoint      Relative URL for the configuration endpoint.
 * @param[out] pEnrConf      Receives the parsed platform response.
 * @return 0 on success, non-zero on failure.
 */
static int get_enroll_config(const char *sessionToken, const char *jobId,
                             const char *endpoint,
                             EnrollmentConfigResp_t **pEnrConf)
{
    char *url      = NULL;
    char *jsonReq  = NULL;
    char *jsonResp = NULL;
    int   res      = 0;

    log_verbose("%s::%s(%d) : Sending enrollment config request: %s",
                LOG_INF, jobId);

    CommonConfigReq_t *req = CommonConfigReq_new();
    if (!req) {
        log_error("%s::%s(%d) : Error creating common config request structure",
                  LOG_INF);
        return 999;
    }

    req->JobId        = strdup(jobId);
    req->SessionToken = strdup(sessionToken);

    jsonReq = CommonConfigReq_toJson(req);
    url     = config_build_url(endpoint, true);

    res = http_post_json(url, ConfigData->Username, ConfigData->Password,
                         ConfigData->TrustStore, ConfigData->AgentCert,
                         ConfigData->AgentKey, ConfigData->AgentKeyPassword,
                         jsonReq, &jsonResp,
                         ConfigData->httpRetries, ConfigData->retryInterval);
    if (res == 0) {
        *pEnrConf = EnrollmentConfigResp_fromJson(jsonResp);
    } else {
        log_error("%s::%s(%d) : Config retrieval failed with error code %d",
                  LOG_INF, res);
    }

    if (jsonReq)  free(jsonReq);
    if (jsonResp) free(jsonResp);
    if (url)      free(url);
    if (req)      CommonConfigReq_free(req);

    return res;
} /* get_enroll_config */


/**
 * @brief Sends the CSR to the platform for signing.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobId         Platform GUID identifying this job.
 * @param[in]  endpoint      Relative URL for the enrollment endpoint.
 * @param[in]  csr           PEM-encoded certificate signing request.
 * @param[out] pEnrResp      Receives the parsed platform response.
 * @return 0 on success, non-zero on failure.
 */
static int send_enrollment(const char *sessionToken, const char *jobId,
                           const char *endpoint, const char *csr,
                           EnrollmentEnrollResp_t **pEnrResp)
{
    char *url      = NULL;
    char *jsonReq  = NULL;
    char *jsonResp = NULL;
    int   res      = 0;

    log_verbose("%s::%s(%d) : Sending enrollment request: %s",
                LOG_INF, jobId);

    EnrollmentEnrollReq_t *enrReq = calloc(1, sizeof(*enrReq));
    if (!enrReq) {
        log_error("%s::%s(%d) : Error creating enrollment request", LOG_INF);
        return 999;
    }

    enrReq->SessionToken = strdup(sessionToken);
    enrReq->JobId        = strdup(jobId);
    enrReq->CSRText      = strdup(csr);

    jsonReq = EnrollmentEnrollReq_toJson(enrReq);
    url     = config_build_url(endpoint, true);

    res = http_post_json(url, ConfigData->Username, ConfigData->Password,
                         ConfigData->TrustStore, ConfigData->AgentCert,
                         ConfigData->AgentKey, ConfigData->AgentKeyPassword,
                         jsonReq, &jsonResp,
                         ConfigData->httpRetries, ConfigData->retryInterval);
    if (res == 0) {
        *pEnrResp = EnrollmentEnrollResp_fromJson(jsonResp);
    } else {
        log_error("%s::%s(%d) : Enrollment failed with error code %d",
                  LOG_INF, res);
    }

    if (jsonReq)  free(jsonReq);
    if (jsonResp) free(jsonResp);
    if (url)      free(url);
    if (enrReq)   EnrollmentEnrollReq_free(enrReq);

    return res;
} /* send_enrollment */


/**
 * @brief Sends enrollment job completion status to the platform.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobId         Platform GUID identifying this job.
 * @param[in]  endpoint      Relative URL for the completion endpoint.
 * @param[in]  jobStatus     Numeric status code to report.
 * @param[in]  auditId       Audit record ID associated with this job.
 * @param[in]  message       Human-readable result or error message.
 * @param[out] pEnrComp      Receives the parsed platform acknowledgement.
 * @return 0 on success, non-zero on failure.
 */
static int send_enroll_job_complete(const char *sessionToken,
                                    const char *jobId,
                                    const char *endpoint,
                                    int jobStatus, long auditId,
                                    const char *message,
                                    EnrollmentCompleteResp_t **pEnrComp)
{
    char *url      = NULL;
    char *jsonReq  = NULL;
    char *jsonResp = NULL;
    int   res      = 0;

    log_verbose("%s::%s(%d) : Sending enrollment complete request: %ld "
                "for session: %s", LOG_INF, auditId, sessionToken);

    CommonCompleteReq_t *req = CommonCompleteReq_new();
    if (!req) {
        log_error("%s::%s(%d) : Error creating common complete request structure",
                  LOG_INF);
        return 999;
    }

    req->SessionToken = strdup(sessionToken);
    req->JobId        = strdup(jobId);
    req->Status       = jobStatus;
    req->AuditId      = auditId;
    req->Message      = strdup(message);

    jsonReq = CommonCompleteReq_toJson(req);
    url     = config_build_url(endpoint, true);

    res = http_post_json(url, ConfigData->Username, ConfigData->Password,
                         ConfigData->TrustStore, ConfigData->AgentCert,
                         ConfigData->AgentKey, ConfigData->AgentKeyPassword,
                         jsonReq, &jsonResp,
                         ConfigData->httpRetries, ConfigData->retryInterval);
    if (res == 0) {
        *pEnrComp = EnrollmentCompleteResp_fromJson(jsonResp);
    } else {
        log_error("%s::%s(%d) : Job completion failed with error code %d",
                  LOG_INF, res);
    }

    if (jsonReq)  free(jsonReq);
    if (jsonResp) free(jsonResp);
    if (url)      free(url);
    if (req)      CommonCompleteReq_free(req);

    return res;
} /* send_enroll_job_complete */


/**
 * @brief Validates the enrollment store configuration received from the platform.
 *
 * Checks that a store path was provided, that it is not a directory, and that
 * it is not the agent's own certificate store. Note: unlike inventory and
 * management, enrollment does not require the store to exist yet.
 *
 * @param[in]  enrConf        Enrollment configuration response to validate.
 * @param[out] statusMessage  Accumulates human-readable validation failure messages.
 * @return true if all checks pass, false if any check fails.
 */
static bool enrollment_store_config_valid(const EnrollmentConfigResp_t *enrConf,
                                          char **statusMessage)
{
    if (!enrConf->StorePath) {
        log_error("%s::%s(%d) : Job doesn't contain a target store to enroll into.",
                  LOG_INF);
        append_linef(statusMessage,
                     "Job doesn't contain a target store to enroll into.");
        return false;
    }

    log_verbose("%s::%s(%d) : KeyType: %s", LOG_INF, enrConf->KeyType);
    log_verbose("%s::%s(%d) : Store to reenroll = %s", LOG_INF, enrConf->StorePath);

    if (is_directory(enrConf->StorePath)) {
        log_error("%s::%s(%d) : The store path must be a file and not a directory.",
                  LOG_INF);
        append_linef(statusMessage,
                     "The store path must be a file and not a directory.");
        return false;
    }

    if (ConfigData->UseAgentCert && ConfigData->AgentCert &&
        0 == strcasecmp(ConfigData->AgentCert, enrConf->StorePath)) {
        log_warn("%s::%s(%d) : Attempting to re-enroll the agent cert is "
                 "not allowed.", LOG_INF);
        append_linef(statusMessage,
                     "Attempting to re-enroll the agent cert is not allowed.");
        return false;
    }

    return true;
} /* enrollment_store_config_valid */


/**
 * @brief Seeds the SSL RNG with platform-supplied entropy if provided.
 *
 * No-ops silently if entropy is NULL or empty.
 *
 * @param[in] entropy  Base64-encoded entropy string from the platform, or NULL.
 */
static void seed_rng_if_provided(const char *entropy)
{
    if (!entropy || 0 == strlen(entropy) ||
        0 == strcasecmp("", entropy))
        return;

    log_verbose("%s::%s(%d) : Seeding RNG with provided entropy", LOG_INF);
    ssl_seed_rng(entropy);
} /* seed_rng_if_provided */


/**
 * @brief Generates a keypair for enrollment using the configured key type and size.
 *
 * On TPM builds, validates that a PrivateKeyPath is provided before attempting
 * key generation, and returns early on failure to avoid passing a NULL path
 * to the TPM interface.
 *
 * @param[in]  enrConf   Enrollment configuration containing key parameters.
 * @param[out] pMessage  Accumulates human-readable status messages.
 * @param[out] pStatus   Receives the result status of the operation.
 * @return 0 on success, -1 on failure.
 */
static int generate_enrollment_keypair(const EnrollmentConfigResp_t *enrConf,
                                       char **pMessage,
                                       enum AgentApiResultStatus *pStatus)
{
#if defined(__TPM__)
    if (!enrConf->PrivateKeyPath ||
        0 == strcasecmp("", enrConf->PrivateKeyPath)) {
        log_error("%s::%s(%d) : A TPM requires a PrivateKeyPath", LOG_INF);
        append_linef(pMessage, "%s::%s(%d) : A TPM requires a PrivateKeyPath",
                     LOG_INF);
        *pStatus = STAT_ERR;
        return -1;
    }
    if (!generate_keypair(enrConf->KeyType, enrConf->KeySize,
                          enrConf->PrivateKeyPath)) {
#else
    if (!generate_keypair(enrConf->KeyType, enrConf->KeySize)) {
#endif
        log_error("%s::%s(%d) : Unable to generate key pair with type %s "
                  "and length %d", LOG_INF,
                  enrConf->KeyType, enrConf->KeySize);
        append_linef(pMessage,
                     "Unable to generate key pair with type %s and length %d",
                     enrConf->KeyType, enrConf->KeySize);
        *pStatus = STAT_ERR;
        return -1;
    }
    return 0;
} /* generate_enrollment_keypair */


/**
 * @brief Generates a CSR from the keypair held in the SSL wrapper.
 *
 * @param[in]  enrConf   Enrollment configuration containing the subject DN.
 * @param[out] pMessage  Accumulates human-readable status messages.
 * @param[out] pStatus   Receives the result status of the operation.
 * @return Heap-allocated PEM CSR string on success, NULL on failure.
 *         Caller is responsible for freeing the returned string.
 */
static char *generate_enrollment_csr(const EnrollmentConfigResp_t *enrConf,
                                     char **pMessage,
                                     enum AgentApiResultStatus *pStatus)
{
    size_t csrLen   = 0;
    char  *csrString = NULL;

    log_trace("%s::%s(%d) : Generating CSR", LOG_INF);

    csrString = ssl_generate_csr(enrConf->Subject, &csrLen, pMessage);
    if (!csrString) {
        log_error("%s::%s(%d) : Failed to generate CSR", LOG_INF);
        append_linef(pMessage, "%s::%s(%d) : Failed to generate CSR", LOG_INF);
        *pStatus = STAT_ERR;
        return NULL;
    }

    log_verbose("%s::%s(%d) : Successfully created CSR", LOG_INF);
    return csrString;
} /* generate_enrollment_csr */


/**
 * @brief Submits a CSR to the platform and validates the enrollment response.
 *
 * Sends the CSR for signing and checks the platform's result. Sets pStatus to
 * STAT_ERR if the HTTP call fails or the platform returns an error result.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobInfo       Job descriptor containing endpoint and ID fields.
 * @param[in]  enrConf       Enrollment configuration containing the endpoint.
 * @param[in]  csrString     PEM-encoded CSR to submit.
 * @param[out] pEnrResp      Receives the parsed enrollment response.
 * @param[out] pMessage      Accumulates human-readable status messages.
 * @param[out] pStatus       Receives the result status of the operation.
 * @return 0 on success, non-zero on failure.
 */
static int submit_csr_to_platform(const char *sessionToken,
                                  const SessionJob_t *jobInfo,
                                  const EnrollmentConfigResp_t *enrConf,
                                  const char *csrString,
                                  EnrollmentEnrollResp_t **pEnrResp,
                                  char **pMessage,
                                  enum AgentApiResultStatus *pStatus)
{
    int res = send_enrollment(sessionToken, jobInfo->JobId,
                              enrConf->EnrollEndpoint, csrString, pEnrResp);
    if (res != 0) {
        log_error("%s::%s(%d) : Enrollment failed with error code %d",
                  LOG_INF, res);
        append_linef(pMessage, "Enrollment failed with error code %d", res);
        *pStatus = STAT_ERR;
        return res;
    }

    if (*pEnrResp &&
        !AgentApiResult_log((*pEnrResp)->Result, pMessage, pStatus)) {
        log_error("%s::%s(%d) : Enrollment response indicates error", LOG_INF);
        *pStatus = STAT_ERR;
        return -1;
    }

    return 0;
} /* submit_csr_to_platform */


/**
 * @brief Executes the full enrollment operation sequence.
 *
 * Seeds the RNG, generates a keypair, generates a CSR, submits it to the
 * platform, and saves the returned certificate and key to disk. Each step
 * is skipped if a prior step has set pStatus to STAT_ERR.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobInfo       Job descriptor containing endpoint and ID fields.
 * @param[in]  enrConf       Enrollment configuration from the platform.
 * @param[out] pMessage      Accumulates human-readable status messages.
 * @param[out] pStatus       Receives the result status of the operation.
 * @return 0 on success, 999 on failure.
 */
static int run_enrollment_operations(const char *sessionToken,
                                     const SessionJob_t *jobInfo,
                                     const EnrollmentConfigResp_t *enrConf,
                                     char **pMessage,
                                     enum AgentApiResultStatus *pStatus)
{
    char                   *csrString = NULL;
    EnrollmentEnrollResp_t *enrResp   = NULL;
    int                     returnable = 0;
    int                     res        = 0;

    seed_rng_if_provided(enrConf->Entropy);

    if (0 != generate_enrollment_keypair(enrConf, pMessage, pStatus)) {
        returnable = 999;
        goto cleanup;
    }

    csrString = generate_enrollment_csr(enrConf, pMessage, pStatus);
    if (!csrString) {
        returnable = 999;
        goto cleanup;
    }

    res = submit_csr_to_platform(sessionToken, jobInfo, enrConf,
                                  csrString, &enrResp, pMessage, pStatus);
    if (res != 0) {
        returnable = 999;
        goto cleanup;
    }

    if (*pStatus < STAT_ERR && enrResp && enrResp->Certificate) {
        res = save_cert_key(enrConf->StorePath, enrConf->PrivateKeyPath,
                            enrConf->StorePassword, enrResp->Certificate,
                            pMessage, pStatus);
        if (res != 0 || *pStatus >= STAT_ERR) {
            log_error("%s::%s(%d) : Failed to save certificate and key",
                      LOG_INF);
            returnable = 999;
        }
    }

cleanup:
    if (csrString) free(csrString);
    if (enrResp)   EnrollmentEnrollResp_free(enrResp);
    return returnable;
} /* run_enrollment_operations */


/**
 * @brief Sends job completion to the platform, sets any chain job, and logs outcome.
 *
 * Transmits the final status to the platform, optionally stores a follow-on
 * inventory job ID if chain jobs are enabled, then logs success, warning, or
 * error based on the reported status.
 *
 * @param[in]  sessionToken   GUID for the current curl session.
 * @param[in]  jobInfo        Job descriptor containing endpoint and ID fields.
 * @param[in]  status         Final result status of the enrollment operation.
 * @param[in]  auditId        Audit record ID associated with this job.
 * @param[in]  statusMessage  Human-readable result or error message to send.
 * @param[out] chainJob       Receives the follow-on job ID if provided by platform.
 * @return 0 on success, 999 if the completion POST fails or status >= STAT_ERR.
 */
static int finalize_enrollment_job(const char *sessionToken,
                                   const SessionJob_t *jobInfo,
                                   enum AgentApiResultStatus status,
                                   long auditId,
                                   const char *statusMessage,
                                   char **chainJob)
{
    EnrollmentCompleteResp_t *enrComp = NULL;

    int res = send_enroll_job_complete(sessionToken, jobInfo->JobId,
                                       jobInfo->CompletionEndpoint,
                                       status + 1, auditId,
                                       statusMessage, &enrComp);
    if (res != 0) {
        log_error("%s::%s(%d) : Failed to send enrollment job complete",
                  LOG_INF);
        EnrollmentCompleteResp_free(enrComp);
        return 999;
    }

#if defined(__RUN_CHAIN_JOBS__)
    if (enrComp &&
        AgentApiResult_log(enrComp->Result, NULL, NULL) &&
        enrComp->InventoryJob &&
        chainJob) {
        *chainJob = strdup(enrComp->InventoryJob);
    }
#endif

    if (status >= STAT_ERR) {
        log_error("%s::%s(%d) : Enrollment job %s failed with error: %s",
                  LOG_INF, jobInfo->JobId, statusMessage);
    } else if (status == STAT_WARN) {
        log_warn("%s::%s(%d) : Enrollment job %s completed with warning: %s",
                 LOG_INF, jobInfo->JobId, statusMessage);
    } else {
        log_info("%s::%s(%d) : Enrollment job %s completed successfully",
                 LOG_INF, jobInfo->JobId);
    }

    EnrollmentCompleteResp_free(enrComp);
    return (status >= STAT_ERR) ? 999 : 0;
} /* finalize_enrollment_job */


/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * @brief Entry point for the certificate enrollment job.
 *
 * Orchestrates the full enrollment job lifecycle:
 *   1. Fetches the job configuration from the platform.
 *   2. Validates the store configuration.
 *   3. Exits early if the job was cancelled.
 *   4. Generates a keypair, creates a CSR, submits it, and saves the result.
 *   5. Reports job completion back to the platform.
 *
 * @param[in]  jobInfo       Job descriptor received from the scheduler.
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[out] chainJob      Receives a follow-on job ID if provided by platform.
 * @return 0 on success, 1 if the job was cancelled, 999 on error.
 */
int cms_job_enroll(SessionJob_t *jobInfo, char *sessionToken, char **chainJob)
{
    EnrollmentConfigResp_t   *enrConf      = NULL;
    char                     *statusMessage = strdup("");
    enum AgentApiResultStatus status        = STAT_UNK;
    int                       returnable   = 0;
    int                       res          = 0;

    log_info("%s::%s(%d) : Starting enrollment job %s",
             LOG_INF, jobInfo->JobId);

    res = get_enroll_config(sessionToken, jobInfo->JobId,
                            jobInfo->ConfigurationEndpoint, &enrConf);
    if (res != 0) {
        log_error("%s::%s(%d) : Failed to get enrollment config", LOG_INF);
        free(statusMessage);
        return 999;
    }

    if (!enrConf) {
        log_error("%s::%s(%d) : No enrollment configuration returned "
                  "by platform.", LOG_INF);
        free(statusMessage);
        return 999;
    }

    if (!enrollment_store_config_valid(enrConf, &statusMessage)) {
        EnrollmentCompleteResp_t *enrComp = NULL;
        send_enroll_job_complete(sessionToken, jobInfo->JobId,
                                 jobInfo->CompletionEndpoint,
                                 STAT_ERR, enrConf->AuditId,
                                 statusMessage, &enrComp);
        EnrollmentCompleteResp_free(enrComp);
        returnable = 999;
        goto exit;
    }

    if (!AgentApiResult_log(enrConf->Result, &statusMessage, &status)) {
        returnable = 999;
        goto exit;
    }

    if (enrConf->JobCancelled) {
        log_info("%s::%s(%d) : Job has been cancelled and will not be run",
                 LOG_INF);
        returnable = 1;
        goto exit;
    }

    log_verbose("%s::%s(%d) : Audit Id: %ld", LOG_INF, enrConf->AuditId);

    res = run_enrollment_operations(sessionToken, jobInfo, enrConf,
                                    &statusMessage, &status);
    if (res != 0)
        returnable = 999;

    returnable = finalize_enrollment_job(sessionToken, jobInfo, status,
                                         enrConf->AuditId, statusMessage,
                                         chainJob);
exit:
    EnrollmentConfigResp_free(enrConf);
    free(statusMessage);
    return returnable;
} /* cms_job_enroll */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
