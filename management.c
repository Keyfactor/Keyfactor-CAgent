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
#include "lib/base64.h"
#include "logging.h"
#include "utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

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

/**
 * @brief Requests the detailed management job configuration from the platform.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobId         Platform GUID identifying this job.
 * @param[in]  endpoint      Relative URL for the configuration endpoint.
 * @param[out] pManConf      Receives the parsed platform response.
 * @return 0 on success, HTTP response code on failure.
 */
static int get_management_config(const char *sessionToken, const char *jobId,
                                 const char *endpoint,
                                 ManagementConfigResp_t **pManConf) {
    char *url = NULL;
    char *jsonReq = NULL;
    char *jsonResp = NULL;
    int res = 0;

    log_verbose("%s::%s(%d) : Sending management config request: %s", LOG_INF,
                jobId);

    CommonConfigReq_t *req = CommonConfigReq_new();
    if (!req) {
        log_error("%s::%s(%d) : Error creating new request structure", LOG_INF);
        return 999;
    }
    req->JobId = strdup(jobId);
    req->SessionToken = strdup(sessionToken);

    jsonReq = CommonConfigReq_toJson(req);
    url = config_build_url(endpoint, true);

    res = http_post_json(url, ConfigData->Username, ConfigData->Password,
                         ConfigData->TrustStore, ConfigData->AgentCert,
                         ConfigData->AgentKey, ConfigData->AgentKeyPassword,
                         jsonReq, &jsonResp, ConfigData->httpRetries,
                         ConfigData->retryInterval);
    if (res == 0) {
        *pManConf = ManagementConfigResp_fromJson(jsonResp);
        if (!*pManConf) {
            log_error("%s::%s(%d) : Error parsing management config response",
                      LOG_INF);
            return 999;
        }
    } else {
        log_error("%s::%s(%d) : Config retrieval failed with error code %d",
                  LOG_INF, res);
    }

    if (jsonReq)
        free(jsonReq);
    if (jsonResp)
        free(jsonResp);
    if (url)
        free(url);
    if (req)
        CommonConfigReq_free(req);

    return res;
} /* get_management_config */

/**
 * @brief Sends job completion status and result data to the platform.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobId         Platform GUID identifying this job.
 * @param[in]  endpoint      Relative URL for the completion endpoint.
 * @param[in]  jobStatus     Numeric status code to report.
 * @param[in]  auditId       Audit record ID associated with this job.
 * @param[in]  message       Human-readable result or error message.
 * @param[out] pManComp      Receives the parsed platform acknowledgement.
 * @return 0 on success, HTTP response code on failure.
 */
static int send_management_job_complete(const char *sessionToken,
                                        const char *jobId, const char *endpoint,
                                        int jobStatus, long auditId,
                                        const char *message,
                                        ManagementCompleteResp_t **pManComp) {
    char *url = NULL;
    char *jsonReq = NULL;
    char *jsonResp = NULL;
    int res = 0;

    log_verbose("%s::%s(%d) : Sending management complete request: %ld "
                "for session: %s",
                LOG_INF, auditId, sessionToken);

    CommonCompleteReq_t *req = CommonCompleteReq_new();
    if (!req) {
        log_error("%s::%s(%d) : Error creating new request structure", LOG_INF);
        return 999;
    }
    req->SessionToken = strdup(sessionToken);
    req->JobId = strdup(jobId);
    req->Status = jobStatus;
    req->AuditId = auditId;
    req->Message = strdup(message);

    jsonReq = CommonCompleteReq_toJson(req);
    url = config_build_url(endpoint, true);

    res = http_post_json(url, ConfigData->Username, ConfigData->Password,
                         ConfigData->TrustStore, ConfigData->AgentCert,
                         ConfigData->AgentKey, ConfigData->AgentKeyPassword,
                         jsonReq, &jsonResp, ConfigData->httpRetries,
                         ConfigData->retryInterval);
    if (res == 0) {
        *pManComp = ManagementCompleteResp_fromJson(jsonResp);
    } else {
        log_error("%s::%s(%d) : Job completion failed with error code %d",
                  LOG_INF, res);
    }

    if (jsonReq)
        free(jsonReq);
    if (jsonResp)
        free(jsonResp);
    if (url)
        free(url);
    if (req)
        CommonCompleteReq_free(req);

    return res;
} /* send_management_job_complete */

/**
 * @brief Returns true if a certificate already exists in the inventory list.
 *
 * Performs a case-insensitive thumbprint comparison between the candidate
 * certificate and every entry in the provided inventory list.
 *
 * @param[in] pemList    Inventory list to search.
 * @param[in] certToAdd  Certificate whose thumbprint is being sought.
 * @return true if a matching thumbprint is found, false otherwise.
 */
static bool cert_exists_in_store(const PemInventoryList *pemList,
                                 const PemInventoryItem *certToAdd) {
    if (!certToAdd->thumbprint_string)
        return false;

    for (int i = 0; i < pemList->item_count; i++) {
        if (!pemList->items[i]->thumbprint_string)
            continue;
        log_trace("%s::%s(%d) : Comparing thumbprints:\n%s\n%s", LOG_INF,
                  certToAdd->thumbprint_string,
                  pemList->items[i]->thumbprint_string);
        if (0 == strcasecmp(certToAdd->thumbprint_string,
                            pemList->items[i]->thumbprint_string)) {
            return true;
        }
    }
    return false;
} /* cert_exists_in_store */

/**
 * @brief Adds a PEM certificate to the specified certificate store.
 *
 * Reads the existing store inventory, checks for a duplicate by thumbprint,
 * and appends the certificate only if it is not already present.
 *
 * @param[in]  storePath   Filesystem path to the target certificate store.
 * @param[in]  certASCII   PEM-encoded certificate to add.
 * @param[out] pMessage    Accumulates human-readable status messages.
 * @param[out] pStatus     Receives the result status of the operation.
 * @return 0 on success, -1 on failure.
 */
static int add_cert_to_store(const char *storePath, const char *certASCII,
                             char **pMessage,
                             enum AgentApiResultStatus *pStatus) {
    PemInventoryItem *certToAdd = NULL;
    PemInventoryList *pemList = NULL;
    int ret = 0;

    log_trace("%s::%s(%d) : Creating a new PemInventoryItem for certificate",
              LOG_INF);
    if (!ssl_PemInventoryItem_create(&certToAdd, certASCII)) {
        log_error("%s::%s(%d) : Error creating cert thumbprint or invalid cert",
                  LOG_INF);
        append_linef(
            pMessage,
            "%s::%s(%d) : Error creating cert thumbprint or invalid cert",
            LOG_INF);
        *pStatus = STAT_ERR;
        return -1;
    }
    log_trace("%s::%s(%d) : New certificate thumbprint: %s", LOG_INF,
              certToAdd->thumbprint_string);

    log_trace("%s::%s(%d) : Reading cert store %s inventory", LOG_INF,
              storePath);
    if (0 != ssl_read_store_inventory(storePath, NULL, &pemList)) {
        log_error("%s::%s(%d) : Error reading PEM store at %s", LOG_INF,
                  storePath);
        append_linef(pMessage, "%s::%s(%d) : Error reading PEM store at %s",
                     LOG_INF, storePath);
        *pStatus = STAT_ERR;
        ret = -1;
        goto cleanup;
    }
    log_trace("%s::%s(%d) : Found %d certs in store", LOG_INF,
              pemList->item_count);

    if (cert_exists_in_store(pemList, certToAdd)) {
        log_warn("%s::%s(%d) : Certificate with thumbprint %s already present "
                 "in store %s",
                 LOG_INF, certToAdd->thumbprint_string, storePath);
        append_linef(pMessage,
                     "%s::%s(%d) : WARNING: Certificate with thumbprint %s "
                     "was already present in store %s",
                     LOG_INF, certToAdd->thumbprint_string, storePath);
        *pStatus = STAT_WARN;
        goto cleanup;
    }

    log_trace("%s::%s(%d) : Adding cert with thumbprint %s to store %s",
              LOG_INF, certToAdd->thumbprint_string, storePath);
    if (!ssl_Store_Cert_add(storePath, certASCII)) {
        log_error("%s::%s(%d) : Error writing cert to store", LOG_INF);
        append_linef(pMessage, "%s::%s(%d) Error writing cert to store",
                     LOG_INF);
        *pStatus = STAT_ERR;
        ret = -1;
    } else {
        log_verbose("%s::%s(%d) : Certificate successfully written to store",
                    LOG_INF);
        *pStatus = STAT_SUCCESS;
    }

cleanup:
    if (certToAdd)
        PemInventoryItem_free(certToAdd);
    if (pemList)
        PemInventoryList_free(pemList);
    return ret;
} /* add_cert_to_store */

/**
 * @brief Removes a certificate and its associated key from a store.
 *
 * @param[in]  storePath    Filesystem path to the certificate store.
 * @param[in]  searchThumb  SHA-1 thumbprint of the certificate to remove.
 * @param[in]  keyPath      Optional path to the associated private key file.
 *                          Pass NULL if the key is embedded in the store.
 * @param[in]  password     Password for an encrypted key, or NULL.
 * @param[out] pMessage     Accumulates human-readable status messages.
 * @param[out] pStatus      Receives the result status of the operation.
 * @return 0 on success, -1 on failure.
 */
static int remove_cert_from_store(const char *storePath,
                                  const char *searchThumb, const char *keyPath,
                                  const char *password, char **pMessage,
                                  enum AgentApiResultStatus *pStatus) {
    if (!ssl_remove_cert_from_store(storePath, searchThumb, keyPath,
                                    password)) {
        log_error("%s::%s(%d) : Unable to remove cert from store at %s",
                  LOG_INF, storePath);
        append_linef(pMessage, "Unable to remove cert from store at %s",
                     storePath);
        *pStatus = STAT_ERR;
        return -1;
    }
    return 0;
} /* remove_cert_from_store */

/**
 * @brief Validates the management store configuration received from the
 * platform.
 *
 * Checks that a store path was provided, that it is a file and not a directory,
 * that it is not the agent's own certificate store, and that it exists on disk.
 *
 * @param[in]  manConf        Management configuration response to validate.
 * @param[out] statusMessage  Accumulates human-readable validation failure
 * messages.
 * @return true if all validation checks pass, false if any check fails.
 */
static bool management_store_config_valid(ManagementConfigResp_t *manConf,
                                          char **statusMessage) {
    if (!manConf->Job.StorePath) {
        log_error("%s::%s(%d) : Job doesn't contain a target store to manage.",
                  LOG_INF);
        append_linef(statusMessage,
                     "Job doesn't contain a target store to manage.");
        return false;
    }

    if (is_directory(manConf->Job.StorePath)) {
        log_error(
            "%s::%s(%d) : The store path must be a file and not a directory.",
            LOG_INF);
        append_linef(statusMessage,
                     "The store path must be a file and not a directory.");
        return false;
    }

    if (ConfigData->UseAgentCert && ConfigData->AgentCert &&
        0 == strcasecmp(ConfigData->AgentCert, manConf->Job.StorePath)) {
        log_warn("%s::%s(%d) : Attempting a Management job on the agent cert "
                 "store is not allowed.",
                 LOG_INF);
        append_linef(statusMessage,
                     "Attempting a Management job on the agent cert store is "
                     "not allowed.");
        return false;
    }

    if (!file_exists(manConf->Job.StorePath)) {
        log_warn("%s::%s(%d) : Attempting to manage a certificate store that "
                 "does not exist yet.",
                 LOG_INF);
        append_linef(statusMessage,
                     "Attempting to manage a certificate store that does not "
                     "exist yet.");
        return false;
    }

    return true;
} /* management_store_config_valid */

/**
 * @brief Executes the ADD operation for a management job.
 *
 * Rejects PFX (private key entry) additions as unsupported, then delegates
 * to add_cert_to_store for plain certificate additions.
 *
 * @param[in]  manConf   Management configuration containing job parameters.
 * @param[out] pMessage  Accumulates human-readable status messages.
 * @param[out] pStatus   Receives the result status of the operation.
 * @return 0 on success, non-zero on failure.
 */
static int handle_op_add(const ManagementConfigResp_t *manConf, char **pMessage,
                         enum AgentApiResultStatus *pStatus) {
    if (manConf->Job.PrivateKeyEntry) {
        const char *msg = "Adding a PFX is not supported at this time";
        log_info("%s::%s(%d) : %s", LOG_INF, msg);
        append_line(pMessage, msg);
        *pStatus = STAT_ERR;
        return 999;
    }

    if (!manConf->Job.EntryContents) {
        log_error("%s::%s(%d) : EntryContents is NULL", LOG_INF);
        append_line(pMessage, "EntryContents is NULL");
        *pStatus = STAT_ERR;
        return -1;
    }

    log_info("%s::%s(%d) : Attempting to add certificate to the store:\n%s",
             LOG_INF, manConf->Job.EntryContents);
    return add_cert_to_store(manConf->Job.StorePath, manConf->Job.EntryContents,
                             pMessage, pStatus);
} /* handle_op_add */

/**
 * @brief Executes the REMOVE operation for a management job.
 *
 * Delegates directly to remove_cert_from_store using the job's alias as the
 * thumbprint to search for.
 *
 * @param[in]  manConf   Management configuration containing job parameters.
 * @param[out] pMessage  Accumulates human-readable status messages.
 * @param[out] pStatus   Receives the result status of the operation.
 * @return 0 on success, non-zero on failure.
 */
static int handle_op_remove(const ManagementConfigResp_t *manConf,
                            char **pMessage,
                            enum AgentApiResultStatus *pStatus) {
    log_verbose("%s::%s(%d) : Remove certificate operation", LOG_INF);
    return remove_cert_from_store(
        manConf->Job.StorePath, manConf->Job.Alias, manConf->Job.PrivateKeyPath,
        manConf->Job.StorePassword, pMessage, pStatus);
} /* handle_op_remove */

/**
 * @brief Dispatches the management job to the correct operation handler.
 *
 * Routes OP_ADD and OP_REM to their respective handlers. Any unrecognised
 * operation type is logged and reported as an error.
 *
 * @param[in]  manConf   Management configuration containing the operation type.
 * @param[out] pMessage  Accumulates human-readable status messages.
 * @param[out] pStatus   Receives the result status of the dispatched operation.
 * @return 0 on success, 999 on unsupported or failed operation.
 */
static int dispatch_management_operation(const ManagementConfigResp_t *manConf,
                                         char **pMessage,
                                         enum AgentApiResultStatus *pStatus) {
    switch (manConf->Job.OperationType) {
    case OP_ADD:
        log_verbose("%s::%s(%d) : Add certificate operation", LOG_INF);
        return handle_op_add(manConf, pMessage, pStatus);

    case OP_REM:
        log_verbose("%s::%s(%d) : Remove certificate operation", LOG_INF);
        return handle_op_remove(manConf, pMessage, pStatus);

    default:
        log_error("%s::%s(%d) : Unsupported operation type: %d", LOG_INF,
                  manConf->Job.OperationType);
        append_linef(pMessage, "Unsupported operation type: %d",
                     manConf->Job.OperationType);
        *pStatus = STAT_ERR;
        return 999;
    }
} /* dispatch_management_operation */

/**
 * @brief Sends job completion to the platform and logs the outcome.
 *
 * Transmits the final status to the platform, then logs a success, warning,
 * or error message based on the reported status value.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobInfo       Job descriptor containing endpoint and ID fields.
 * @param[in]  status        Final result status of the management operation.
 * @param[in]  auditId       Audit record ID associated with this job.
 * @param[in]  statusMessage Human-readable result or error message to send.
 * @return 0 on success, 999 if the completion POST itself fails.
 */
static int finalize_management_job(const char *sessionToken,
                                   const SessionJob_t *jobInfo,
                                   enum AgentApiResultStatus status,
                                   long auditId, const char *statusMessage) {
    ManagementCompleteResp_t *manComp = NULL;
    int res = send_management_job_complete(
        sessionToken, jobInfo->JobId, jobInfo->CompletionEndpoint, status + 1,
        auditId, statusMessage, &manComp);

    if (res == 0 && manComp) {
        AgentApiResult_log(manComp->Result, NULL, NULL);
    }

    ManagementCompleteResp_free(manComp);

    if (res != 0) {
        log_error("%s::%s(%d) : Failed to send management job complete",
                  LOG_INF);
        return 999;
    }

    if (status >= STAT_ERR) {
        log_error("%s::%s(%d) : Management job %s failed with error: %s",
                  LOG_INF, jobInfo->JobId, statusMessage);
    } else if (status == STAT_WARN) {
        log_warn("%s::%s(%d) : Management job %s completed with warning: %s",
                 LOG_INF, jobInfo->JobId, statusMessage);
    } else {
        log_info("%s::%s(%d) : Management job %s completed successfully",
                 LOG_INF, jobInfo->JobId);
    }

    return (status >= STAT_ERR) ? 999 : 0;
} /* finalize_management_job */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * @brief Entry point for the certificate management job.
 *
 * Orchestrates the full management job lifecycle:
 *   1. Fetches the job configuration from the platform.
 *   2. Validates the store configuration.
 *   3. Exits early if the job was cancelled.
 *   4. Dispatches the operation (ADD or REMOVE).
 *   5. Reports job completion back to the platform.
 *
 * @param[in]  jobInfo       Job descriptor received from the scheduler.
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[out] chainJob      Reserved for any follow-on job to chain.
 * @return 0 on success, 1 if the job was cancelled, 999 on error.
 */
int cms_job_manage(SessionJob_t *jobInfo, char *sessionToken, char **chainJob) {
    ManagementConfigResp_t *manConf = NULL;
    char *statusMessage = strdup("");
    enum AgentApiResultStatus status = STAT_UNK;
    int returnable = 0;
    int res = 0;

    log_info("%s::%s(%d) : Starting management job %s", LOG_INF,
             jobInfo->JobId);

    res = get_management_config(sessionToken, jobInfo->JobId,
                                jobInfo->ConfigurationEndpoint, &manConf);
    if (res != 0) {
        log_error("%s::%s(%d) : Failed to get management config", LOG_INF);
        free(statusMessage);
        return res;
    }

    if (!manConf) {
        log_error("%s::%s(%d) : No management configuration returned from "
                  "the platform.",
                  LOG_INF);
        free(statusMessage);
        return 999;
    }

    if (!management_store_config_valid(manConf, &statusMessage)) {
        finalize_management_job(sessionToken, jobInfo, STAT_ERR,
                                manConf->AuditId, statusMessage);
        returnable = 999;
        goto exit;
    }

    if (!AgentApiResult_log(manConf->Result, &statusMessage, &status)) {
        returnable = 999;
        goto exit;
    }

    if (manConf->JobCancelled) {
        log_info("%s::%s(%d) : Job has been cancelled and will not be run",
                 LOG_INF);
        returnable = 1;
        goto exit;
    }

    res = dispatch_management_operation(manConf, &statusMessage, &status);
    if (res != 0) {
        log_error("%s::%s(%d) : Management operation failed", LOG_INF);
    }

    returnable = finalize_management_job(sessionToken, jobInfo, status,
                                         manConf->AuditId, statusMessage);

exit:
    ManagementConfigResp_free(manConf);
    free(statusMessage);
    return returnable;
} /* cms_job_manage */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
