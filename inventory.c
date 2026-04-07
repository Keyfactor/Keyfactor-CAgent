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

#include "inventory.h"
#include <stdio.h>
#include "httpclient.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "constants.h"
#include "lib/base64.h"
#include "utils.h"
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
 * @brief Requests the inventory job configuration from the platform.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobId         Platform GUID identifying this job.
 * @param[in]  endpoint      Relative URL for the configuration endpoint.
 * @param[out] pInvConf      Receives the parsed platform response.
 * @return 0 on success, non-zero on failure.
 */
static int get_inventory_config(const char *sessionToken, const char *jobId,
                                const char *endpoint,
                                InventoryConfigResp_t **pInvConf)
{
    char *url      = NULL;
    char *jsonReq  = NULL;
    char *jsonResp = NULL;
    int   res      = 0;

    log_verbose("%s::%s(%d) : Sending inventory config request: %s",
                LOG_INF, jobId);

    CommonConfigReq_t *req = CommonConfigReq_new();
    if (!req) {
        log_error("%s::%s(%d) : Out of memory in CommonConfigReq_new()",
                  LOG_INF);
        return -1;
    }

    req->JobId        = strdup(jobId);
    req->SessionToken = strdup(sessionToken);

    log_trace("%s::%s(%d) : Set job ID to %s", LOG_INF, jobId);
    log_trace("%s::%s(%d) : Set session token to %s", LOG_INF, sessionToken);

    jsonReq = CommonConfigReq_toJson(req);
    log_trace("%s::%s(%d) : Config request JSON: %s", LOG_INF, jsonReq);

    url = config_build_url(endpoint, true);
    log_trace("%s::%s(%d) : POSTing to %s", LOG_INF, url);

    res = http_post_json(url, ConfigData->Username, ConfigData->Password,
                         ConfigData->TrustStore, ConfigData->AgentCert,
                         ConfigData->AgentKey, ConfigData->AgentKeyPassword,
                         jsonReq, &jsonResp,
                         ConfigData->httpRetries, ConfigData->retryInterval);
    if (res == 0) {
        *pInvConf = InventoryConfigResp_fromJson(jsonResp);
    } else {
        log_error("%s::%s(%d) : Config retrieval failed with error code %d",
                  LOG_INF, res);
    }

    free(jsonReq);
    free(jsonResp);
    free(url);
    CommonConfigReq_free(req);

    return res;
} /* get_inventory_config */


/**
 * @brief Submits the computed inventory delta to the platform.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobId         Platform GUID identifying this job.
 * @param[in]  endpoint      Relative URL for the inventory update endpoint.
 * @param[in]  newInv        The computed list of ADD, REMOVE, and UNCHANGED items.
 * @param[out] pUpdResp      Receives the parsed platform acknowledgement.
 * @return 0 on success, non-zero on failure.
 */
static int send_inventory_update(const char *sessionToken, const char *jobId,
                                 const char *endpoint,
                                 InventoryUpdateList_t *newInv,
                                 InventoryUpdateResp_t **pUpdResp)
{
    char *url      = NULL;
    char *jsonReq  = NULL;
    char *jsonResp = NULL;
    int   res      = 0;

    log_verbose("%s::%s(%d) : Sending inventory update request: %s",
                LOG_INF, jobId);

    InventoryUpdateReq_t *updReq = calloc(1, sizeof(*updReq));
    if (!updReq) {
        log_error("%s::%s(%d) : Error couldn't allocate update request structure",
                  LOG_INF);
        return 999;
    }

    updReq->SessionToken = strdup(sessionToken);
    updReq->JobId        = strdup(jobId);
    updReq->Inventory    = *newInv;

    jsonReq = InventoryUpdateReq_toJson(updReq);
    url     = config_build_url(endpoint, true);

    res = http_post_json(url, ConfigData->Username, ConfigData->Password,
                         ConfigData->TrustStore, ConfigData->AgentCert,
                         ConfigData->AgentKey, ConfigData->AgentKeyPassword,
                         jsonReq, &jsonResp,
                         ConfigData->httpRetries, ConfigData->retryInterval);
    if (res == 0) {
        *pUpdResp = InventoryUpdateResp_fromJson(jsonResp);
    } else {
        log_error("%s::%s(%d) : Update submission failed with error code %d",
                  LOG_INF, res);
    }

    if (jsonReq)  free(jsonReq);
    if (jsonResp) free(jsonResp);
    if (url)      free(url);
    if (updReq)   InventoryUpdateReq_free(updReq);

    return res;
} /* send_inventory_update */


/**
 * @brief Sends job completion status and message to the platform.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobId         Platform GUID identifying this job.
 * @param[in]  endpoint      Relative URL for the completion endpoint.
 * @param[in]  jobStatus     Numeric status code to report.
 * @param[in]  auditId       Audit record ID associated with this job.
 * @param[in]  message       Human-readable result or error message.
 * @param[out] pInvComp      Receives the parsed platform acknowledgement.
 * @return 0 on success, non-zero on failure.
 */
static int send_inventory_job_complete(const char *sessionToken,
                                       const char *jobId,
                                       const char *endpoint,
                                       int jobStatus, long auditId,
                                       const char *message,
                                       CommonCompleteResp_t **pInvComp)
{
    char *url      = NULL;
    char *jsonReq  = NULL;
    char *jsonResp = NULL;
    int   res      = 0;

    log_verbose("%s::%s(%d) : Sending inventory complete request: %ld "
                "for session: %s", LOG_INF, auditId, sessionToken);

    CommonCompleteReq_t *req = CommonCompleteReq_new();
    if (!req) {
        log_error("%s::%s(%d) : Error allocating request structure", LOG_INF);
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
        *pInvComp = CommonCompleteResp_fromJson(jsonResp);
    } else {
        log_error("%s::%s(%d) : Job completion failed with error code %d",
                  LOG_INF, res);
    }

    if (jsonReq)  free(jsonReq);
    if (jsonResp) free(jsonResp);
    if (url)      free(url);
    if (req)      CommonCompleteReq_free(req);

    return res;
} /* send_inventory_job_complete */


/**
 * @brief Appends a single item to an inventory update list.
 *
 * Grows the list's item array by one and stores the pointer. Logs an error
 * if the realloc fails; the list is left unmodified in that case.
 *
 * @param[in,out] list  The list to append to.
 * @param[in]     item  The item to append.
 */
static void InventoryUpdateList_add(InventoryUpdateList_t *list,
                                    InventoryUpdateItem_t *item)
{
    if (!list || !item)
        return;

    InventoryUpdateItem_t **tmp = realloc(list->items,
                          (list->count + 1) * sizeof(InventoryUpdateItem_t *));
    if (!tmp) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        return;
    }
    list->items = tmp;

    list->items[list->count] = item;
    list->count++;
} /* InventoryUpdateList_add */


/**
 * @brief Frees an inventory update list and all items it contains.
 *
 * @param[in] list  The list to free. Safe to call with NULL.
 */
static void InventoryUpdateList_free(InventoryUpdateList_t *list)
{
    if (!list)
        return;

    for (int i = 0; i < list->count; i++) {
        InventoryUpdateItem_t *item = list->items[i];
        if (!item)
            continue;
        if (item->Alias)
            free(item->Alias);
        if (item->Certificates) {
            for (int j = 0; j < item->Certificates_count; j++) {
                if (item->Certificates[j])
                    free(item->Certificates[j]);
            }
        }
        free(item);
    }

    if (list->items)
        free(list->items);
    free(list);
} /* InventoryUpdateList_free */


/**
 * @brief Validates the inventory store configuration received from the platform.
 *
 * Checks that a store path was provided, that it is a file and not a directory,
 * that it is not the agent's own certificate store, and that it exists on disk.
 *
 * @param[in]  invConf        Inventory configuration response to validate.
 * @param[out] statusMessage  Accumulates human-readable validation failure messages.
 * @return true if all checks pass, false if any check fails.
 */
static bool inventory_store_config_valid(const InventoryConfigResp_t *invConf,
                                         char **statusMessage)
{
    if (!invConf->Job.StorePath) {
        log_error("%s::%s(%d) : Job doesn't contain a store to inventory.",
                  LOG_INF);
        append_linef(statusMessage, "Job doesn't contain a store to inventory.");
        return false;
    }

    if (is_directory(invConf->Job.StorePath)) {
        log_error("%s::%s(%d) : The store path must be a file and not a directory.",
                  LOG_INF);
        append_linef(statusMessage,
                     "The store path must be a file and not a directory.");
        return false;
    }

    if (ConfigData->UseAgentCert && ConfigData->AgentCert &&
        0 == strcasecmp(ConfigData->AgentCert, invConf->Job.StorePath)) {
        log_warn("%s::%s(%d) : Attempting to inventory the agent cert store "
                 "is not allowed.", LOG_INF);
        append_linef(statusMessage,
                     "Attempting to inventory the agent cert store is not allowed.");
        return false;
    }

    if (!file_exists(invConf->Job.StorePath)) {
        log_warn("%s::%s(%d) : Attempting to inventory a certificate store "
                 "that does not exist yet.", LOG_INF);
        append_linef(statusMessage,
                     "Attempting to inventory a certificate store that does "
                     "not exist yet.");
        return false;
    }

    return true;
} /* inventory_store_config_valid */


/**
 * @brief Classifies each certificate in the on-disk store as ADD or UNCHANGED.
 *
 * Walks the agent's local PEM inventory. If a certificate's thumbprint is
 * found in the platform's list it is marked UNCHANGED; otherwise it is marked
 * ADD and its PEM content is included so the platform can record it.
 *
 * @param[in]     cmsItems      Array of inventory items the platform knows about.
 * @param[in]     cmsItemCount  Number of entries in cmsItems.
 * @param[in]     fileItemList  Certificates found in the on-disk store.
 * @param[in,out] updateList    Receives the classified update items.
 */
static void classify_file_certs(InventoryCurrentItem_t **cmsItems,
                                int cmsItemCount,
                                const struct PemInventoryList *fileItemList,
                                InventoryUpdateList_t *updateList)
{
    for (int i = 0; i < fileItemList->item_count; i++) {
        PemInventoryItem *currentPem = fileItemList->items[i];
        bool inCms = false;

        for (int j = 0; j < cmsItemCount; j++) {
            if (0 != strcasecmp(currentPem->thumbprint_string,
                                cmsItems[j]->Alias))
                continue;

            log_verbose("%s::%s(%d) : Alias %s is UNCHANGED",
                        LOG_INF, currentPem->thumbprint_string);
            inCms = true;

            InventoryUpdateItem_t *item = calloc(1, sizeof(*item));
            if (!item) {
                log_error("%s::%s(%d) : Out of memory", LOG_INF);
                return;
            }
            item->Alias           = strdup(cmsItems[j]->Alias
                                           ? cmsItems[j]->Alias : "");
            item->ItemStatus      = INV_STAT_UNCH;
            item->PrivateKeyEntry = cmsItems[j]->PrivateKeyEntry;
            item->UseChainLevel   = false;

            InventoryUpdateList_add(updateList, item);
            break;
        }

        if (inCms)
            continue;

        log_verbose("%s::%s(%d) : Alias %s is ADDED",
                    LOG_INF, currentPem->thumbprint_string);

        InventoryUpdateItem_t *item = calloc(1, sizeof(*item));
        if (!item) {
            log_error("%s::%s(%d) : Out of memory", LOG_INF);
            return;
        }
        item->Alias               = strdup(currentPem->thumbprint_string
                                           ? currentPem->thumbprint_string : "");
        item->ItemStatus          = INV_STAT_ADD;
        item->PrivateKeyEntry     = currentPem->has_private_key;
        item->UseChainLevel       = false;
        item->Certificates        = calloc(1, sizeof(char *));
        item->Certificates[0]     = strdup(currentPem->cert);
        item->Certificates_count  = 1;

        InventoryUpdateList_add(updateList, item);
    }
} /* classify_file_certs */


/**
 * @brief Classifies platform certificates that no longer exist on disk as REMOVE.
 *
 * Walks the platform's known inventory. Any certificate whose thumbprint is
 * not found in the agent's local store is marked for removal.
 *
 * @param[in]     cmsItems      Array of inventory items the platform knows about.
 * @param[in]     cmsItemCount  Number of entries in cmsItems.
 * @param[in]     fileItemList  Certificates found in the on-disk store.
 * @param[in,out] updateList    Receives the classified REMOVE items.
 */
static void classify_deleted_certs(InventoryCurrentItem_t **cmsItems,
                                   int cmsItemCount,
                                   const struct PemInventoryList *fileItemList,
                                   InventoryUpdateList_t *updateList)
{
    for (int m = 0; m < cmsItemCount; m++) {
        bool inFile = false;

        for (int n = 0; n < fileItemList->item_count; n++) {
            if (0 == strcasecmp(fileItemList->items[n]->thumbprint_string,
                                cmsItems[m]->Alias)) {
                inFile = true;
                break;
            }
        }

        if (inFile)
            continue;

        log_verbose("%s::%s(%d) : Alias %s is DELETED",
                    LOG_INF, cmsItems[m]->Alias);

        InventoryUpdateItem_t *item = calloc(1, sizeof(*item));
        if (!item) {
            log_error("%s::%s(%d) : Out of Memory", LOG_INF);
            return;
        }
        item->Alias           = strdup(cmsItems[m]->Alias);
        item->ItemStatus      = INV_STAT_REM;
        item->PrivateKeyEntry = false;
        item->UseChainLevel   = false;

        InventoryUpdateList_add(updateList, item);
    }
} /* classify_deleted_certs */


/**
 * @brief Builds the full inventory delta by classifying all certificates.
 *
 * Allocates a new update list, then delegates to classify_file_certs to find
 * ADDs and UNCHANGEDs, and classify_deleted_certs to find REMOVEs.
 *
 * NOTE: The returned updateList is heap-allocated and must be freed by the
 * caller using InventoryUpdateList_free().
 *
 * @param[in]  cmsItems      Array of inventory items the platform knows about.
 * @param[in]  cmsItemCount  Number of entries in cmsItems.
 * @param[in]  fileItemList  Certificates found in the on-disk store.
 * @param[out] updateList    Receives the fully classified update list.
 * @return 0 on success.
 */
static int compute_inventory_update(InventoryCurrentItem_t **cmsItems,
                                    int cmsItemCount,
                                    const struct PemInventoryList *fileItemList,
                                    InventoryUpdateList_t **updateList)
{
    *updateList = calloc(1, sizeof(InventoryUpdateList_t));
    if (!*updateList) {
        log_error("%s::%s(%d) : Out of memory allocating update list", LOG_INF);
        return -1;
    }

    classify_file_certs(cmsItems, cmsItemCount, fileItemList, *updateList);
    classify_deleted_certs(cmsItems, cmsItemCount, fileItemList, *updateList);

    return 0;
} /* compute_inventory_update */


/**
 * @brief Computes the inventory delta and submits it to the platform.
 *
 * Compares the on-disk PEM store against the platform's known inventory,
 * sends the resulting ADD/REMOVE/UNCHANGED list, and processes the response.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobInfo       Job descriptor containing endpoint and ID fields.
 * @param[in]  invConf       Inventory configuration from the platform.
 * @param[in]  pemList       Certificates read from the on-disk store.
 * @param[out] pStatus       Receives the result status of the update.
 * @param[out] pMessage      Accumulates human-readable status messages.
 * @return 0 on success, non-zero on failure.
 */
static int send_inventory_comparison(const char *sessionToken,
                                     const SessionJob_t *jobInfo,
                                     const InventoryConfigResp_t *invConf,
                                     const PemInventoryList *pemList,
                                     enum AgentApiResultStatus *pStatus,
                                     char **pMessage)
{
    InventoryUpdateList_t *updateList = NULL;
    InventoryUpdateResp_t *updResp   = NULL;
    int res = 0;

    compute_inventory_update(invConf->Job.Inventory,
                             invConf->Job.Inventory_count,
                             pemList, &updateList);

    res = send_inventory_update(sessionToken, jobInfo->JobId,
                                invConf->InventoryEndpoint,
                                updateList, &updResp);
    if (res != 0) {
        log_error("%s::%s(%d) : Failed to send inventory update", LOG_INF);
        *pStatus = STAT_ERR;
    } else if (updResp) {
        AgentApiResult_log(updResp->Result, pMessage, pStatus);
    }

    if (updateList) InventoryUpdateList_free(updateList);
    if (updResp)    InventoryUpdateResp_free(updResp);

    return res;
} /* send_inventory_comparison */


/**
 * @brief Reads the on-disk store and drives the full inventory comparison cycle.
 *
 * Reads the PEM store into memory, delegates comparison and submission to
 * send_inventory_comparison, then frees the PEM list.
 *
 * @param[in]  sessionToken  GUID for the current curl session.
 * @param[in]  jobInfo       Job descriptor containing endpoint and ID fields.
 * @param[in]  invConf       Inventory configuration from the platform.
 * @param[out] pStatus       Receives the result status of the operation.
 * @param[out] pMessage      Accumulates human-readable status messages.
 * @return 0 on success, non-zero on failure.
 */
static int run_inventory_operations(const char *sessionToken,
                                    const SessionJob_t *jobInfo,
                                    const InventoryConfigResp_t *invConf,
                                    enum AgentApiResultStatus *pStatus,
                                    char **pMessage)
{
    PemInventoryList *pemList = NULL;
    int res = 0;

    log_trace("%s::%s(%d) : Reading inventory store at %s",
              LOG_INF, invConf->Job.StorePath);

    res = ssl_read_store_inventory(invConf->Job.StorePath,
                                   invConf->Job.StorePassword, &pemList);
    if (res != 0) {
        log_error("%s::%s(%d) : Failed to read store inventory", LOG_INF);
        *pStatus = STAT_ERR;
        append_line(pMessage, strerror(res));
        return res;
    }

    res = send_inventory_comparison(sessionToken, jobInfo, invConf,
                                    pemList, pStatus, pMessage);

    if (pemList) {
        log_trace("%s::%s(%d) : Freeing pemList containing %d items",
                  LOG_INF, pemList->item_count);
        PemInventoryList_free(pemList);
    }

    return res;
} /* run_inventory_operations */


/**
 * @brief Sends job completion to the platform and logs the final outcome.
 *
 * Transmits the final status, then logs success, warning, or error depending
 * on the reported status value.
 *
 * @param[in]  sessionToken   GUID for the current curl session.
 * @param[in]  jobInfo        Job descriptor containing endpoint and ID fields.
 * @param[in]  status         Final result status of the inventory operation.
 * @param[in]  auditId        Audit record ID associated with this job.
 * @param[in]  statusMessage  Human-readable result or error message to send.
 * @return 0 on success, 999 if the completion POST itself fails.
 */
static int finalize_inventory_job(const char *sessionToken,
                                  const SessionJob_t *jobInfo,
                                  enum AgentApiResultStatus status,
                                  long auditId,
                                  const char *statusMessage)
{
    CommonCompleteResp_t *invComp = NULL;

    int res = send_inventory_job_complete(sessionToken, jobInfo->JobId,
                                          jobInfo->CompletionEndpoint,
                                          status + 1, auditId,
                                          statusMessage, &invComp);
    if (res != 0) {
        log_error("%s::%s(%d) : Failed to send inventory job complete",
                  LOG_INF);
        CommonCompleteResp_free(invComp);
        return 999;
    }

    if (invComp)
        AgentApiResult_log(invComp->Result, NULL, NULL);

    if (status >= STAT_ERR) {
        log_error("%s::%s(%d) : Inventory job %s failed with error: %s",
                  LOG_INF, jobInfo->JobId, statusMessage);
    } else if (status == STAT_WARN) {
        log_warn("%s::%s(%d) : Inventory job %s completed with warning: %s",
                 LOG_INF, jobInfo->JobId, statusMessage);
    } else {
        log_info("%s::%s(%d) : Inventory job %s completed successfully",
                 LOG_INF, jobInfo->JobId);
    }

    CommonCompleteResp_free(invComp);
    return (status >= STAT_ERR) ? 999 : 0;
} /* finalize_inventory_job */


/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * @brief Entry point for the certificate inventory job.
 *
 * Orchestrates the full inventory job lifecycle:
 *   1. Fetches the job configuration from the platform.
 *   2. Validates the store configuration.
 *   3. Exits early if the job was cancelled.
 *   4. Reads the store, computes the delta, and submits the update.
 *   5. Reports job completion back to the platform.
 *
 * @param[in]  jobInfo       Job descriptor received from the scheduler.
 * @param[in]  sessionToken  GUID for the current curl session.
 * @return 0 on success, 1 if the job was cancelled, 999 on error.
 */
int cms_job_inventory(SessionJob_t *jobInfo, char *sessionToken)
{
    InventoryConfigResp_t    *invConf      = NULL;
    char                     *statusMessage = strdup("");
    enum AgentApiResultStatus status        = STAT_UNK;
    int                       returnable   = 0;
    int                       res          = 0;

    log_info("%s::%s(%d) : Starting inventory job %s",
             LOG_INF, jobInfo->JobId);

    res = get_inventory_config(sessionToken, jobInfo->JobId,
                               jobInfo->ConfigurationEndpoint, &invConf);
    if (res != 0) {
        log_error("%s::%s(%d) : Failed to get inventory config", LOG_INF);
        free(statusMessage);
        return 999;
    }

    if (!invConf) {
        log_error("%s::%s(%d) : No inventory configuration returned from "
                  "the platform.", LOG_INF);
        free(statusMessage);
        return 999;
    }

    if (!inventory_store_config_valid(invConf, &statusMessage)) {
        CommonCompleteResp_t *invComp = NULL;
        send_inventory_job_complete(sessionToken, jobInfo->JobId,
                                    jobInfo->CompletionEndpoint,
                                    STAT_ERR, invConf->AuditId,
                                    statusMessage, &invComp);
        CommonCompleteResp_free(invComp);
        returnable = 999;
        goto exit;
    }

    if (!AgentApiResult_log(invConf->Result, &statusMessage, &status)) {
        returnable = 999;
        goto exit;
    }

    if (invConf->JobCancelled) {
        log_info("%s::%s(%d) : Job has been cancelled and will not be run",
                 LOG_INF);
        returnable = 1;
        goto exit;
    }

    log_verbose("%s::%s(%d) : Audit Id: %ld", LOG_INF, invConf->AuditId);

    res = run_inventory_operations(sessionToken, jobInfo, invConf,
                                   &status, &statusMessage);
    if (res != 0)
        returnable = 999;

    returnable = finalize_inventory_job(sessionToken, jobInfo, status,
                                        invConf->AuditId, statusMessage);

exit:
    InventoryConfigResp_free(invConf);
    free(statusMessage);
    return returnable;
} /* cms_job_inventory */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
