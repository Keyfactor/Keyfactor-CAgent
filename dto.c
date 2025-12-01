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

#include "dto.h"
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include "lib/json.h"
#include "logging.h"
#include <string.h>
#include <stdbool.h>

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/
#define MAX_BUF_LEN 1024        /* Maximum buffer length */

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
static void AgentApiResult_free(AgentApiResult_t result)
{
    if (result.Error.Message) {
        free(result.Error.Message);
        result.Error.Message = NULL;
    }
    if (result.Error.CodeString) {
        free(result.Error.CodeString);
        result.Error.CodeString = NULL;
    }
} /* AgentApiResult_free */

static AgentApiResult_t AgentApiResult_fromJsonNode(JsonNode * jsonResult) {
    AgentApiResult_t result;
    JsonNode *jsonError = NULL;
    char *tempString = NULL;

    if (jsonResult) {
        result.Status = json_get_member_number(jsonResult, "Status", 0);

        jsonError = json_find_member(jsonResult, "Error");
        if (jsonError) {
            result.Error.Code = json_get_member_number(jsonError, "Code", 0);
            tempString = json_get_member_string(jsonError, "CodeString");
            if (NULL == tempString) {
                result.Error.CodeString =
                    json_get_member_string(jsonError, "HResult");
            } else {
                result.Error.CodeString = tempString;
            }
            result.Error.Message = json_get_member_string(jsonError, "Message");
        } else {
            result.Error.Code = 0;
            result.Error.CodeString = NULL;
            result.Error.Message = NULL;
        }
    } else {
        result.Status = STAT_ERR;
        result.Error.Code = 999;
        result.Error.Message = strdup("Unknown Error");
        result.Error.CodeString = strdup("Unknown Error");
    }

    return result;
} /* AgentApiResult_fromJsonNode */

bool AgentApiResult_log(AgentApiResult_t result,
                        char **pMessage, enum AgentApiResultStatus *pStatus)
{
    int messageLen = 20;
    char *introBuf = NULL;
    char buf[MAX_BUF_LEN];

    log_trace("%s::%s(%d) : Decoding agent api result",
              LOG_INF);
    if (pStatus && *pStatus < result.Status) {
        *pStatus = result.Status;
    }

    if (result.Status == STAT_ERR || result.Status == STAT_WARN) {
        introBuf = (result.Status == STAT_ERR ?
                    strdup("Error") : strdup("Warning"));
        if (result.Error.Message && result.Error.CodeString) {
            messageLen = 20 + strlen(result.Error.Message) +
                strlen(result.Error.CodeString);

        } else if (result.Error.Message) {
            messageLen = 20 + strlen(result.Error.Message);
        }

        snprintf(buf, (size_t) messageLen, "%s: %s (%s)\n",
                 introBuf ? introBuf : "Unknown",
                 result.Error.Message ? result.Error.Message : "No message",
                 result.Error.CodeString ? result.Error.CodeString : "No code");
        log_error("%s::%s(%d) : %s", LOG_INF, buf);

        if (pMessage && *pMessage) {
            log_trace("%s::%s(%d) : reallocating pMessage", LOG_INF);
            char *newMessage = realloc(*pMessage, strlen(*pMessage) + messageLen);
            if (newMessage) {
                *pMessage = newMessage;
                strcat(*pMessage, buf);
            } else {
                log_error("%s::%s(%d) : Failed to reallocate pMessage", LOG_INF);
            }
        }
    }

    if (NULL != introBuf) {
        free(introBuf);
    }

    if ((result.Status == STAT_ERR) || (result.Status == STAT_WARN)) {
        return false;
    } else {
        return true;
    }
} /* AgentApiResult_log */

static ClientParameter_t * ClientParameter_new(const char *key,
                                               const char *value){
    ClientParameter_t *cp = calloc(1, sizeof(ClientParameter_t));
    if (!cp) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        return NULL;
    }
    if (key) {
        cp->Key = strdup(key);
        if (!cp->Key) {
            log_error("%s::%s(%d) : Failed to allocate Key", LOG_INF);
            free(cp);
            return NULL;
        }
    } else {
        cp->Key = NULL;
    }
    if (value) {
        cp->Value = strdup(value);
        if (!cp->Value) {
            log_error("%s::%s(%d) : Failed to allocate Value", LOG_INF);
            free(cp->Key);
            free(cp);
            return NULL;
        }
    } else {
        cp->Value = NULL;
    }

    return cp;
} /* ClientParameter_new */

static void ClientParameter_free(ClientParameter_t * cliParam)
{
    if (cliParam) {
        if (cliParam->Key) {
            free(cliParam->Key);
            cliParam->Key = NULL;
        }
        if (cliParam->Value) {
            free(cliParam->Value);
            cliParam->Value = NULL;
        }
        free(cliParam);
    }
} /* ClientParameter_free */

/*                                                                            */
/* Add an additional ClientParameter to the session after the                 */
/* ClientParameterPath has been processed.                                    */
/*                                                                            */
/* @param  - [Input/Output] req: A pointer to the SessionRegisterRequest      */
/* @param  - [Input] key: The string to add to the key variable client        */
/* parameter                                                                  */
/* @param  - [Input] value: The string to add to the value variable client    */
/* parameter                                                                  */
/* @return - Success: true                                                    */
/* Failure: false                                                             */
/*                                                                            */
bool SessionRegisterReq_addNewClientParameter(SessionRegisterReq_t * req,
                                         const char *key, const char *value)
{
    bool bResult = false;
    int index;

    if (!req) {
        log_error("%s::%s(%d) : Null pointer dereference - req is NULL", LOG_INF);
        return false;
    }

    index = req->ClientParameters_count;

    req->ClientParameters_count++;
    log_trace("%s::%s(%d) Increasing parameter count to %d",
              LOG_INF, req->ClientParameters_count);
    req->ClientParameters = realloc(req->ClientParameters,
               (req->ClientParameters_count * sizeof(ClientParameter_t *)));
    if (NULL == req->ClientParameters) {
        log_error("%s::%s(%d) : Out of memory error",
                  LOG_INF);
        return false;
    }

    req->ClientParameters[index] = ClientParameter_new(key, value);
    if (NULL != req->ClientParameters[index]) {
        log_trace("%s::%s(%d) : Successfully added key= %s with "
                  "value= %s to ClientParameters", LOG_INF, key, value);
        bResult = true;
    } else {
        log_error("%s::%s(%d) : Error adding new client parameters"
                  " to SessionRegisterRequest", LOG_INF);
        bResult = false;
        /* Reset things */
        free(req->ClientParameters[index]);
        req->ClientParameters_count--;
    }

    return bResult;
} /* SessionRegisterReq_addNewClientParameter */

SessionRegisterReq_t *SessionRegisterReq_new(char *clientParamPath)
{
    SessionRegisterReq_t *req = calloc(1, sizeof(*req));
    if (!req) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        return NULL;
    }

    req->Capabilities_count = 0;
    req->TenantId = strdup("00000000-0000-0000-0000-000000000000");
    req->ClientParameters_count = 0;

    if (clientParamPath) {
        log_trace("%s::%s(%d) : Found client parameters -- adding them"
                  " to the session", LOG_INF);
        FILE *fp = fopen(clientParamPath, "r");
        if (fp) {
            /* Client parameter file should never be anywhere near this long */
            char buf[4096];
            size_t len = fread(buf, 1, 4095, fp);
            buf[len++] = '\0';

            JsonNode *jsonRoot = json_decode(buf);
            if (jsonRoot && jsonRoot->tag == JSON_OBJECT) {
                JsonNode *curNode;
                int nodeCount = 0;
                json_foreach(curNode, jsonRoot) {       /* Loop first to get
                                                         * count */
                    if (curNode->tag == JSON_STRING) {
                        nodeCount++;
                    }
                }

                req->ClientParameters = calloc(nodeCount,
                                            sizeof(*req->ClientParameters));
                req->ClientParameters_count = nodeCount;

                nodeCount = 0;
                json_foreach(curNode, jsonRoot) {
                    if (curNode->tag == JSON_STRING &&
                        curNode->key &&
                        curNode->string_) {
                        req->ClientParameters[nodeCount++] =
                            ClientParameter_new(curNode->key, curNode->string_);
                    }
                }

                json_delete(jsonRoot);
            } else {
                log_error("%s::%s(%d) : Contents of %s are not valid JSON",
                          LOG_INF, clientParamPath);
            }
            (void)fclose(fp);   /* Deallocate memory associated with this
                                 * file */
        } else {
            int err = errno;
            log_error(\
                 "%s::%s(%d) : Unable to open client parameter file %s: %s",
                      LOG_INF, clientParamPath, strerror(err));
        }
    }

    return req;
} /* SessionRegisterReq_new */

void SessionRegisterReq_free(SessionRegisterReq_t * req)
{
    if (req) {
        if (req->TenantId) {
            free(req->TenantId);
            req->TenantId = NULL;
        }
        if (req->ClientMachine) {
            free(req->ClientMachine);
            req->ClientMachine = NULL;
        }
        /* Agent Platform is an enum, no need to free */
        if (req->Capabilities) {
            for (int i = 0; i < req->Capabilities_count; ++i) {
                free(req->Capabilities[i]);
                req->Capabilities[i] = NULL;
            }
            free(req->Capabilities);
            req->Capabilities = NULL;
        }
        /* Capabilities count is an int, no need to free */
        /* Agent version is an int, no need to free */
        if (req->AgentId) {
            free(req->AgentId);
            req->AgentId = NULL;
        }
        /* Free the entire array */
        if (req->ClientParameters) {
            for (int i = 0; i < req->ClientParameters_count; ++i) {
                ClientParameter_free(req->ClientParameters[i]);
                req->ClientParameters[i] = NULL;
            }
            free(req->ClientParameters);
            req->ClientParameters = NULL;
        }
        /* ClientParameters_count is an int, no need to free */
        if (req->CSR) {
            free(req->CSR);
            req->CSR = NULL;
        }
        free(req);
        req = NULL;
    }
} /* SessionRegisterReq_free */

char *SessionRegisterReq_toJson(SessionRegisterReq_t * req)
{
    char *jsonString = NULL;

    if (req) {
        JsonNode *jsonRoot = json_mkobject();
        json_append_member(jsonRoot, "AgentPlatform",
                           json_mknumber(req->AgentPlatform));
        json_append_member(jsonRoot, "AgentVersion",
                           json_mknumber(req->AgentVersion));

        if (req->TenantId) {
            json_append_member(jsonRoot, "TenantId",
                               json_mkstring(req->TenantId));
        } else {
            json_append_member(jsonRoot, "TenantId",
                               json_mknull());
        }
        if (req->ClientMachine) {
            json_append_member(jsonRoot, "ClientMachine",
                               json_mkstring(req->ClientMachine));
        } else {
            json_append_member(jsonRoot, "ClientMachine",
                               json_mknull());
        }
        if (req->CSR) {
            json_append_member(jsonRoot, "CSR",
                               json_mkstring(req->CSR));
        } else {
            json_append_member(jsonRoot, "CSR",
                               json_mknull());
        }
        if (req->AgentId) {
            json_append_member(jsonRoot, "AgentId",
                               json_mkstring(req->AgentId));
        } else {
            json_append_member(jsonRoot, "AgentId",
                               json_mknull());
        }

        JsonNode *jsonCaps = json_mkarray();
        if (req->Capabilities) {
            for (int i = 0; i < req->Capabilities_count; ++i) {
                if (req->Capabilities[i]) {
                    json_append_element(jsonCaps,
                                        json_mkstring(req->Capabilities[i]));
                }
            }
        }
        json_append_member(jsonRoot, "Capabilities", jsonCaps);

        JsonNode *jsonCliParams = json_mkobject();
        if (req->ClientParameters) {
            for (int i = 0; i < req->ClientParameters_count; ++i) {
                if (req->ClientParameters[i]) {
                    json_append_member(jsonCliParams,
                                       req->ClientParameters[i]->Key,
                            json_mkstring(req->ClientParameters[i]->Value));
                }
            }
        }
        json_append_member(jsonRoot, "ClientParameters", jsonCliParams);

        jsonString = json_encode(jsonRoot);
        json_delete(jsonRoot);
    }

    return jsonString;
} /* SessionRegisterReq_toJson */


void SessionJob_free(SessionJob_t * job)
{
    if (job) {
        if (job->CompletionEndpoint) {
            free(job->CompletionEndpoint);
            job->CompletionEndpoint = NULL;
        }
        if (job->ConfigurationEndpoint) {
            free(job->ConfigurationEndpoint);
            job->ConfigurationEndpoint = NULL;
        }
        if (job->Cron) {
            free(job->Cron);
            job->Cron = NULL;
        }
        if (job->JobId) {
            free(job->JobId);
            job->JobId = NULL;
        }
        if (job->JobTypeId) {
            free(job->JobTypeId);
            job->JobTypeId = NULL;
        }
        if (job->Schedule) {
            free(job->Schedule);
            job->Schedule = NULL;
        }
        free(job);
    }
} /* SessionJob_free */

void SessionRegisterResp_freeJobs(SessionRegisterResp_t * resp)
{
    int lp = 0;

    if (!resp) {
        log_error("%s::%s(%d) : Null pointer dereference - resp is NULL", LOG_INF);
        return;
    }

    while (lp < resp->Session.Jobs_count) {
        if (resp->Session.Jobs[lp]) {
            log_info("%s::%s(%d) : Freeing job # %s", LOG_INF,
                     resp->Session.Jobs[lp]->JobId ? resp->Session.Jobs[lp]->JobId : "(null)");
            SessionJob_free(resp->Session.Jobs[lp]);
            resp->Session.Jobs[lp] = NULL;
        }
        lp++;
    }

    if (resp->Session.Jobs) {
        free(resp->Session.Jobs);
        resp->Session.Jobs = NULL;
    }

    return;
} /* SessionRegisterResp_freeJobs */

void SessionRegisterResp_free(SessionRegisterResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);
        if (resp->Session.AgentId) {
            free(resp->Session.AgentId);
            resp->Session.AgentId = NULL;
        }
        if (resp->Session.Token) {
            free(resp->Session.Token);
            resp->Session.Token = NULL;
        }
        if (resp->Session.ClientMachine) {
            free(resp->Session.ClientMachine);
            resp->Session.ClientMachine = NULL;
        }
        if (resp->Session.Certificate) {
            free(resp->Session.Certificate);
            resp->Session.Certificate = NULL;
        }
        if (resp->Session.Jobs) {
#if defined(__NEVER_COMPILE_THIS__)
            /*
             * Ownership of these will be handed off & freed elsewhere
             */
            /*
             * for(int i = 0; i < resp->Session.Jobs_count; ++i)
             */
            /*
             * {
             */
            /* SessionJob_free(resp->Session.Jobs[i]);                       */
            /* resp->Session.Jobs[i] = NULL;                                 */
            /*
             * }
             */
#endif                          /* Never Compile this Code */
            free(resp->Session.Jobs);
            resp->Session.Jobs = NULL;
        }
        if (resp->Session.ClientParameters) {
            for (int i = 0; i < resp->Session.ClientParameters_count; ++i) {
                ClientParameter_free(resp->Session.ClientParameters[i]);
                resp->Session.ClientParameters[i] = NULL;
            }
            free(resp->Session.ClientParameters);
            resp->Session.ClientParameters = NULL;
        }
        free(resp);
    }
} /* SessionRegisterResp_free */

static SessionJob_t* SessionJob_fromJsonNode(JsonNode * jsonJob) {
    SessionJob_t *job = NULL;
    if (jsonJob) {
        job = calloc(1, sizeof(SessionJob_t));
        if (!job) {
            log_error("%s::%s(%d) : Null pointer dereference - failed to allocate SessionJob_t", LOG_INF);
            return NULL;
        }
        job->CompletionEndpoint = json_get_member_string(jsonJob,
                                                      "CompletionEndpoint");
        job->ConfigurationEndpoint = json_get_member_string(jsonJob,
                                                   "ConfigurationEndpoint");
        job->Cron = json_get_member_string(jsonJob, "Cron");
        job->JobId = json_get_member_string(jsonJob, "JobId");
        job->JobTypeId = json_get_member_string(jsonJob, "JobTypeId");
        job->Schedule = json_get_member_string(jsonJob, "Schedule");
        job->Priority = json_get_member_number(jsonJob, "Priority", 5);
    }

    return job;
} /* SessionJob_fromJsonNode */

SessionRegisterResp_t *SessionRegisterResp_fromJson(char *jsonString)
{
    JsonNode *jsonRoot = NULL;
    JsonNode *jsonSession = NULL;
    int jobCount = 0;
    JsonNode *jsonJobs = NULL;
    JsonNode *jsonTmp = NULL;
    int current = 0;
    JsonNode *jsonParams = NULL;
    JsonNode *jsonResult = NULL;
    SessionRegisterResp_t *resp = NULL;

    resp = calloc(1, sizeof(SessionRegisterResp_t));
    if (NULL == resp) {
        log_error("%s::%s(%d) : Out of memory allocating Session Response",
                  LOG_INF);
        return NULL;
    }

    if (jsonString) {
        jsonRoot = json_decode(jsonString);
        if (jsonRoot) {
            jsonSession = json_find_member(jsonRoot, "Session");
            if (jsonSession) {
                resp->Session.Token =
                    json_get_member_string(jsonSession, "Token");
                resp->Session.AgentId =
                    json_get_member_string(jsonSession, "AgentId");
                resp->Session.Certificate =
                    json_get_member_string(jsonSession, "Certificate");
                resp->Session.ClientMachine =
                    json_get_member_string(jsonSession, "ClientMachine");
                resp->Session.HeartbeatInterval =
                    json_get_member_number(jsonSession, "HeartbeatInterval", 5);

                jsonJobs = json_find_member(jsonSession, "Jobs");
                jobCount = json_array_size(jsonJobs);
                resp->Session.Jobs_count = jobCount;
                resp->Session.Jobs = calloc(jobCount,
                                            sizeof(SessionJob_t *));
                if (NULL == resp->Session.Jobs) {
                    log_error("%s::%s(%d) : Out of memory allocating"
                              " Session.Jobs", LOG_INF);

                    if (resp) {
                        /* Free any allocated memory before returning */
                        SessionRegisterResp_free(resp);
                    }
                    return NULL;
                }

                current = 0;
                json_foreach(jsonTmp, jsonJobs) {
                    resp->Session.Jobs[current++] =
                        SessionJob_fromJsonNode(jsonTmp);
                }

                jsonParams = json_find_member(jsonSession, "ClientParameters");
                if (jsonParams && jsonParams->tag == JSON_OBJECT) {
                    current = 0;
                    json_foreach(jsonTmp, jsonParams) {
                        current++;
                    }

                    resp->Session.ClientParameters = calloc(current,
                                               sizeof(ClientParameter_t *));
                    if (NULL == resp->Session.ClientParameters) {
                        log_error("%s::%s(%d) : Out of memory allocating"
                                  " ClientParameters", LOG_INF);
                        if (resp) {
                            /* Free any allocated memory before returning */
                            /* Note, we may have jobs at this point.      */
                            /* So manually free them first, as the        */
                            /* SessionRegisterResp_free will not do that  */
                            SessionRegisterResp_freeJobs(resp);
                            SessionRegisterResp_free(resp);
                        }
                        return NULL;
                    }
                    current = 0;
                    json_foreach(jsonTmp, jsonParams) {
                        if (jsonTmp && jsonTmp->tag == JSON_STRING &&
                            jsonTmp->string_) {
                            resp->Session.ClientParameters[current++] =
                                ClientParameter_new(jsonTmp->key, jsonTmp->string_);
                        }
                    }
                    resp->Session.ClientParameters_count = current;
                }
            }

            jsonResult = json_find_member(jsonRoot, "Result");
            if (jsonResult) {
                resp->Result = AgentApiResult_fromJsonNode(jsonResult);
            }

            json_delete(jsonRoot);
        }
    }

    return resp;
} /* SessionRegisterResp_fromJson */

CommonConfigReq_t *CommonConfigReq_new()
{
    return calloc(1, sizeof(CommonConfigReq_t));
} /* CommonConfigReq_new */

void CommonConfigReq_free(CommonConfigReq_t * req)
{
    if (req) {
        if (req->JobId) {
            free(req->JobId);
            req->JobId = NULL;
        }
        if (req->SessionToken) {
            free(req->SessionToken);
            req->SessionToken = NULL;
        }
        free(req);
    }
} /* CommonConfigReq_free */

char *CommonConfigReq_toJson(CommonConfigReq_t * req)
{
    char *jsonString = NULL;

    if (req) {
        JsonNode *jsonRoot = json_mkobject();
        if (req->SessionToken) {
            json_append_member(jsonRoot, "SessionToken",
                               json_mkstring(req->SessionToken));
        } else {
            json_append_member(jsonRoot, "SessionToken", json_mknull());
        }
        if (req->JobId) {
            json_append_member(jsonRoot, "JobId", json_mkstring(req->JobId));
        } else {
            json_append_member(jsonRoot, "JobId", json_mknull());
        }

        jsonString = json_encode(jsonRoot);
        json_delete(jsonRoot);
    }

    return jsonString;
} /* CommonConfigReq_toJson */

CommonCompleteReq_t *CommonCompleteReq_new()
{
    return calloc(1, sizeof(CommonCompleteReq_t));
} /* CommonCompleteReq_new */

void CommonCompleteReq_free(CommonCompleteReq_t * req)
{
    if (req) {
        if (req->JobId) {
            free(req->JobId);
            req->JobId = NULL;
        }
        if (req->SessionToken) {
            free(req->SessionToken);
            req->SessionToken = NULL;
        }
        if (req->Message) {
            free(req->Message);
            req->Message = NULL;
        }
        free(req);
    }
} /* CommonCompleteReq_free */

char *CommonCompleteReq_toJson(CommonCompleteReq_t * req)
{
    char *jsonString = NULL;

    if (req) {
        JsonNode *jsonRoot = json_mkobject();
        json_append_member(jsonRoot, "Status",
                           json_mknumber((double)req->Status));
        json_append_member(jsonRoot, "AuditId",
                           json_mknumber((double)req->AuditId));
        if (req->JobId) {
            json_append_member(jsonRoot, "JobId", json_mkstring(req->JobId));
        } else {
            json_append_member(jsonRoot, "JobId", json_mknull());
        }
        if (req->Message) {
            json_append_member(jsonRoot, "Message",
                               json_mkstring(req->Message));
        } else {
            json_append_member(jsonRoot, "Message", json_mknull());
        }

        if (req->SessionToken) {
            json_append_member(jsonRoot, "SessionToken",
                               json_mkstring(req->SessionToken));
        } else {
            json_append_member(jsonRoot, "SessionToken", json_mknull());
        }

        jsonString = json_encode(jsonRoot);
        json_delete(jsonRoot);
    }

    return jsonString;
} /* CommonCompleteReq_toJson */

void CommonCompleteResp_free(CommonCompleteResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);
        free(resp);
    }
} /* CommonCompleteResp_free */

CommonCompleteResp_t *CommonCompleteResp_fromJson(char *jsonString)
{
    CommonCompleteResp_t *resp = NULL;
    if (jsonString) {
        JsonNode *jsonRoot = json_decode(jsonString);
        if (jsonRoot) {
            resp = calloc(1, sizeof(CommonCompleteResp_t));
            if (!resp) {
                log_error("%s::%s(%d) : Null pointer dereference - failed to allocate CommonCompleteResp_t", LOG_INF);
                json_delete(jsonRoot);
                return NULL;
            }

            JsonNode *jsonResult = json_find_member(jsonRoot, "Result");
            if (jsonResult) {
                resp->Result = AgentApiResult_fromJsonNode(jsonResult);
            }

            json_delete(jsonRoot);
        }
    }

    return resp;
} /* CommonCompleteResp_fromJson */

void ManagementConfigResp_free(ManagementConfigResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);
        if (resp->Job.Alias) {
            free(resp->Job.Alias);
            resp->Job.Alias = NULL;
        }
        if (resp->Job.ClientMachine) {
            free(resp->Job.ClientMachine);
            resp->Job.ClientMachine = NULL;
        }
        if (resp->Job.StorePath) {
            free(resp->Job.StorePath);
            resp->Job.StorePath = NULL;
        }
        if (resp->Job.StorePassword) {
            free(resp->Job.StorePassword);
            resp->Job.StorePassword = NULL;
        }
        if (resp->Job.EntryPassword) {
            free(resp->Job.EntryPassword);
            resp->Job.EntryPassword = NULL;
        }
        if (resp->Job.Thumbprint) {
            free(resp->Job.Thumbprint);
            resp->Job.Thumbprint = NULL;
        }
        if (resp->Job.EntryContents) {
            free(resp->Job.EntryContents);
            resp->Job.EntryContents = NULL;
        }
        if (resp->Job.PfxPassword) {
            free(resp->Job.PfxPassword);
            resp->Job.PfxPassword = NULL;
        }
        if (resp->Job.PrivateKeyPath) {
            free(resp->Job.PrivateKeyPath);
            resp->Job.PrivateKeyPath = NULL;
        }
        free(resp);
    }
} /* ManagementConfigResp_free */

ManagementConfigResp_t *ManagementConfigResp_fromJson(char *jsonString)
{
    ManagementConfigResp_t *resp = NULL;
    if (jsonString) {
        JsonNode *jsonRoot = json_decode(jsonString);
        if (jsonRoot) {
            resp = calloc(1, sizeof(ManagementConfigResp_t));
            if (!resp) {
                log_error("%s::%s(%d) : Null pointer dereference - failed to allocate ManagementConfigResp_t", LOG_INF);
                json_delete(jsonRoot);
                return NULL;
            }

            resp->AuditId = json_get_member_number(jsonRoot, "AuditId", 0);
            resp->JobCancelled =
                json_get_member_bool(jsonRoot, "JobCancelled", false);

            JsonNode *jsonResult = json_find_member(jsonRoot, "Result");
            if (jsonResult) {
                resp->Result = AgentApiResult_fromJsonNode(jsonResult);
            }
            JsonNode *jsonJob = json_find_member(jsonRoot, "Job");
            if (jsonJob) {
                resp->Job.Alias =
                    json_get_member_string(jsonJob, "Alias");
                resp->Job.Category =
                    json_get_member_number(jsonJob, "Category", 0);
                resp->Job.ClientMachine =
                    json_get_member_string(jsonJob, "ClientMachine");
                resp->Job.EntryContents =
                    json_get_member_string(jsonJob, "EntryContents");
                resp->Job.EntryPassword =
                    json_get_member_string(jsonJob, "EntryPassword");
                resp->Job.OperationType =
                    json_get_member_number(jsonJob, "OperationType", 0);
                resp->Job.Overwrite =
                    json_get_member_bool(jsonJob, "Overwrite", false);
                resp->Job.PfxPassword =
                    json_get_member_string(jsonJob, "PfxPassword");
                resp->Job.PrivateKeyEntry =
                    json_get_member_bool(jsonJob, "PrivateKeyEntry", false);
                resp->Job.StorePassword =
                    json_get_member_string(jsonJob, "StorePassword");
                resp->Job.StorePath =
                    json_get_member_string(jsonJob, "StorePath");
                resp->Job.StoreType =
                    json_get_member_number(jsonJob, "StoreType", 0);
                resp->Job.Thumbprint =
                    json_get_member_string(jsonJob, "Thumbprint");

                JsonNode *jsonProps = NULL;
                char *propString =
                json_get_member_string(jsonJob, "Properties");
                if (propString && (jsonProps = json_decode(propString))) {
                    resp->Job.PrivateKeyPath =
                        json_get_member_string(jsonProps, "PrivateKeyPath");
                }
                free(propString);
                json_delete(jsonProps);
            }

            json_delete(jsonRoot);
        }
    }

    return resp;
} /* ManagementConfigResp_fromJson */

void ManagementCompleteResp_free(ManagementCompleteResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);

        if (resp->InventoryJob) {
            free(resp->InventoryJob);
            resp->InventoryJob = NULL;
        }

        free(resp);
    }
} /* ManagementCompleteResp_free */

ManagementCompleteResp_t *ManagementCompleteResp_fromJson(char *jsonString)
{
    ManagementCompleteResp_t *resp = NULL;
    if (jsonString) {
        JsonNode *jsonRoot = json_decode(jsonString);
        if (jsonRoot) {
            resp = calloc(1, sizeof(ManagementCompleteResp_t));
            if (!resp) {
                log_error("%s::%s(%d) : Null pointer dereference - failed to allocate ManagementCompleteResp_t", LOG_INF);
                json_delete(jsonRoot);
                return NULL;
            }

            JsonNode *jsonResult = json_find_member(jsonRoot, "Result");
            if (jsonResult) {
                resp->Result = AgentApiResult_fromJsonNode(jsonResult);
            }

            resp->InventoryJob =
                json_get_member_string(jsonRoot, "InventoryJob");

            json_delete(jsonRoot);
        }
    }

    return resp;
} /* ManagementCompleteResp_fromJson */

static void InventoryCurrentItem_free(InventoryCurrentItem_t * item)
{
    if (item) {
        if (item->Alias) {
            free(item->Alias);
            item->Alias = NULL;
        }
        if (item->Thumbprints) {
            for (int i = 0; i < item->Thumbprints_count; ++i) {
                free(item->Thumbprints[i]);
                item->Thumbprints[i] = NULL;
            }
            free(item->Thumbprints);
            item->Thumbprints = NULL;
        }
        free(item);
    }
} /* InventoryCurrentItem_free */

static InventoryCurrentItem_t *
InventoryCurrentItem_fromJsonNode(JsonNode * node) {
    InventoryCurrentItem_t *result = NULL;

    if (node) {
        result = calloc(1, sizeof(InventoryCurrentItem_t));
        if (!result) {
            log_error("%s::%s(%d) : Null pointer dereference - failed to allocate InventoryCurrentItem_t", LOG_INF);
            return NULL;
        }

        result->Alias = json_get_member_string(node, "Alias");
        result->PrivateKeyEntry =
            json_get_member_bool(node, "PrivateKeyEntry", false);

        JsonNode *jsonThumbs = json_find_member(node, "Thumbprints");
        if (jsonThumbs) {
            int thumbCount = json_array_size(jsonThumbs);
            result->Thumbprints_count = thumbCount;
            result->Thumbprints = calloc(thumbCount, sizeof(char *));

            int current = 0;
            JsonNode *jsonTmp = NULL;
            json_foreach(jsonTmp, jsonThumbs) {
                result->Thumbprints[current++] = json_get_value_string(jsonTmp);
            }
        }
    }

    return result;
} /* InventoryCurrentItem_fromJsonNode */

void InventoryConfigResp_free(InventoryConfigResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);
        if (resp->InventoryEndpoint) {
            free(resp->InventoryEndpoint);
            resp->InventoryEndpoint = NULL;
        }
        if (resp->Job.ClientMachine) {
            free(resp->Job.ClientMachine);
            resp->Job.ClientMachine = NULL;
        }
        if (resp->Job.StorePath) {
            free(resp->Job.StorePath);
            resp->Job.StorePath = NULL;
        }
        if (resp->Job.StorePassword) {
            free(resp->Job.StorePassword);
            resp->Job.StorePassword = NULL;
        }
        if (resp->Job.Inventory) {
            for (int i = 0; i < resp->Job.Inventory_count; ++i) {
                InventoryCurrentItem_free(resp->Job.Inventory[i]);
                resp->Job.Inventory[i] = NULL;
            }
            free(resp->Job.Inventory);
            resp->Job.Inventory = NULL;
        }
        free(resp);
    }
} /* InventoryConfigResp_free */

InventoryConfigResp_t *InventoryConfigResp_fromJson(char *jsonString)
{
    InventoryConfigResp_t *resp = NULL;
    if (jsonString) {
        JsonNode *jsonRoot = json_decode(jsonString);
        if (jsonRoot) {
            resp = calloc(1, sizeof(InventoryConfigResp_t));
            if (!resp) {
                log_error("%s::%s(%d) : Null pointer dereference - failed to allocate InventoryConfigResp_t", LOG_INF);
                json_delete(jsonRoot);
                return NULL;
            }

            resp->AuditId = json_get_member_number(jsonRoot, "AuditId", 0);
            resp->JobCancelled =
                json_get_member_bool(jsonRoot, "JobCancelled", false);
            resp->InventoryEndpoint =
                json_get_member_string(jsonRoot, "InventoryEndpoint");

            JsonNode *jsonResult = json_find_member(jsonRoot, "Result");
            if (jsonResult) {
                resp->Result = AgentApiResult_fromJsonNode(jsonResult);
            }
            JsonNode *jsonJob = json_find_member(jsonRoot, "Job");
            if (jsonJob) {
                resp->Job.Category =
                    json_get_member_number(jsonJob, "Category", 0);
                resp->Job.ClientMachine =
                    json_get_member_string(jsonJob, "ClientMachine");
                resp->Job.StorePassword =
                    json_get_member_string(jsonJob, "StorePassword");
                resp->Job.StorePath =
                    json_get_member_string(jsonJob, "StorePath");

                JsonNode *jsonInv = json_find_member(jsonJob, "Inventory");
                if (jsonInv) {
                    int invCount = json_array_size(jsonInv);
                    resp->Job.Inventory_count = invCount;
                    resp->Job.Inventory = calloc(invCount,
                                          sizeof(InventoryCurrentItem_t *));
                    if (!resp->Job.Inventory) {
                        log_error("%s::%s(%d) : Null pointer dereference - failed to allocate Inventory array", LOG_INF);
                        json_delete(jsonRoot);
                        InventoryConfigResp_free(resp);
                        return NULL;
                    }

                    JsonNode *jsonTmp;
                    int current = 0;
                    json_foreach(jsonTmp, jsonInv) {
                        resp->Job.Inventory[current++] =
                            InventoryCurrentItem_fromJsonNode(jsonTmp);
                    }
                }
            }

            json_delete(jsonRoot);
        }
    }

    return resp;
} /* InventoryConfigResp_fromJson */

static void InventoryUpdateItem_free(InventoryUpdateItem_t * item)
{
    if (item) {
        if (item->Alias) {
            free(item->Alias);
            item->Alias = NULL;
        }
        if (item->Certificates) {
            for (int i = 0; i < item->Certificates_count; ++i) {
                free(item->Certificates[i]);
                item->Certificates[i] = NULL;
            }
            free(item->Certificates);
            item->Certificates = NULL;
        }
        free(item);
    }
} /* InventoryUpdateItem_free */

static JsonNode *
InventoryUpdateItem_toJsonNode(InventoryUpdateItem_t * updateItem) {
    JsonNode *result = NULL;

    if (updateItem) {
        result = json_mkobject();
        json_append_member(result, "PrivateKeyEntry",
                           json_mkbool(updateItem->PrivateKeyEntry));
        json_append_member(result, "UseChainLevel",
                           json_mkbool(updateItem->UseChainLevel));
        json_append_member(result, "ItemStatus",
                           json_mknumber(updateItem->ItemStatus));
        if (updateItem->Alias) {
            json_append_member(result, "Alias",
                               json_mkstring(updateItem->Alias));
        } else {
            json_append_member(result, "Alias", json_mknull());
        }

        JsonNode *jsonCerts = json_mkarray();
        if (updateItem->Certificates) {
            for (int i = 0; i < updateItem->Certificates_count; ++i) {
                json_append_element(jsonCerts,
                                json_mkstring(updateItem->Certificates[i]));
            }
        }
        json_append_member(result, "Certificates", jsonCerts);
    }

    return result;
} /* InventoryUpdateItem_toJsonNode */

void InventoryUpdateReq_free(InventoryUpdateReq_t * req)
{
    if (req) {
        if (req->JobId) {
            free(req->JobId);
            req->JobId = NULL;
        }
        if (req->SessionToken) {
            free(req->SessionToken);
            req->SessionToken = NULL;
        }

        for (int i = 0; i < req->Inventory.count; ++i) {
            InventoryUpdateItem_free(req->Inventory.items[i]);
            req->Inventory.items[i] = NULL;
        }
        free(req);
    }
} /* InventoryUpdateReq_free */

char           *InventoryUpdateReq_toJson(InventoryUpdateReq_t * req)
{
    char *jsonString = NULL;

    if (req) {
        JsonNode *jsonRoot = json_mkobject();
        if (req->SessionToken) {
            json_append_member(jsonRoot, "SessionToken",
                               json_mkstring(req->SessionToken));
        } else {
            json_append_member(jsonRoot, "SessionToken", json_mknull());
        }
        if (req->JobId) {
            json_append_member(jsonRoot, "JobId", json_mkstring(req->JobId));
        } else {
            json_append_member(jsonRoot, "JobId", json_mknull());
        }

        JsonNode *jsonInv = json_mkarray();

        for (int i = 0; i < req->Inventory.count; ++i) {
            json_append_element(jsonInv,
                   InventoryUpdateItem_toJsonNode(req->Inventory.items[i]));
        }
        json_append_member(jsonRoot, "Inventory", jsonInv);

        jsonString = json_encode(jsonRoot);
        json_delete(jsonRoot);
    }

    return jsonString;
} /* InventoryUpdateReq_toJson */

void InventoryUpdateResp_free(InventoryUpdateResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);
        free(resp);
    }
} /* InventoryUpdateResp_free */

InventoryUpdateResp_t *InventoryUpdateResp_fromJson(char *jsonString)
{
    InventoryUpdateResp_t *resp = NULL;
    if (jsonString) {
        JsonNode *jsonRoot = json_decode(jsonString);
        if (jsonRoot) {
            resp = calloc(1, sizeof(InventoryUpdateResp_t));
            if (!resp) {
                log_error("%s::%s(%d) : Null pointer dereference - failed to allocate InventoryUpdateResp_t", LOG_INF);
                json_delete(jsonRoot);
                return NULL;
            }

            JsonNode *jsonResult = json_find_member(jsonRoot, "Result");
            if (jsonResult) {
                resp->Result = AgentApiResult_fromJsonNode(jsonResult);
            }

            json_delete(jsonRoot);
        }
    }

    return resp;
} /* InventoryUpdateResp_fromJson */

void EnrollmentConfigResp_free(EnrollmentConfigResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);

        if (resp->Entropy) {
            free(resp->Entropy);
            resp->Entropy = NULL;
        }
        if (resp->KeyType) {
            free(resp->KeyType);
            resp->KeyType = NULL;
        }
        if (resp->Subject) {
            free(resp->Subject);
            resp->Subject = NULL;
        }
        if (resp->ClientMachine) {
            free(resp->ClientMachine);
            resp->ClientMachine = NULL;
        }
        if (resp->StorePath) {
            free(resp->StorePath);
            resp->StorePath = NULL;
        }
        if (resp->StorePassword) {
            free(resp->StorePassword);
            resp->StorePassword = NULL;
        }
        if (resp->EnrollEndpoint) {
            free(resp->EnrollEndpoint);
            resp->EnrollEndpoint = NULL;
        }
        if (resp->PrivateKeyPath) {
            free(resp->PrivateKeyPath);
            resp->PrivateKeyPath = NULL;
        }
        if (resp->Properties) {
            free(resp->Properties);
            resp->Properties = NULL;
        }
        free(resp);
    }
} /* EnrollmentConfigResp_free */

EnrollmentConfigResp_t *EnrollmentConfigResp_fromJson(char *jsonString)
{
    EnrollmentConfigResp_t *resp = NULL;
    if (jsonString) {
        JsonNode *jsonRoot = json_decode(jsonString);
        if (jsonRoot) {
            resp = calloc(1, sizeof(EnrollmentConfigResp_t));
            if (!resp) {
                log_error("%s::%s(%d) : Null pointer dereference - failed to allocate EnrollmentConfigResp_t", LOG_INF);
                json_delete(jsonRoot);
                return NULL;
            }

            JsonNode *jsonResult = json_find_member(jsonRoot, "Result");
            if (jsonResult) {
                resp->Result = AgentApiResult_fromJsonNode(jsonResult);
            }

            resp->AuditId = json_get_member_number(jsonRoot, "AuditId", 0);
            resp->JobCancelled =
                json_get_member_bool(jsonRoot, "JobCancelled", false);

            resp->ClientMachine =
                json_get_member_string(jsonRoot, "ClientMachine");
            resp->Entropy = json_get_member_string(jsonRoot, "Entropy");
            resp->KeyType = json_get_member_string(jsonRoot, "KeyType");
            resp->Subject = json_get_member_string(jsonRoot, "Subject");
            resp->StorePath = json_get_member_string(jsonRoot, "StorePath");
            resp->StorePassword =
                json_get_member_string(jsonRoot, "StorePassword");
            resp->EnrollEndpoint =
                json_get_member_string(jsonRoot, "EnrollEndpoint");


            JsonNode *keySizeNode = json_find_member(jsonRoot, "KeySize");
            if (keySizeNode && keySizeNode->tag == JSON_NUMBER) {
                resp->KeySize = keySizeNode->number_;
            } else if (keySizeNode && keySizeNode->tag == JSON_STRING) {
                int tmp;
                if (sscanf(keySizeNode->string_, "%d", &tmp) == 1) {
                    resp->KeySize = tmp;
                }
            }

            JsonNode *jsonProps = NULL;
            resp->Properties = json_get_member_string(jsonRoot, "Properties");
            if (resp->Properties && (jsonProps = json_decode(resp->Properties))) {
                log_verbose("%s::%s(%d) : \"Properties\": %s",
                            LOG_INF, resp->Properties);

                /*
                 * NOTE: The platform is not sending the separatePrivateKey
                 * down as
                 */
                /*
                 * a boolean.  Instead it sends it down as a text value
                 */
                /*
                 * Therefore, this code will not work & must be modified to
                 * the
                 */
                /* Code below it */
#if defined(__SEPPRIVKEY_IS_BOOLEAN__)
                bool theBool =
                json_get_member_bool(jsonProps, "separatePrivateKey", \
                                     false);
#else
                bool theBool = false;
                char *theBoolString =
                json_get_member_string(jsonProps, "separatePrivateKey");
                if (theBoolString && 0 == strcasecmp("TRUE", theBoolString)) {
                    theBool = true;
                }
                if (theBoolString) {
                    free(theBoolString);
                }
#endif

                log_verbose("%s::%s(%d) : Separate Private Key = %s",
                            LOG_INF, theBool ? "true" : "false");
                if (theBool) {
                    resp->PrivateKeyPath =
                        json_get_member_string(jsonProps, "privateKeyPath");

                    log_verbose("%s::%s(%d) : privateKeyPath: %s",
                                LOG_INF, resp->PrivateKeyPath);
                } else
                    resp->PrivateKeyPath = NULL;
            }
            json_delete(jsonProps);
            json_delete(jsonRoot);
        }
    }

    return resp;
} /* EnrollmentConfigResp_fromJson */

void EnrollmentEnrollReq_free(EnrollmentEnrollReq_t * req)
{
    if (req) {
        if (req->JobId) {
            free(req->JobId);
            req->JobId = NULL;
        }
        if (req->SessionToken) {
            free(req->SessionToken);
            req->SessionToken = NULL;
        }

        if (req->CSRText) {
            free(req->CSRText);
            req->CSRText = NULL;
        }


        free(req);
    }
} /* EnrollmentEnrollReq_free */

char           *EnrollmentEnrollReq_toJson(EnrollmentEnrollReq_t * req)
{
    char *jsonString = NULL;

    if (req) {
        JsonNode *jsonRoot = json_mkobject();
        if (req->SessionToken) {
            json_append_member(jsonRoot, "SessionToken",
                               json_mkstring(req->SessionToken));
        } else {
            json_append_member(jsonRoot, "SessionToken", json_mknull());
        }
        if (req->JobId) {
            json_append_member(jsonRoot, "JobId", json_mkstring(req->JobId));
        } else {
            json_append_member(jsonRoot, "JobId", json_mknull());
        }

        if (req->CSRText) {
            json_append_member(jsonRoot, "CSRText",
                               json_mkstring(req->CSRText));
        } else {
            json_append_member(jsonRoot, "CSRText", json_mknull());
        }

        jsonString = json_encode(jsonRoot);
        json_delete(jsonRoot);
    }

    return jsonString;
} /* EnrollmentEnrollReq_toJson */

void EnrollmentEnrollResp_free(EnrollmentEnrollResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);

        if (resp->Certificate) {
            free(resp->Certificate);
            resp->Certificate = NULL;
        }

        free(resp);
    }
} /* EnrollmentEnrollResp_free */

EnrollmentEnrollResp_t *EnrollmentEnrollResp_fromJson(char *jsonString)
{
    EnrollmentEnrollResp_t *resp = NULL;
    if (jsonString) {
        JsonNode *jsonRoot = json_decode(jsonString);
        if (jsonRoot) {
            resp = calloc(1, sizeof(EnrollmentEnrollResp_t));
            if (!resp) {
                log_error("%s::%s(%d) : Null pointer dereference - failed to allocate EnrollmentEnrollResp_t", LOG_INF);
                json_delete(jsonRoot);
                return NULL;
            }

            JsonNode *jsonResult = json_find_member(jsonRoot, "Result");
            if (jsonResult) {
                resp->Result = AgentApiResult_fromJsonNode(jsonResult);
            }

            resp->Certificate = json_get_member_string(jsonRoot, "Certificate");

            json_delete(jsonRoot);
        }
    }

    return resp;
} /* EnrollmentEnrollResp_fromJson */

void EnrollmentCompleteResp_free(EnrollmentCompleteResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);

        if (resp->InventoryJob) {
            free(resp->InventoryJob);
            resp->InventoryJob = NULL;
        }

        free(resp);
    }
} /* EnrollmentCompleteResp_free */

EnrollmentCompleteResp_t *EnrollmentCompleteResp_fromJson(char *jsonString)
{
    EnrollmentCompleteResp_t *resp = NULL;
    if (jsonString) {
        JsonNode *jsonRoot = json_decode(jsonString);
        if (jsonRoot) {
            resp = calloc(1, sizeof(EnrollmentCompleteResp_t));
            if (!resp) {
                log_error("%s::%s(%d) : Null pointer dereference - failed to allocate EnrollmentCompleteResp_t", LOG_INF);
                json_delete(jsonRoot);
                return NULL;
            }

            JsonNode *jsonResult = json_find_member(jsonRoot, "Result");
            if (jsonResult) {
                resp->Result = AgentApiResult_fromJsonNode(jsonResult);
            }

            resp->InventoryJob =
                json_get_member_string(jsonRoot, "InventoryJob");

            json_delete(jsonRoot);
        }
    }

    return resp;
} /* EnrollmentCompleteResp_fromJson */

void FetchLogsConfigResp_free(FetchLogsConfigResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);

        free(resp);
    }
} /* FetchLogsConfigResp_free */

FetchLogsConfigResp_t *FetchLogsConfigResp_fromJson(char *jsonString)
{
    log_verbose("%s::%s(%d) : jsonString: %s",
                LOG_INF, jsonString);
    FetchLogsConfigResp_t *resp = NULL;

    if (jsonString) {
        JsonNode *jsonRoot = json_decode(jsonString);
        if (jsonRoot) {
            resp = calloc(1, sizeof(FetchLogsConfigResp_t));
            if (!resp) {
                log_error("%s::%s(%d) : Null pointer dereference - failed to allocate FetchLogsConfigResp_t", LOG_INF);
                json_delete(jsonRoot);
                return NULL;
            }

            JsonNode *jsonResult = json_find_member(jsonRoot, "Result");
            if (jsonResult) {
                resp->Result = AgentApiResult_fromJsonNode(jsonResult);
            }
            resp->AuditId = json_get_member_number(jsonRoot, "AuditId", 0);
            resp->MaxCharactersToReturn =
                json_get_member_number(jsonRoot, "MaxCharactersToReturn", 0);

            json_delete(jsonRoot);
        }
    }

    return resp;
} /* FetchLogsConfigResp_fromJson */

void FetchLogsCompleteReq_free(FetchLogsCompleteReq_t * req)
{
    if (req) {
        if (req->JobId) {
            free(req->JobId);
            req->JobId = NULL;
        }
        if (req->SessionToken) {
            free(req->SessionToken);
            req->SessionToken = NULL;
        }
        if (req->Message) {
            free(req->Message);
            req->Message = NULL;
        }
        if (req->Log) {
            free(req->Log);
            req->Log = NULL;
        }
        free(req);
    }
} /* FetchLogsCompleteReq_free */

char           *FetchLogsCompleteReq_toJson(FetchLogsCompleteReq_t * req)
{
    char *jsonString = NULL;

    if (req) {
        JsonNode *jsonRoot = json_mkobject();
        json_append_member(jsonRoot, "Status",
                           json_mknumber((double)req->Status));
        json_append_member(jsonRoot, "AuditId",
                           json_mknumber((double)req->AuditId));
        if (req->JobId) {
            json_append_member(jsonRoot, "JobId", json_mkstring(req->JobId));
        } else {
            json_append_member(jsonRoot, "JobId", json_mknull());
        }
        if (req->Message) {
            json_append_member(jsonRoot, "Message",
                               json_mkstring(req->Message));
        } else {
            json_append_member(jsonRoot, "Message", json_mknull());
        }

        if (req->SessionToken) {
            json_append_member(jsonRoot, "SessionToken",
                               json_mkstring(req->SessionToken));
        } else {
            json_append_member(jsonRoot, "SessionToken", json_mknull());
        }

        if (req->Log) {
            json_append_member(jsonRoot, "Log", json_mkstring(req->Log));
        } else {
            json_append_member(jsonRoot, "Log", json_mknull());
        }

        jsonString = json_encode(jsonRoot);
        json_delete(jsonRoot);
    }

    return jsonString;
} /* FetchLogsCompleteReq_toJson */

FetchLogsCompleteReq_t *FetchLogsCompleteReq_new()
{
    return calloc(1, sizeof(FetchLogsCompleteReq_t));
} /* FetchLogsCompleteReq_new */
/******************************************************************************/
/******************************* END OF FILE **********************************/
