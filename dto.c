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
#include <limits.h>
#include <stdio.h>
#include "lib/json.h"
#include "logging.h"
#include <string.h>
#include <strings.h>
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

/**
 * @brief Free memory allocated for an AgentApiResult structure
 *
 * @param[in] result The AgentApiResult structure to free
 * @return None
 */
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

/**
 * @brief Parse an AgentApiResult from a JSON node
 *
 * @param[in] jsonResult JSON node containing the result data
 * @return AgentApiResult_t structure populated from JSON
 */
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

/**
 * @brief Log an AgentApiResult and update status/message
 *
 * @param[in] result The AgentApiResult to log
 * @param[in,out] pMessage Pointer to message string to append error details
 * @param[in,out] pStatus Pointer to status to update if result status is worse
 * @return true if result status is success, false if error or warning
 */
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

/**
 * @brief Allocate and initialize a new ClientParameter structure
 *
 * @param[in] key The parameter key string (will be duplicated)
 * @param[in] value The parameter value string (will be duplicated)
 * @return Pointer to newly allocated ClientParameter_t, or NULL on failure
 */
static ClientParameter_t * ClientParameter_new(const char *key,
                                               const char *value){

  // ReSharper disable once CppDFAMemoryLeak
  // Ownership of cp is transferred to the caller, which stores it in either
  // SessionRegisterReq_t->ClientParameters[] or
  // SessionRegisterResp_t->Session.ClientParameters[]. In both cases it is
  // freed via ClientParameter_free() called from SessionRegisterReq_free()
  // or SessionRegisterResp_free() respectively.
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

  // ReSharper disable once CppDFAMemoryLeak
  // Ownership of cp is transferred to the caller, which stores it in either
  // SessionRegisterReq_t->ClientParameters[] or
  // SessionRegisterResp_t->Session.ClientParameters[]. In both cases it is
  // freed via ClientParameter_free() called from SessionRegisterReq_free()
  // or SessionRegisterResp_free() respectively.
  return cp;
} /* ClientParameter_new */

/**
 * @brief Free memory allocated for a ClientParameter structure
 *
 * @param[in] cliParam Pointer to ClientParameter to free
 * @return None
 */
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

/**
 * @brief Add an additional ClientParameter to the session request
 *
 * Add a new key-value pair to the ClientParameters array after the
 * ClientParameterPath has been processed.
 *
 * @param[in,out] req Pointer to the SessionRegisterRequest to modify
 * @param[in] key The parameter key string
 * @param[in] value The parameter value string
 * @return true on success, false on failure
 */
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

  // ReSharper disable once CppDFAMemoryLeak
  // False positive: ClientParameter_t allocated here is stored in
  // req->ClientParameters[] which is owned by the SessionRegisterReq_t struct.
  // It is freed via the ClientParameter_free() loop inside
  // SessionRegisterReq_free(), which is called by all callers once they are
  // done with the request.
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

/**
 * @brief Allocate and initialize a new SessionRegisterRequest structure
 *
 * Creates a new session registration request and optionally loads client
 * parameters from a JSON file.
 *
 * @param[in] clientParamPath Path to JSON file containing client parameters (optional)
 * @return Pointer to newly allocated SessionRegisterReq_t, or NULL on failure
 */
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
              curNode->u.string_) {
            // ReSharper disable once CppDFAMemoryLeak
            // False positive: ClientParameter_t instances allocated here are stored in
            // req->ClientParameters[] which is owned by the SessionRegisterReq_t struct
            // returned to the caller. They are freed via the ClientParameter_free() loop
            // inside SessionRegisterReq_free(), which is called by all callers of
            // SessionRegisterReq_new() once they are done with the request.
            req->ClientParameters[nodeCount++] =
                ClientParameter_new(curNode->key, curNode->u.string_);
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

/**
 * @brief Free memory allocated for a SessionRegisterRequest structure
 *
 * @param[in] req Pointer to SessionRegisterReq_t to free
 * @return None
 */
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

/**
 * @brief Convert a SessionRegisterRequest to JSON string
 *
 * @param[in] req Pointer to SessionRegisterReq_t to serialize
 * @return Newly allocated JSON string, or NULL on failure. Caller must free.
 */
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

/**
 * @brief Free memory allocated for a SessionJob structure
 *
 * @param[in] job Pointer to SessionJob_t to free
 * @return None
 */
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

/**
 * @brief Free all jobs in a SessionRegisterResponse
 *
 * Frees the Jobs array and all individual SessionJob structures within
 * the response, but does not free the response itself.
 *
 * @param[in,out] resp Pointer to SessionRegisterResp_t containing jobs to free
 * @return None
 */
void SessionRegisterResp_freeJobs(SessionRegisterResp_t * resp)
{
    int lp = 0;

    if (!resp) {
        log_error("%s::%s(%d) : Null pointer dereference - resp is NULL", LOG_INF);
        return;
    }
    if (!resp->Session.Jobs) {
        log_error("%s::%s(%d) : Null pointer dereference - resp->Session.Jobs is NULL", LOG_INF);
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

/**
 * @brief Free memory allocated for a SessionRegisterResponse structure
 *
 * Note: This does NOT free the Jobs array. Call SessionRegisterResp_freeJobs()
 * first if jobs need to be freed.
 *
 * @param[in] resp Pointer to SessionRegisterResp_t to free
 * @return None
 */
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

/**
 * @brief Parse a SessionJob from a JSON node
 *
 * @param[in] jsonJob JSON node containing the job data
 * @return Pointer to newly allocated SessionJob_t, or NULL on failure
 */
static SessionJob_t* SessionJob_fromJsonNode(JsonNode * jsonJob) {
    SessionJob_t *job = NULL;
    if (jsonJob) {
      // ReSharper disable once CppDFAMemoryLeak
      // Rider flags this calloc as a potential leak, but ownership of the returned
      // SessionJob_t is intentionally transferred to the scheduler's ScheduledJob_t
      // linked list via prioritize_jobs()/schedule_job(). Jobs are released by
      // clear_job_schedules(). In the first-registration path where jobs are not
      // scheduled, the caller (SessionRegisterResp_fromJson) frees them explicitly
      // via SessionRegisterResp_freeJobs(). See the __NEVER_COMPILE_THIS__ block
      // in SessionRegisterResp_free() for the full ownership rationale.
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
      double priorityVal = json_get_member_number(jsonJob, "Priority", 5);
      if (priorityVal < INT_MIN || priorityVal > INT_MAX) {
        log_error("%s::%s(%d) : Priority value %.0f out of integer range, defaulting to 5",
                  LOG_INF, priorityVal);
        job->Priority = 5;
      } else {
        job->Priority = (int)priorityVal;
      }
    }

    return job;
} /* SessionJob_fromJsonNode */

/**
 * @brief Parse a SessionRegisterResponse from JSON string
 *
 * @param[in] jsonString JSON string to parse
 * @return Pointer to newly allocated SessionRegisterResp_t, or NULL on failure
 */
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
          // ReSharper disable once CppDFAMemoryLeak
          // False positive: SessionJob_t instances allocated here are stored in
          // resp->Session.Jobs[] and ownership is intentionally transferred to the
          // scheduler's ScheduledJob_t linked list via prioritize_jobs()/schedule_job().
          // They are freed by clear_job_schedules(). In the first-registration path
          // where jobs are not scheduled, the caller frees them explicitly via
          // SessionRegisterResp_freeJobs() before calling SessionRegisterResp_free().
          // See the __NEVER_COMPILE_THIS__ block in SessionRegisterResp_free() for
          // the full ownership rationale.
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
                jsonTmp->u.string_) {
              // ReSharper disable once CppDFAMemoryLeak
              // False positive: ClientParameter_t instances allocated here are stored in
              // resp->Session.ClientParameters[] and are owned by the response struct.
              // They are guaranteed to be freed by the ClientParameter_free() loop inside
              // SessionRegisterResp_free(), which is called by all callers of this function
              // once they are done with the response. There are no execution paths between
              // this point and the return of resp that can cause a leak.
              resp->Session.ClientParameters[current++] =
                  ClientParameter_new(jsonTmp->key, jsonTmp->u.string_);
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

/**
 * @brief Allocate and initialize a new CommonConfigRequest structure
 *
 * @return Pointer to newly allocated CommonConfigReq_t, or NULL on failure
 */
CommonConfigReq_t *CommonConfigReq_new(void)
{
    return calloc(1, sizeof(CommonConfigReq_t));
} /* CommonConfigReq_new */

/**
 * @brief Free memory allocated for a CommonConfigRequest structure
 *
 * @param[in] req Pointer to CommonConfigReq_t to free
 * @return None
 */
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

/**
 * @brief Convert a CommonConfigRequest to JSON string
 *
 * @param[in] req Pointer to CommonConfigReq_t to serialize
 * @return Newly allocated JSON string, or NULL on failure. Caller must free.
 */
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

/**
 * @brief Allocate and initialize a new CommonCompleteRequest structure
 *
 * @return Pointer to newly allocated CommonCompleteReq_t, or NULL on failure
 */
CommonCompleteReq_t *CommonCompleteReq_new(void)
{
    return calloc(1, sizeof(CommonCompleteReq_t));
} /* CommonCompleteReq_new */

/**
 * @brief Free memory allocated for a CommonCompleteRequest structure
 *
 * @param[in] req Pointer to CommonCompleteReq_t to free
 * @return None
 */
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

/**
 * @brief Convert a CommonCompleteRequest to JSON string
 *
 * @param[in] req Pointer to CommonCompleteReq_t to serialize
 * @return Newly allocated JSON string, or NULL on failure. Caller must free.
 */
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

/**
 * @brief Free memory allocated for a CommonCompleteResponse structure
 *
 * @param[in] resp Pointer to CommonCompleteResp_t to free
 * @return None
 */
void CommonCompleteResp_free(CommonCompleteResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);
        free(resp);
    }
} /* CommonCompleteResp_free */

/**
 * @brief Parse a CommonCompleteResponse from JSON string
 *
 * @param[in] jsonString JSON string to parse
 * @return Pointer to newly allocated CommonCompleteResp_t, or NULL on failure
 */
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

/**
 * @brief Free memory allocated for a ManagementConfigResponse structure
 *
 * @param[in] resp Pointer to ManagementConfigResp_t to free
 * @return None
 */
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

/**
 * @brief Parse a ManagementConfigResponse from JSON string
 *
 * @param[in] jsonString JSON string to parse
 * @return Pointer to newly allocated ManagementConfigResp_t, or NULL on failure
 */
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
                if (propString && ((jsonProps = json_decode(propString)) != NULL)) {
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

/**
 * @brief Free memory allocated for a ManagementCompleteResponse structure
 *
 * @param[in] resp Pointer to ManagementCompleteResp_t to free
 * @return None
 */
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

/**
 * @brief Parse a ManagementCompleteResponse from JSON string
 *
 * @param[in] jsonString JSON string to parse
 * @return Pointer to newly allocated ManagementCompleteResp_t, or NULL on failure
 */
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

/**
 * @brief Free memory allocated for an InventoryCurrentItem structure
 *
 * @param[in] item Pointer to InventoryCurrentItem_t to free
 * @return None
 */
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

/**
 * @brief Parse an InventoryCurrentItem from a JSON node
 *
 * @param[in] node JSON node containing the inventory item data
 * @return Pointer to newly allocated InventoryCurrentItem_t, or NULL on failure
 */
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

/**
 * @brief Free memory allocated for an InventoryConfigResponse structure
 *
 * @param[in] resp Pointer to InventoryConfigResp_t to free
 * @return None
 */
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

/**
 * @brief Parse an InventoryConfigResponse from JSON string
 *
 * @param[in] jsonString JSON string to parse
 * @return Pointer to newly allocated InventoryConfigResp_t, or NULL on failure
 */
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

/**
 * @brief Free memory allocated for an InventoryUpdateItem structure
 *
 * @param[in] item Pointer to InventoryUpdateItem_t to free
 * @return None
 */
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

/**
 * @brief Convert an InventoryUpdateItem to a JSON node
 *
 * @param[in] updateItem Pointer to InventoryUpdateItem_t to serialize
 * @return Newly allocated JSON node, or NULL on failure
 */
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

/**
 * @brief Free memory allocated for an InventoryUpdateRequest structure
 *
 * @param[in] req Pointer to InventoryUpdateReq_t to free
 * @return None
 */
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

/**
 * @brief Convert an InventoryUpdateRequest to JSON string
 *
 * @param[in] req Pointer to InventoryUpdateReq_t to serialize
 * @return Newly allocated JSON string, or NULL on failure. Caller must free.
 */
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

/**
 * @brief Free memory allocated for an InventoryUpdateResponse structure
 *
 * @param[in] resp Pointer to InventoryUpdateResp_t to free
 * @return None
 */
void InventoryUpdateResp_free(InventoryUpdateResp_t * resp)
{
    if (resp) {
        AgentApiResult_free(resp->Result);
        free(resp);
    }
} /* InventoryUpdateResp_free */

/**
 * @brief Parse an InventoryUpdateResponse from JSON string
 *
 * @param[in] jsonString JSON string to parse
 * @return Pointer to newly allocated InventoryUpdateResp_t, or NULL on failure
 */
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

/**
 * @brief Free memory allocated for an EnrollmentConfigResponse structure
 *
 * @param[in] resp Pointer to EnrollmentConfigResp_t to free
 * @return None
 */
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

/**
 * @brief Parse an EnrollmentConfigResponse from JSON string
 *
 * @param[in] jsonString JSON string to parse
 * @return Pointer to newly allocated EnrollmentConfigResp_t, or NULL on failure
 */
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
                resp->KeySize = keySizeNode->u.number_;
            } else if (keySizeNode && keySizeNode->tag == JSON_STRING) {
                int tmp;
                if (sscanf(keySizeNode->u.string_, "%d", &tmp) == 1) {
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

/**
 * @brief Free memory allocated for an EnrollmentEnrollRequest structure
 *
 * @param[in] req Pointer to EnrollmentEnrollReq_t to free
 * @return None
 */
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

/**
 * @brief Convert an EnrollmentEnrollRequest to JSON string
 *
 * @param[in] req Pointer to EnrollmentEnrollReq_t to serialize
 * @return Newly allocated JSON string, or NULL on failure. Caller must free.
 */
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

/**
 * @brief Free memory allocated for an EnrollmentEnrollResponse structure
 *
 * @param[in] resp Pointer to EnrollmentEnrollResp_t to free
 * @return None
 */
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

/**
 * @brief Parse an EnrollmentEnrollResponse from JSON string
 *
 * @param[in] jsonString JSON string to parse
 * @return Pointer to newly allocated EnrollmentEnrollResp_t, or NULL on failure
 */
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

/**
 * @brief Free memory allocated for an EnrollmentCompleteResponse structure
 *
 * @param[in] resp Pointer to EnrollmentCompleteResp_t to free
 * @return None
 */
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

/**
 * @brief Parse an EnrollmentCompleteResponse from JSON string
 *
 * @param[in] jsonString JSON string to parse
 * @return Pointer to newly allocated EnrollmentCompleteResp_t, or NULL on failure
 */
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
/******************************************************************************/
/******************************* END OF FILE **********************************/
