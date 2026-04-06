/******************************************************************************/
/* Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT  */
/* LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent   */
/* Reference Implementation uses the OpenSSL encryption libraries, which are  */
/* not included as a part of this distribution.                               */
/* For hardware key storage or TPM support, libraries such as WolfSSL may     */
/* also be used in place of OpenSSL.                                          */
/******************************************************************************/
/* @file session.c                                                            */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include "csr.h"
#include "constants.h"
#include "config.h"
#include "dto.h"
#include "httpclient.h"
#include "logging.h"
#include "schedule.h"
#include "session.h"
#include "utils.h"
#include "agent.h"
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

#include <curl/curl.h>
#include "global.h"

#define MANAGEMENT_ADD_PRIORITY 3
#define PLATORM_ENROLL_STORES "registration-enroll-stores"

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/*                                                                            */
/* Add any customer specific client parameters to the session request         */
/*                                                                            */
/* @param  [Output] : sessionReq = The request structure to add data into     */
/* @return : void                                                             */
/*                                                                            */
static void add_custom_client_parameters(SessionRegisterReq_t * sessionReq) {
    /*
     * To send custom ClientParameters to the platform, do something like
     * this: SessionRegisterReq_addNewClientParameter(sessionReq,
     * "devicetype", "linux");
     */
#ifdef __QATESTING__
    SessionRegisterReq_addNewClientParameter(sessionReq, "qatesting", "true");
#endif
    return;
} /* add_custom_client_parameters */

/*                                                                            */
/* Modify the config.json file with the AgentId if EnrollOnStartup is true.   */
/* The AgentId is assigned by the platform during the inital call-in.         */
/* This should get set only once.                                             */
/*                                                                            */
/* Modify the config.json file when the session returns.                      */
/* The config.json file holds both configuration parameters and persistent    */
/* variables.  That is variables that must exist beyond the Agent's instance. */
/*                                                                            */
/* Examples of persistent variables are EnrollOnStartup and AgentId.          */
/*                                                                            */
/* @param  [Input] : sessionResp = the Platform's response                    */
/* @returns true if no error, false otherwise                                 */
/*                                                                            */
static bool update_agentid_from_session(SessionRegisterResp_t * sessionResp) {
    if (!ConfigData || !sessionResp) {
        log_error("%s::%s(%d) : Missing ConfigData or sessionResponse, exiting", LOG_INF);
        return false;
    }

    if (ConfigData->EnrollOnStartup) {
        if (
            ConfigData->AgentId &&
            sessionResp->Session.AgentId &&
            (strlen(sessionResp->Session.AgentId) > 0)
            ) {
            if (strcmp(sessionResp->Session.AgentId, ConfigData->AgentId) != 0) {
                log_info("%s::%s(%d) : Received new AgentId. Updating AgentId in configuration", LOG_INF);
                free(ConfigData->AgentId);
                ConfigData->AgentId = strdup(sessionResp->Session.AgentId);
                if (!ConfigData->AgentId) {
                    log_error("%s::%s(%d) : Null pointer dereference - failed to allocate AgentId", LOG_INF);
                    return false;
                }
                log_verbose("%s::%s(%d) : Saving configuration to file system", LOG_INF);
                config_save();
                return true;
            }
        } else {
            log_error("%s::%s(%d) : No AgentId assigned in config or not recieved from platform.", LOG_INF);
            return false;
        }
    } else {
        /* Not in enroll on startup */
        log_debug("%s::%s(%d) : Not in EnrollOnStartup", LOG_INF);
        return true;
    }
    log_warn("%s::%s(%d) : The agent ID is already set", LOG_INF);
    return true;
} /* update_agentid_from_session */

/*                                                                            */
/* Modify the config.json file when the session returns.                      */
/* The config.json file holds both configuration parameters and persistent    */
/* variables.  That is variables that must exist beyond the Agent's instance. */
/*                                                                            */
/* Examples of persistent variables are EnrollOnStartup and AgentId.          */
/*                                                                            */
/* @param  [Input] : sessionResp = the Platform's response                    */
/* @returns none                                                              */
/*                                                                            */
static void update_config_from_session(SessionRegisterResp_t * sessionResp) {
    bool isChanged = false;

    if (!ConfigData || !sessionResp) return;
    if (!ConfigData->EnrollOnStartup) return;

    if (sessionResp->Session.Certificate && sessionResp->Session.Certificate[0] != '\0') {
        log_info("%s::%s(%d) : Received Agent Certificate. Turning off EnrollOnStartup.", LOG_INF);
        isChanged = true;
        ConfigData->EnrollOnStartup = false;
    } else if (false == ConfigData->UseAgentCert) {
      log_info("%s::%s(%d) : Not using an Agent Certificate. Turning off EnrollOnStartup.", LOG_INF);
      isChanged = true;
      ConfigData->EnrollOnStartup = false;
    } else {
      log_info("%s::%s(%d) : Received no Agent Certificate. BUT, we should have received one.", LOG_INF);
    }

    if (isChanged) {
        log_trace("%s::%s(%d) : Saving configuration to file system", LOG_INF);
        config_save();
    }
} /* update_config_from_session */

/*                                                                            */
/* Configure the registration request to ask for Agent Registration           */
/*                                                                            */
/* @param  - [Output] : sessionReq = the session where we need to add the     */
/* registration information                                                   */
/* @return - success : true                                                   */
/* - failure : false                                                          */
/*                                                                            */
static bool register_agent(SessionRegisterReq_t * sessionReq) {
    bool bResult = false;
    size_t csrLen = 0;
    char *message = strdup("");
    enum AgentApiResultStatus status = STAT_SUCCESS;

    if (!sessionReq) {
        log_error("%s::%s(%d) : Null pointer dereference - sessionReq is NULL", LOG_INF);
        if (message) free(message);
        return false;
    }
    if (!message) {
        log_error("%s::%s(%d) : Null pointer dereference - failed to allocate message", LOG_INF);
        return false;
    }

    log_info("%s::%s(%d) : Registering agent with the platform for the first time", LOG_INF);

    /* Generate the temporary keypair & store it in the ssl wrapper layer */
#if defined(__TPM__)
    if (!generate_keypair(ConfigData->CSRKeyType, ConfigData->CSRKeySize,
                          ConfigData->AgentKey))
#else
    if (!generate_keypair(ConfigData->CSRKeyType, ConfigData->CSRKeySize))
#endif
    {
        log_error("%s::%s(%d) : Error generating keypair", LOG_INF);
        goto exit;
    }

    /* Get the CSR as a non-crypto specific string, the ssl wrapper does
     * this: */
    /* 1. Create a CSR request specific to the SSL implementation */
    /* 2. Add the subjects to the subject portion of the request */
    /* 3. Sign the request using the temporary private key in the ssl wrapper */
    /* 4. Convert the signed request into an ASCII string & return it */
    sessionReq->CSR = generate_csr(ConfigData->CSRSubject, &csrLen, &message, &status);
    if (message) {
        free(message);          /* right now, we don't do anything with this
                                 * structure */
    }

    log_verbose("%s::%s(%d) : Keypair & CSR generated for the Agent", LOG_INF);
    bResult = true;

exit:
    return bResult;
} /* register_agent */

/*                                                                            */
/* Take a session register response & parse the list of jobs.                 */
/* Schedule those jobs based on the following priorities:                     */
/* 1.) Store management ADD jobs (highest priority)                           */
/* 2.) Reenrollment jobs                                                      */
/* 3.) Store management non-ADD jobs                                          */
/* 4.) Inventory jobs                                                         */
/* 5.) Log file retrieval jobs (lowest priority)                              */
/*                                                                            */
/* @param  [Output] : pJobList = a pointer to the job list to populate.       */
/* allocated before calling this function                                     */
/* @param  [Input] : a session response                                       */
/* @return none                                                               */
/*                                                                            */
static void prioritize_jobs(ScheduledJob_t **pJobList,
                            SessionRegisterResp_t *response) {
  int i;
  SessionJob_t *job_to_schedule = NULL;

  if (!pJobList || !response) {
    log_error(
        "%s::%s(%d) : Null pointer dereference - pJobList or response is NULL",
        LOG_INF);
    return;
  }

  log_verbose("%s::%s(%d) : Prioritizing jobs", LOG_INF);

  /* Store management ADD jobs */
  for (i = 0; response->Session.Jobs_count > i; i++) {
    job_to_schedule = response->Session.Jobs[i];
    if (!job_to_schedule || !job_to_schedule->JobTypeId) {
      log_warn("%s::%s(%d) : Null job or JobTypeId at index %d", LOG_INF, i);
      continue;
    }
    if (0 == strcasecmp(CAP_PEM_MANAGEMENT, job_to_schedule->JobTypeId)) {
      if (MANAGEMENT_ADD_PRIORITY == job_to_schedule->Priority) {
        log_trace("%s::%s(%d) : Adding management ADD job %s", LOG_INF,
                  job_to_schedule->JobId);
        schedule_job(pJobList, job_to_schedule);
      }
    }
  }
  /* Reenrollment jobs */
  for (i = 0; response->Session.Jobs_count > i; i++) {
    job_to_schedule = response->Session.Jobs[i];
    if (!job_to_schedule || !job_to_schedule->JobTypeId) {
      log_warn("%s::%s(%d) : Null job or JobTypeId at index %d", LOG_INF, i);
      continue;
    }
    if (0 == strcasecmp(CAP_PEM_REENROLLMENT, job_to_schedule->JobTypeId)) {
      log_trace("%s::%s(%d) : Adding reenrollment job %s", LOG_INF,
                job_to_schedule->JobId);
      schedule_job(pJobList, job_to_schedule);
    }
  }
  /* Store management non-ADD jobs */
  for (i = 0; response->Session.Jobs_count > i; i++) {
    job_to_schedule = response->Session.Jobs[i];
    if (!job_to_schedule || !job_to_schedule->JobTypeId) {
      log_warn("%s::%s(%d) : Null job or JobTypeId at index %d", LOG_INF, i);
      continue;
    }
    if (0 == strcasecmp(CAP_PEM_MANAGEMENT, job_to_schedule->JobTypeId)) {
      if (MANAGEMENT_ADD_PRIORITY != job_to_schedule->Priority) {
        log_trace("%s::%s(%d) : Adding management non-ADD job %s", LOG_INF,
                  job_to_schedule->JobId);
        schedule_job(pJobList, job_to_schedule);
      }
    }
  }
  /* Inventory jobs */
  for (i = 0; response->Session.Jobs_count > i; i++) {
    job_to_schedule = response->Session.Jobs[i];
    if (!job_to_schedule || !job_to_schedule->JobTypeId) {
      log_warn("%s::%s(%d) : Null job or JobTypeId at index %d", LOG_INF, i);
      continue;
    }
    if (0 == strcasecmp(CAP_PEM_INVENTORY, job_to_schedule->JobTypeId)) {
      log_trace("%s::%s(%d) : Adding inventory job %s", LOG_INF,
                job_to_schedule->JobId);
      schedule_job(pJobList, job_to_schedule);
    }
  }
} /* prioritize_jobs */

/*                                                                            */
/* Add the capabilities allowed in this version of the agent by               */
/* capability GUID defined in Keyfactor                                       */
/*                                                                            */
/* @param  - [Output] : sessionReq The session to modify                      */
/* @return - success : true                                                   */
/* failure : false                                                            */
/*                                                                            */
static bool register_add_capabilities(SessionRegisterReq_t * sessionReq) {
    bool bResult = false;

    if (!sessionReq) {
        log_error("%s::%s(%d) : Null pointer dereference - sessionReq is NULL", LOG_INF);
        return false;
    }

    sessionReq->Capabilities_count = 3;
    sessionReq->Capabilities = calloc(sessionReq->Capabilities_count, sizeof(char *));
    if (sessionReq->Capabilities) {
        sessionReq->Capabilities[0] = strdup(cap_pem_inventory);
        sessionReq->Capabilities[1] = strdup(cap_pem_management);
        sessionReq->Capabilities[2] = strdup(cap_pem_reenrollment);
        if (!sessionReq->Capabilities[0] || !sessionReq->Capabilities[1] ||
            !sessionReq->Capabilities[2]) {
            log_error("%s::%s(%d) : Null pointer dereference - failed to allocate capabilities", LOG_INF);
            return false;
        }
        bResult = true;
    } else {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
    }
    return bResult;
} /* register_add_capabilities */

/*                                                                            */
/* Set up the registration parameters associated with a /Session/Request POST */
/*                                                                            */
/* @param  [Input] : sessionReq = a session request structure to fill         */
/* @return : void                                                             */
/*                                                                            */
static void set_registration_parameters(SessionRegisterReq_t * sessionReq) {
    if (!sessionReq) {
        log_error("%s::%s(%d) : Null pointer dereference - sessionReq is NULL", LOG_INF);
        return;
    }

    if (ConfigData->AgentName) {
        sessionReq->ClientMachine = strdup(ConfigData->AgentName);
        if (!sessionReq->ClientMachine) {
            log_error("%s::%s(%d) : Null pointer dereference - failed to allocate ClientMachine", LOG_INF);
            return;
        }
    } else {
        sessionReq->ClientMachine = strdup("");
        if (!sessionReq->ClientMachine) {
            log_error("%s::%s(%d) : Null pointer dereference - failed to allocate ClientMachine", LOG_INF);
            return;
        }
    }

    if ((ConfigData->EnrollOnStartup) || !(ConfigData->AgentId)) {
        /* Never send an Agent GUID to the platform when registering the */
        /* Agent or if the Id was not defined in the config */
        sessionReq->AgentId = strdup("");
        if (!sessionReq->AgentId) {
            log_error("%s::%s(%d) : Null pointer dereference - failed to allocate AgentId", LOG_INF);
            return;
        }
    } else {
        sessionReq->AgentId = strdup(ConfigData->AgentId);
        if (!sessionReq->AgentId) {
            log_error("%s::%s(%d) : Null pointer dereference - failed to allocate AgentId", LOG_INF);
            return;
        }
    }

    sessionReq->AgentPlatform = PLAT_NATIVE;
    sessionReq->AgentVersion = (uint64_t) AGENT_VERSION;

    /* Add the agent's capabilities, so the Platform knows what to expect */
    register_add_capabilities(sessionReq);
    /* Add any custom parameters for this customer */
    add_custom_client_parameters(sessionReq);

} /* set_registration_parameters */

/*                                                                            */
/* Check a certificate's expiry date                                          */
/*                                                                            */
/* @param  - [Input] certFile = path & filename of certificate to inspect     */
/* @return - certificate has not expired = true                               */
/* otherwise = false                                                          */
/*                                                                            */
static bool is_cert_active(char *certFile) {
    bool bResult = false;

    if (!certFile) {
        log_error("%s::%s(%d) : Null pointer dereference - certFile is NULL", LOG_INF);
        return false;
    }

    log_trace("%s::%s(%d) : Does cert file exist at %s?", LOG_INF, certFile);
    if (0 == file_exists(certFile)) {
        log_error("%s::%s(%d) : File %s does not exist", LOG_INF, certFile);
        goto exit;
    } else {
        log_trace("%s::%s(%d) : Yes cert file exists -- continuing to date check", LOG_INF);
    }

    bResult = ssl_is_cert_active(certFile);

exit:
    return bResult;
} /* is_cert_active */

/*                                                                            */
/* Reset the agent as a new one.  The next run of the agent will then         */
/* go through the re-provisioning process.                                    */
/*                                                                            */
/* @param  - none                                                             */
/* @return - none                                                             */
/*                                                                            */
static void reset_agent(void) {
    char *savedName = NULL;
    char *savedId = NULL;
    savedName = strdup(ConfigData->AgentName);
    savedId = strdup(ConfigData->AgentId);
    if (!savedName || !savedId) {
        log_error("%s::%s(%d) : Null pointer dereference - failed to allocate saved names", LOG_INF);
        if (savedName) free(savedName);
        if (savedId) free(savedId);
        return;
    }
    /* save current name */
    /* Reset the agent id */
    if (0 < strlen(ConfigData->AgentId)) {
        free(ConfigData->AgentId);
        ConfigData->AgentId = NULL;
    }
    ConfigData->AgentId = strdup("");

    /* Adjust the agent name by appending a datetime */
    /* NOTE: if a datetime is already added, be sure to remove it. */
    char *tempName = get_prefix_substring(ConfigData->AgentName, '_');
    if (NULL == tempName) {
        log_debug("%s::%s(%d) : Appending datetime to %s", LOG_INF, ConfigData->AgentName);
        tempName = strdup(ConfigData->AgentName);
    } else {
        log_debug("%s::%s(%d) : Appending datetime to %s", LOG_INF, tempName);
    }
    /* get the datetime */
    struct tm      *tm = NULL;
    time_t t;
    char tBuf[DATE_TIME_LEN + 1];
    log_verbose("%s::%s(%d) : Retrieving time from OS", LOG_INF);
    if (!time(&t)) {
        log_error("%s::%s(%d) : Error getting time from OS", LOG_INF);
        goto cleanup;
    }
    tm = gmtime(&t);
    if (!tm) {
        log_error("%s::%s(%d) : Null pointer dereference - gmtime failed", LOG_INF);
        goto cleanup;
    }
    (void)strftime(tBuf, DATE_TIME_LEN + 1, "%Y%m%d%H%M%S", tm);
    log_verbose("%s::%s(%d) : Date time is %s", LOG_INF, tBuf);
    /* Now we can adjust the Agent's Name */
    if ((ConfigData->AgentName) && (0 < strlen(ConfigData->AgentName))) {
        free(ConfigData->AgentName);
        ConfigData->AgentName = NULL;
    }
    int correctBytes = (strlen(tempName) + DATE_TIME_LEN + 2);
    ConfigData->AgentName = calloc(correctBytes, sizeof(char));
    if (!ConfigData->AgentName) {
        log_error("%s::%s(%d) : Null pointer dereference - failed to allocate AgentName", LOG_INF);
        goto cleanup;
    }
    if (0 >= snprintf(ConfigData->AgentName, correctBytes, "%s_%s", tempName, tBuf)) {
        log_error("%s::%s(%d) : Fatal error rewriting agent name, not changing name or ID", LOG_INF);
        ConfigData->AgentName = strdup(savedName);
        ConfigData->AgentId = strdup(savedId);
    } else {
        /*
         * as long as we get here we successfully wrote the new agent name,
         * so re-enroll
         */
        ConfigData->EnrollOnStartup = true;
    }

cleanup:
    if (tempName) {
        free(tempName);
        tempName = NULL;
    }
    if (savedName) {
        free(savedName);
        savedName = NULL;
    }
    if (savedId) {
        free(savedId);
        savedId = NULL;
    }

    config_save();

    return;
} /* reset_agent */

/*                                                                            */
/* Process the first registration response, which should include the Agent's  */
/* signed certificate (from the CA).                                          */
/* OR if we are not using agent certs, then make sure we got an Agent Id      */
/*                                                                            */
/* @param  [Input] : resp = the session response to parse                     */
/* @param  [Output] : status = any status message we need to pass to          */
/* Keyfactor                                                                  */
/* @param  [Output] : statusCode = the status code to pass to Keyfactor       */
/* @return if an Agent Id was sent & we either got a certificate OR we are    */
/* not using a agent cert then return = true                                  */
/* otherwise = false                                                          */
static bool do_first_registration_response(SessionRegisterResp_t * resp, char **status,
                                      enum AgentApiResultStatus *statusCode)
{
  if (NULL == resp) {
      log_error("%s::%s(%d) : Error, response to parse is null", LOG_INF);
      return false;
  }
  bool bResult = false;
  bool bIdOk = false;
  log_trace("%s::%s(%d): Updating config from session", LOG_INF);
  bIdOk = update_agentid_from_session(resp);

  if (ConfigData->UseAgentCert && bIdOk) {
      if (resp->Session.Certificate) {
          bResult = true;
          log_info("%s::%s(%d): Agent certificate received from platform.  Saving Agent Specific Keypair and "
                   "Agent Specific Cert.", LOG_INF);
          save_cert_key(ConfigData->AgentCert,
                        ConfigData->AgentKey, ConfigData->AgentKeyPassword,
                        resp->Session.Certificate, status, statusCode);
          update_config_from_session(resp);
      } else {
          /* The platform should have provided a certificate */
          log_error("%s::%s(%d): Certificate not found", LOG_INF);
      }
  } else {
      /* We don't need a certificate, but we do need an AgentId */
      if (bIdOk)
          bResult = true;
  }

  log_info("%s::%s(%d): First registration completed with %s",
    LOG_INF, bResult ? "success" : "failure");

  return bResult;
} /* do_first_registration_response */

/*                                                                            */
/* Schedule the jobs associated with the /Session/Register response           */
/*                                                                            */
/* @param  [Input] : resp = the platform response to parse                    */
/* @param  [Output] : session = the session data to populate                  */
/* @param  [Output] : schedule = string to print into                         */
/* @param  [Output] : pJobList = the head pointer to a linked list of jobs    */
static void do_normal_registration_response(SessionRegisterResp_t * resp,
        SessionInfo_t * session, ScheduledJob_t * *pJobList, char *schedule)
{
    if (!resp || !session || !pJobList || !schedule) {
        log_error("%s::%s(%d) : Invalid function call there is a NULL pointer passed to this function", LOG_INF);
        return;
    }

    log_info("%s::%s(%d): New session %s contains %d jobs", LOG_INF, resp->Session.Token, resp->Session.Jobs_count);

    size_t l = resp->Session.AgentId ? strlen((resp->Session.AgentId)) : 0;
    if (l > 0) {
        strcpy(session->AgentId, resp->Session.AgentId);
    } else {
        log_warn("%s::%s(%d) : No agent id in session", LOG_INF);
        session->AgentId[0] = '\0';
    }

    l = resp->Session.Token ? strlen((resp->Session.Token)) : 0;
    if (l > 0) {
        strcpy(session->Token, resp->Session.Token);
    } else {
        log_warn("%s::%s(%d) : No Token sent in session response", LOG_INF);
        session->Token[0] = '\0';
    }

    session->UnreachableCount = 0;
    clear_job_schedules(pJobList);

    /* Schedule the jobs based on priority */
    prioritize_jobs(pJobList, resp);
} /* do_normal_registration_response */

/*                                                                            */
/* Serialize a session request and POST it to /Session/Register.              */
/* Deserializes the response on success.                                      */
/*                                                                            */
/* @param  [Input]  : req           = populated request structure             */
/* @param  [Output] : respString_out = raw response JSON (caller must free)   */
/* @param  [Output] : resp_out       = decoded response (caller must free)    */
/* @return : 0 on HTTP success, 997 on decode failure, 998 on setup failure   */
/*                                                                            */
static int send_session_request(SessionRegisterReq_t *req,
                                char **respString_out,
                                SessionRegisterResp_t **resp_out)
{
    char *url       = NULL;
    char *reqString = NULL;
    int   httpRes   = 998;

    if (!req || !respString_out || !resp_out) {
        log_error("%s::%s(%d) : Null pointer dereference - invalid arguments", LOG_INF);
        return 998;
    }

    *respString_out = NULL;
    *resp_out       = NULL;

    reqString = SessionRegisterReq_toJson(req);
    if (!reqString) {
        log_error("%s::%s(%d) : Null pointer dereference - failed to create JSON request", LOG_INF);
        goto exit;
    }

    log_verbose("%s::%s(%d): Session Request:", LOG_INF);
    log_verbose("%s", reqString);

    url = config_build_url("/Session/Register", true);
    if (!url) {
        log_error("%s::%s(%d) : Null pointer dereference - failed to build URL", LOG_INF);
        goto exit;
    }

    httpRes = http_post_json(url, ConfigData->Username, ConfigData->Password,
                             ConfigData->TrustStore, ConfigData->AgentCert,
                             ConfigData->AgentKey, ConfigData->AgentKeyPassword,
                             reqString, respString_out,
                             ConfigData->httpRetries, ConfigData->retryInterval);

    if (0 == httpRes) {
        if (!*respString_out) {
            log_error("%s::%s(%d) : Error, no session returned in response", LOG_INF);
            httpRes = 998;
            goto exit;
        }

        log_trace("%s::%s(%d): decoding json response", LOG_INF);
        *resp_out = SessionRegisterResp_fromJson(*respString_out);
        if (!*resp_out) {
            log_error("%s::%s(%d) : Could not decode response", LOG_INF);
            httpRes = 997;
            goto exit;
        }
    }

exit:
    if (reqString) free(reqString);
    if (url)       free(url);
    return httpRes;
} /* send_session_request */

/*                                                                            */
/* Handle the enrollment decision before the first POST.                      */
/* Branches on EnrollOnStartup and UseAgentCert:                              */
/*   - First-time enroll: generates keypair + CSR if using agent cert         */
/*   - Normal heartbeat:  validates the existing agent cert, resets if expired*/
/*                                                                            */
/* @param  [Input/Output] : sessionReq              = request to populate     */
/* @param  [Output]       : firstAgentRegistration  = set true on first enrol */
/* @return : 0 on success, 998 on error (caller should abort and return 998)  */
/*                                                                            */
static int prepare_enrollment(SessionRegisterReq_t *sessionReq,
                              bool *firstAgentRegistration_out)
{
    if (!sessionReq || !firstAgentRegistration_out) {
        log_error("%s::%s(%d) : Null pointer dereference - invalid arguments", LOG_INF);
        return 998;
    }

    *firstAgentRegistration_out = false;

    if (ConfigData->EnrollOnStartup) {
        *firstAgentRegistration_out = true;
        if (ConfigData->UseAgentCert) {
            if (!register_agent(sessionReq)) {
                log_error("%s::%s(%d) : Error setting up agent registration", LOG_INF);
                return 998;
            }
            log_trace("%s::%s(%d) : Successfully set up /Session/Register data.", LOG_INF);
        } else {
            log_trace("%s::%s(%d) : Configured to not use an Agent Certificate", LOG_INF);
        }
    } else {
        if (ConfigData->UseAgentCert) {
            if (is_cert_active(ConfigData->AgentCert)) {
                log_trace("%s::%s:(%d) : Agent cert checks OK", LOG_INF);
            } else {
                log_error("%s::%s(%d) : Agent cert has expired - resetting Agent as a new device", LOG_INF);
                reset_agent();
                return 998;
            }
        }
    }

    return 0;
} /* prepare_enrollment */

/*                                                                            */
/* Returns true if the response error code indicates a cert renewal is needed.*/
/*                                                                            */
static bool is_cert_renewal_error(SessionRegisterResp_t *resp)
{
    return resp &&
           (resp->Result.Status == STAT_ERR || resp->Result.Status == STAT_WARN) &&
           resp->Result.Error.CodeString &&
           ((0 == strcasecmp("A0100007", resp->Result.Error.CodeString)) ||
            (0 == strcasecmp("A0100008", resp->Result.Error.CodeString)));
} /* is_cert_renewal_error */

/*                                                                            */
/* Re-register the agent's cert with the platform.                            */
/*                                                                            */
/* @param  [Output] : session (allocated before calling) a session data       */
/* structure in which we populate the Token, AgentId,                         */
/* and other information associated with the session                          */
/* @param  [Output] : pJobList = a pointer to a job list structure (allocated */
/* before calling this function)                                              */
/* @param  [Input] : agentVersion = the version of the Agent                  */
/* @param  [Input] : needNewAgentName = true to regen new agent               */
/* @return failure : 998 or a failed http code                                */
/* success : 200                                                              */
/*                                                                            */
static int re_register_agent(SessionInfo_t * session,
                             ScheduledJob_t * *pJobList,
                             uint64_t agentVersion,
                             bool needNewAgentName)
{
    int httpRes = 998;
    SessionRegisterResp_t *resp = NULL;
    char *respString = NULL;
    char *status;
    enum AgentApiResultStatus statusCode;
    char schedule[10];

    SessionRegisterReq_t *sessionReq = SessionRegisterReq_new(ConfigData->ClientParameterPath);
    if (!sessionReq) {
        log_error("%s::%s(%d) : Error getting a new session request buffer", LOG_INF);
        goto exit;
    }

    log_info("%s::%s(%d): Re-registering the agent", LOG_INF);

    set_registration_parameters(sessionReq);

    if (!register_agent(sessionReq)) {
        log_error("%s::%s(%d) : Error re-registering agent", LOG_INF);
        SessionRegisterReq_free(sessionReq);
        sessionReq = NULL;
        goto exit;
    }

    httpRes = send_session_request(sessionReq, &respString, &resp);
    SessionRegisterReq_free(sessionReq);
    sessionReq = NULL;

    if (0 == httpRes) {
        if (resp->Session.Token) {
            if (resp->Session.Certificate) {
                log_trace("%s::%s(%d): Found certificate."
                 "  Saving Agent Specific Keypair and Agent Specific Cert.",
                          LOG_INF);
                save_cert_key(ConfigData->AgentCert, ConfigData->AgentKey,
                    ConfigData->AgentKeyPassword, resp->Session.Certificate,
                              &status, &statusCode);
                if (needNewAgentName) {
                    if (ConfigData->AgentId)
                        free(ConfigData->AgentId);
                    ConfigData->AgentId = strdup(resp->Session.AgentId);
                    if (!ConfigData->AgentId) {
                        log_error("%s::%s(%d) : Null pointer dereference - failed to allocate AgentId", LOG_INF);
                        goto exit;
                    }
                    update_config_from_session(resp);
                }
            } else {
                log_trace("%s::%s(%d): Certificate not found", LOG_INF);
            }

            log_info("%s::%s(%d): New session %s contains %d jobs", LOG_INF,
                     resp->Session.Token, resp->Session.Jobs_count);

            size_t l = resp->Session.AgentId ? strlen(resp->Session.AgentId) : 0;
            if (0 < l) {
                strcpy(session->AgentId, resp->Session.AgentId);
            } else {
                log_warn("%s::%s(%d) : No AgentId provided", LOG_INF);
                session->AgentId[0] = '\0';
            }

            l = resp->Session.Token ? strlen(resp->Session.Token) : 0;
            if (0 < l) {
                strcpy(session->Token, resp->Session.Token);
            } else {
                log_warn("%s::%s(%d) : No Token provided", LOG_INF);
                session->Token[0] = '\0';
            }

            session->UnreachableCount = 0;
            clear_job_schedules(pJobList);
            prioritize_jobs(pJobList, resp);
        } else {
            log_error("%s::%s(%d): Agent re-registration did not succeed with error %s", LOG_INF,
                      resp->Result.Error.Message ? resp->Result.Error.Message : "(null)");
        }
    } else {
        log_error("%s::%s(%d): Agent re-registration failed with error code %d", LOG_INF, httpRes);
    }

exit:
    if (resp)       SessionRegisterResp_free(resp);
    if (respString) free(respString);
    return httpRes;
} /* re_register_agent */

/*                                                                            */
/* Handle the platform response when a session token is present.              */
/* Dispatches to first-registration handling, normal handling, or             */
/* re-registration on cert-renewal error codes.                               */
/*                                                                            */
/* @param  [Input]  : resp                      = decoded platform response   */
/* @param  [Output] : session                   = session state to update     */
/* @param  [Output] : pJobList                  = job list to populate        */
/* @param  [Input]  : agentVersion                                            */
/* @param  [Input]  : firstAgentRegistration    = true on initial enroll      */
/* @param  [Output] : bFirstRegistrationSuccess = outcome of first enroll     */
/* @return : httpRes to propagate, or 0 if handled internally                 */
/*                                                                            */
static int handle_token_response(SessionRegisterResp_t *resp,
                                 SessionInfo_t *session,
                                 ScheduledJob_t **pJobList,
                                 uint64_t agentVersion,
                                 bool firstAgentRegistration,
                                 bool *bFirstRegistrationSuccess_out)
{
  char schedule[10];
  char *status = NULL;
  enum AgentApiResultStatus statusCode = STAT_UNK;
  int httpRes = 0;

  log_trace("%s::%s(%d) : Token found, parsing response.", LOG_INF);

  if (AgentApiResult_log(resp->Result, NULL, NULL)) {
    if (firstAgentRegistration) {
      *bFirstRegistrationSuccess_out =
          do_first_registration_response(resp, &status, &statusCode);
    } else {
      do_normal_registration_response(resp, session, pJobList, schedule);
    }
  } else if (is_cert_renewal_error(resp)) {
    log_info("%s::%s(%d): Re-enrolling Agent certificate, WITH session token", LOG_INF);
    httpRes = re_register_agent(session, pJobList, agentVersion, false);
  } else {
    log_verbose("%s::%s(%d): Nothing to do", LOG_INF);
  }

  return httpRes;
} /* handle_token_response */

/*                                                                            */
/* Handle the platform response when no session token is present.             */
/* Re-registers on cert-renewal error codes; logs and advances the schedule   */
/* on all other errors.                                                       */
/*                                                                            */
/* @param  [Input]  : resp         = decoded platform response                */
/* @param  [Output] : session      = session state to update                  */
/* @param  [Output] : pJobList     = job list to populate                     */
/* @param  [Input]  : agentVersion                                            */
/* @return : httpRes from re_register_agent, or 0 if no action taken          */
/*                                                                            */
static int handle_no_token_response(SessionRegisterResp_t *resp,
                                    SessionInfo_t *session,
                                    ScheduledJob_t **pJobList,
                                    uint64_t agentVersion)
{
    char schedule[10];
    int httpRes = 0;

    AgentApiResult_log(resp->Result, NULL, NULL);

    if (is_cert_renewal_error(resp)) {
      log_info("%s::%s(%d): Re-enrolling Agent certificate, no session token", LOG_INF);
      httpRes = re_register_agent(session, pJobList, agentVersion, false);
    } else {
      log_error("%s::%s(%d): Session registration did not succeed with error %s", LOG_INF,
                resp->Result.Error.Message ? resp->Result.Error.Message : "(null)");
      log_error("%s::%s(%d): Session registration provided CodeString of %s", LOG_INF,
                resp->Result.Error.CodeString ? resp->Result.Error.CodeString : "(null)");
    }

    return httpRes;
} /* handle_no_token_response */

/*                                                                            */
/* We need to hit the /Session/Register a second time to get the platform to  */
/* assign store re-enrollment jobs the first time the agent calls in.         */
/* This can't be done via a blueprint, but can be done via a call to          */
/* /Session/Register without a CSR.  The registration handler will see this & */
/* instead of creating a new PKI request, it will hit the re-enrollment API   */
/* as long as we add the RegistrationRequest to the client parameters         */
/*                                                                            */
/* @param  [Output] : session (allocated before calling) a session data       */
/* structure in which we populate the Token, AgentId,                         */
/* and other information associated with the session                          */
/* @param  [Output] : pJobList = a pointer to a job list structure (allocated */
/* before calling this function)                                              */
/* @param  [Input] : agentVersion = the version of the Agent                  */
/* @return failure : 998 or a failed http code                                */
/* success : 200                                                              */
/*                                                                            */
static int do_second_registration(SessionInfo_t * session,
                          ScheduledJob_t * *pJobList, uint64_t agentVersion)
{
  int httpRes = 998;
  SessionRegisterResp_t *resp = NULL;
  char *respString = NULL;
  char schedule[10];

  SessionRegisterReq_t *sessionReq = SessionRegisterReq_new(ConfigData->ClientParameterPath);
  if (!sessionReq) {
    log_error("%s::%s(%d) : Null pointer dereference - failed to allocate sessionReq", LOG_INF);
    return 998;
  }

  log_info("%s::%s(%d): Register 2nd Session, ask for enrollment jobs", LOG_INF);

  if (ConfigData->AgentName) {
    sessionReq->ClientMachine = strdup(ConfigData->AgentName);
    if (!sessionReq->ClientMachine) {
        log_error("%s::%s(%d) : Null pointer dereference - failed to allocate ClientMachine", LOG_INF);
        SessionRegisterReq_free(sessionReq);
        return 998;
    }
  }
  if (ConfigData->AgentId) {
    sessionReq->AgentId = strdup(ConfigData->AgentId);
    if (!sessionReq->AgentId) {
        log_error("%s::%s(%d) : Null pointer dereference - failed to allocate AgentId", LOG_INF);
        SessionRegisterReq_free(sessionReq);
        return 998;
    }
  }

  sessionReq->AgentPlatform = PLAT_NATIVE;
  sessionReq->AgentVersion = agentVersion;
  register_add_capabilities(sessionReq);
  add_custom_client_parameters(sessionReq);

  /* Signal the registration handler to generate re-enrollment jobs */
  SessionRegisterReq_addNewClientParameter(sessionReq,
      "RegistrationRequest", PLATORM_ENROLL_STORES);

  httpRes = send_session_request(sessionReq, &respString, &resp);
  SessionRegisterReq_free(sessionReq);

  if (0 == httpRes) {
    if (!AgentApiResult_log(resp->Result, NULL, NULL)) {
        if (resp->Result.Status == STAT_ERR) {
            log_error("%s::%s(%d): Command reported an error during the second registration call", LOG_INF);
            httpRes = 997;
            goto exit;
        }
    }

    if (resp->Session.Token) {
      log_info("%s::%s(%d): New session %s contains %d jobs", LOG_INF,
               resp->Session.Token, resp->Session.Jobs_count);

      size_t l = resp->Session.Token ? strlen(resp->Session.Token) : 0;
      if (0 < l) {
        strcpy(session->Token, resp->Session.Token);
      } else {
        log_warn("%s::%s(%d) : Session does not contain a token", LOG_INF);
        session->Token[0] = '\0';
      }

      l = resp->Session.AgentId ? strlen(resp->Session.AgentId) : 0;
      if (0 < l) {
        strcpy(session->AgentId, resp->Session.AgentId);
      } else {
        log_warn("%s::%s(%d) : Session does not contain an AgentId", LOG_INF);
        session->AgentId[0] = '\0';
      }

      session->UnreachableCount = 0;
      clear_job_schedules(pJobList);
      prioritize_jobs(pJobList, resp);
    }
  }

exit:
  if (resp)       SessionRegisterResp_free(resp);
  if (respString) free(respString);
  return httpRes;
} /* do_second_registration */

/*                                                                            */
/* Complete first-registration by issuing the second /Session/Register call   */
/* that triggers re-enrollment job generation on the platform.                */
/* Updates and saves EnrollOnStartup based on outcome.                        */
/*                                                                            */
/* @param  [Output] : session      = session state to populate                */
/* @param  [Output] : pJobList     = job list to populate                     */
/* @param  [Input]  : agentVersion                                            */
/* @return : result of do_second_registration()                               */
/*                                                                            */
static int finalize_first_registration(SessionInfo_t *session,
                                       ScheduledJob_t **pJobList,
                                       uint64_t agentVersion)
{
    int httpRes;

    log_trace("%s::%s(%d) Performing second registration.", LOG_INF);
    httpRes = do_second_registration(session, pJobList, agentVersion);

    if (0 == httpRes) {
      log_info("%s::%s(%d): Re-enrollment jobs set up successfully", LOG_INF);
      ConfigData->EnrollOnStartup = false;
    } else {
      log_warn("%s::%s(%d) : Re-registering agent as second registration failed", LOG_INF);
      ConfigData->EnrollOnStartup = true;
    }
    config_save();

    return httpRes;
} /* finalize_first_registration */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS***************************/
/******************************************************************************/

/*                                                                            */
/* Register a session with the Keyfactor Platform.  If this is the first time */
/* the agent connects to the platform, then generate a keyPair and CSR to     */
/* send up to the platform.                                                   */
/*                                                                            */
/* @param  [Output] : session (allocated before calling) a session data       */
/* structure in which we populate the Token, AgentId,                         */
/* and other information associated with the session                          */
/* @param  [Output] : pJobList = a pointer to a job list structure (allocated */
/* before calling this function)                                              */
/* @param  [Input] : agentVersion = the version of the Agent                  */
/* @return failure : 998 or a failed http code                                */
/* success : 200                                                              */
/*                                                                            */
int register_session(SessionInfo_t * session, ScheduledJob_t * *pJobList, uint64_t agentVersion)
{
    int httpRes = 998;
    bool firstAgentRegistration   = false;
    bool bFirstRegistrationSuccess = false;
    SessionRegisterResp_t *resp   = NULL;
    char *respString              = NULL;

    SessionRegisterReq_t *sessionReq = SessionRegisterReq_new(ConfigData->ClientParameterPath);
    if (!sessionReq) {
      log_error("%s::%s(%d) : Error setting registration parameters", LOG_INF);
      return 998;
    }

    log_info("%s::%s(%d): Registering new session", LOG_INF);

    set_registration_parameters(sessionReq);

    if (0 != prepare_enrollment(sessionReq, &firstAgentRegistration)) {
      SessionRegisterReq_free(sessionReq);
      return 998;
    }

#ifdef __DEBUG__
    log_info("%s::%s(%d): Skipping http POST command", LOG_INF);
    SessionRegisterReq_free(sessionReq);
    return 0;
#else
    httpRes = send_session_request(sessionReq, &respString, &resp);
    SessionRegisterReq_free(sessionReq);

    if (0 == httpRes) {
      log_trace("%s::%s(%d): Checking for token in response.", LOG_INF);
      if (resp->Session.Token) {
        httpRes = handle_token_response(resp, session, pJobList, agentVersion,
                                        firstAgentRegistration,
                                        &bFirstRegistrationSuccess);
      } else {
        httpRes = handle_no_token_response(resp, session, pJobList, agentVersion);
      }

      if (firstAgentRegistration) {
        log_trace("%s::%s(%d) : Freeing session jobs", LOG_INF);
        SessionRegisterResp_freeJobs(resp);
      }
      log_trace("%s::%s(%d): Freeing session response", LOG_INF); /* Does NOT free jobs */
      SessionRegisterResp_free(resp);
      resp = NULL;
    } else {
      log_error("%s::%s(%d): Session registration failed with error code %d", LOG_INF, httpRes);
    }

    if (respString) free(respString);

    if (firstAgentRegistration && bFirstRegistrationSuccess)
      httpRes = finalize_first_registration(session, pJobList, agentVersion);

    return httpRes;
#endif /* __DEBUG__ not defined */
} /* register_session */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
