/******************************************************************************/
/* Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT  */
/* LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent   */
/* Reference Implementation uses the OpenSSL encryption libraries, which are  */
/* not included as a part of this distribution.                               */
/* For hardware key storage or TPM support, libraries such as WolfSSL may     */
/* also be used in place of OpenSSL.                                          */
/******************************************************************************/
/** @file session.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
/**                                                                           */
/* Add any customer specific client parameters to the session request         */
/*                                                                            */
/* @param  [Output] : sessionReq = The request structure to add data into     */
/* @return : void                                                             */
/*                                                                            */
static void add_custom_client_parameters(struct SessionRegisterReq* sessionReq) {
    /*
     * To send custom ClientParameters to the platform, do something like this:
    SessionRegisterReq_addNewClientParameter(sessionReq, "devicetype", "linux");
    */
    return;
} /* add_custom_client_parameters */

/**                                                                           */
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
static bool update_agentid_from_session(struct SessionRegisterResp* sessionResp)
{
	if ( !ConfigData || !sessionResp ) {
        log_error("%s::%s(%d) : Missing ConfigData or sessionResponse, exiting", LOG_INF);
		return false;
	}

	if( ConfigData->EnrollOnStartup ) {
		if(
            ConfigData->AgentId &&
			sessionResp->Session.AgentId &&
			(strlen(sessionResp->Session.AgentId) > 0)
          )
        {
			if(strcmp(sessionResp->Session.AgentId, ConfigData->AgentId) != 0) {
				log_info("%s::%s(%d) : Received new AgentId. Updating AgentId in configuration", LOG_INF);
				free(ConfigData->AgentId);
				ConfigData->AgentId = strdup(sessionResp->Session.AgentId);
				log_verbose("%s::%s(%d) : Saving configuration to file system",LOG_INF);
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
	log_error("%s::%s(%d) : We should never get here", LOG_INF);
	return false;
} /* update_agentid_from_session */

/**                                                                           */
/* Modify the config.json file when the session returns.                      */
/* The config.json file holds both configuration parameters and persistent    */
/* variables.  That is variables that must exist beyond the Agent's instance. */
/*                                                                            */
/* Examples of persistent variables are EnrollOnStartup and AgentId.          */
/*                                                                            */
/* @param  [Input] : sessionResp = the Platform's response                    */
/* @returns none                                                              */
/*                                                                            */
static void update_config_from_session(struct SessionRegisterResp* sessionResp)
{
	bool isChanged = false;

	if ( !ConfigData || !sessionResp ) return;
	if ( !ConfigData->EnrollOnStartup )	return;

	if(sessionResp->Session.Certificate)	{
		log_info("%s::%s(%d) : Received Agent Certificate. Turning off EnrollOnStartup.", LOG_INF);
		isChanged = true;
		ConfigData->EnrollOnStartup = false;
	}

	if(isChanged) {
		log_trace("%s::%s(%d) : Saving configuration to file system", LOG_INF);
		config_save();
	}
	return;
} /* update_config_from_session */

/**                                                                           */
/* Configure the registration request to ask for Agent Registration           */
/*                                                                            */
/* @param  - [Output] : sessionReq = the session where we need to add the     */
/*                                   registration information                 */
/* @return - success : 1                                                      */
/*         - failure : anything else but 1                                    */
/*                                                                            */
static bool register_agent(struct SessionRegisterReq* sessionReq)
{
	bool bResult = false;
	size_t csrLen = 0;
	char* message = strdup("");
	enum AgentApiResultStatus status = STAT_SUCCESS;

	log_info("%s::%s(%d) : Registering agent with the platform for the first time", LOG_INF);

	/* Generate the temporary keypair & store it in the ssl wrapper layer */
#if defined(__TPM__)
	if ( !generate_keypair(ConfigData->CSRKeyType, ConfigData->CSRKeySize,
		ConfigData->AgentKey) )
#else
	if ( !generate_keypair(ConfigData->CSRKeyType, ConfigData->CSRKeySize) )
#endif
	{
		log_error("%s::%s(%d) : Error generating keypair", LOG_INF);
		goto exit;
	}

	/* Get the CSR as a non-crypto specific string, the ssl wrapper does this:*/
	/*    1. Create a CSR request specific to the SSL implementation */
	/*    2. Add the subjects to the subject portion of the request */
	/*    3. Sign the request using the temporary private key in the 
				ssl wrapper*/
	/*    4. Convert the signed request into an ASCII string & return it */
	sessionReq->CSR = generate_csr(ConfigData->CSRSubject, &csrLen,	&message, &status);
	if ( message ) {
		free(message); /* right now, we don't do anything with this structure */
	}

	log_verbose("%s::%s(%d) : Keypair & CSR generated for the Agent", LOG_INF);
	bResult = true;

exit:
	return bResult;
} /* register_agent */

/**                                                                           */
/* Take a session register response & parse the list of jobs.                 */
/* Schedule those jobs based on the following priorities:                     */
/*     1.) Store management ADD jobs (highest priority)                       */
/*     2.) Reenrollment jobs                                                  */
/*     3.) Store management non-ADD jobs                                      */
/*     4.) Inventory jobs                                                     */
/*     5.) Log file retrieval jobs (lowest priority)                          */
/*                                                                            */
/* @param  [Output] : pJobList = a pointer to the job list to populate.       */
/*                   allocated before calling this function                   */
/* @param  [Input] : a session response                                       */
/* @return none                                                               */
/*                                                                            */
static void prioritize_jobs(struct ScheduledJob** pJobList, 
	struct SessionRegisterResp* response)
{
	int i;
	struct SessionJob* job_to_schedule = NULL;

	log_verbose("%s::%s(%d) : Prioritizing jobs", LOG_INF);

	/* Store management ADD jobs */
	for ( i = 0; response->Session.Jobs_count > i; i++ ) {
		job_to_schedule = response->Session.Jobs[i];
		if ( 0 == strcasecmp(CAP_PEM_MANAGEMENT, job_to_schedule->JobTypeId) ) {
			if (MANAGEMENT_ADD_PRIORITY == job_to_schedule->Priority) {
				log_trace("%s::%s(%d) : Adding management ADD job %s", LOG_INF, 
					job_to_schedule->JobId);
				schedule_job(pJobList, job_to_schedule, time(NULL));
			}
		}
	}
	/* Reenrollment jobs */
	for ( i = 0; response->Session.Jobs_count > i; i++ ) {
		job_to_schedule = response->Session.Jobs[i];
		if (0 == strcasecmp(CAP_PEM_REENROLLMENT, job_to_schedule->JobTypeId)) {
			log_trace("%s::%s(%d) : Adding reenrollment job %s", LOG_INF, job_to_schedule->JobId);
			schedule_job(pJobList, job_to_schedule, time(NULL));
		}
	}
	/* Store management non-ADD jobs */
	for ( i = 0; response->Session.Jobs_count > i; i++ ) {
		job_to_schedule = response->Session.Jobs[i];
		if ( 0 == strcasecmp(CAP_PEM_MANAGEMENT, job_to_schedule->JobTypeId) ) {
			if (MANAGEMENT_ADD_PRIORITY != job_to_schedule->Priority) {
				log_trace("%s::%s(%d) : Adding management non-ADD job %s",	LOG_INF, job_to_schedule->JobId);
				schedule_job(pJobList, job_to_schedule, time(NULL));
			}
		}
	}
	/* Inventory jobs */
	for ( i = 0; response->Session.Jobs_count > i; i++ ) {
		job_to_schedule = response->Session.Jobs[i];
		if ( 0 == strcasecmp(CAP_PEM_INVENTORY, job_to_schedule->JobTypeId) ) {
			log_trace("%s::%s(%d) : Adding inventory job %s", LOG_INF, job_to_schedule->JobId);
			schedule_job(pJobList, job_to_schedule, time(NULL));
		}
	}
	/* Log file retrieval jobs */
	for ( i = 0; response->Session.Jobs_count > i; i++ ) {
		job_to_schedule = response->Session.Jobs[i];
		if ( 0 == strcasecmp(CAP_FETCH_LOGS, job_to_schedule->JobTypeId) ) {
			log_trace("%s::%s(%d) : Adding log retrieval job %s", LOG_INF,	job_to_schedule->JobId);
			schedule_job(pJobList, job_to_schedule, time(NULL));
		}
	}
	return;
} /* prioritize_jobs */

/**                                                                           */
/* Add the capabilities allowed in this version of the agent by               */
/* capability GUID defined in Keyfactor                                       */
/*                                                                            */
/* @param  - [Output] : sessionReq The session to modify                      */
/* @return - success : true                                                   */
/*           failure : false                                                  */
/*                                                                            */
static bool register_add_capabilities(struct SessionRegisterReq* sessionReq)
{
	bool bResult = false;
	sessionReq->Capabilities_count = 4;
	sessionReq->Capabilities = calloc(sessionReq->Capabilities_count, sizeof(char*));
	if ( sessionReq->Capabilities )	{
		sessionReq->Capabilities[0] = strdup(cap_pem_inventory);
		sessionReq->Capabilities[1] = strdup(cap_pem_management);
		sessionReq->Capabilities[2] = strdup(cap_pem_reenrollment);
		sessionReq->Capabilities[3] = strdup(cap_fetch_logs);
		bResult = true;
	} else {
		log_error("%s::%s(%d) : Out of memory",	LOG_INF);
	}
	return bResult;
} /* register_add_capabilities */

/**                                                                           */
/* Set up the registration parameters associated with a /Session/Request POST */
/*                                                                            */
/* @param  [Input] : sessionReq = a session request structure to fill         */
/* @return : void                                                             */
/*                                                                            */
static void set_registration_parameters(struct SessionRegisterReq* sessionReq)
{
	if(ConfigData->AgentName) {
		sessionReq->ClientMachine = strdup(ConfigData->AgentName);
	} else {
		sessionReq->ClientMachine = strdup("");
	}

	if ( (ConfigData->EnrollOnStartup) || !(ConfigData->AgentId) ) {
		/* Never send an Agent GUID to the platform when registering the */
		/* Agent or if the Id was not defined in the config */
		sessionReq->AgentId = strdup("");
	} else {
		sessionReq->AgentId = strdup(ConfigData->AgentId);
	}

	sessionReq->AgentPlatform = PLAT_NATIVE;
	sessionReq->AgentVersion = (uint64_t)AGENT_VERSION;

	/* Add the agent's capabilities, so the Platform knows what to expect */
	register_add_capabilities(sessionReq);
    /* Add any custom parameters for this customer */
    add_custom_client_parameters(sessionReq);

	return;
} /* set_registration_parameters */

/**                                                                           */
/* Check a certificate's expiry date                                          */
/*                                                                            */
/* @param  - [Input] certFile = path & filename of certificate to inspect     */
/* @return - certificate has not expired = true                               */
/*           otherwise = false                                                */
/*                                                                            */
static bool is_cert_active(char* certFile) {
    bool bResult = false;

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

/**                                                                           */
/* Reset the agent as a new one.  The next run of the agent will then         */
/* go through the re-provisioning process.                                    */
/*                                                                            */
/* @param  - none                                                             */
/* @return - none                                                             */
/*                                                                            */
static void reset_agent(void) {
    char* savedName = NULL;
    char* savedId = NULL;
    savedName = strdup(ConfigData->AgentName);
    savedId = strdup(ConfigData->AgentId);
    /* save current name */
    /* Reset the agent id */
    if (0 < strlen(ConfigData->AgentId)) {
        free(ConfigData->AgentId);
        ConfigData->AgentId = NULL;
    }
    ConfigData->AgentId = strdup("");

    /* Adjust the agent name by appending a datetime */
    /* NOTE: if a datetime is already added, be sure to remove it. */
    char* tempName = get_prefix_substring(ConfigData->AgentName, '_');
    if (NULL == tempName) {
        log_debug("%s::%s(%d) : Appending datetime to %s", LOG_INF, ConfigData->AgentName);
        tempName = strdup(ConfigData->AgentName);
    }
    else {
        log_debug("%s::%s(%d) : Appending datetime to %s", LOG_INF, tempName);
    }
    /* get the datetime */
    struct tm* tm = NULL;
    time_t t;
    char tBuf[DATE_TIME_LEN+1];
    log_verbose("%s::%s(%d) : Retrieving time from OS", LOG_INF);
    if ( !time(&t) ) {
        log_error("%s::%s(%d) : Error getting time from OS", LOG_INF);
        goto cleanup;
    }
    tm = gmtime(&t);
    (void)strftime(tBuf, DATE_TIME_LEN+1, "%Y%m%d%H%M%S", tm);
    log_verbose("%s::%s(%d) : Date time is %s", LOG_INF, tBuf);
    /* Now we can adjust the Agent's Name */
    if ((ConfigData->AgentName) && (0 < strlen(ConfigData->AgentName))) {
        free(ConfigData->AgentName);
        ConfigData->AgentName = NULL;
    }
    int correctBytes = (strlen(tempName)+DATE_TIME_LEN+2);
    ConfigData->AgentName = calloc(correctBytes, sizeof(char));
    if (0 >= snprintf(ConfigData->AgentName,correctBytes,"%s_%s",tempName,tBuf)) {
        log_error("%s::%s(%d) : Fatal error rewriting agent name, not changing name or ID", LOG_INF);
        ConfigData->AgentName = strdup(savedName);
        ConfigData->AgentId = strdup(savedId);
    }
    else {
        /* as long as we get here we successfully wrote the new agent name, so re-enroll */
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

/**                                                                           */
/* We need to hit the /Session/Register a second time to get the platform to  */
/* assign store re-enrollment jobs the first time the agent calls in.         */
/* This can't be done via a blueprint, but can be done via a call to          */
/* /Session/Register without a CSR.  The registration handler will see this & */
/* instead of creating a new PKI request, it will hit the re-enrollment API   */
/* as long as we add the RegistrationRequest to the client parameters         */
/*                                                                            */
/* @param  [Input] : config = Config.json converted to a data structure       */
/* @param  [Output] : session (allocated before calling) a session data       */
/*                    structure in which we populate the Token, AgentId,      */
/*                    and other information associated with the session       */
/* @param  [Output] : pJobList = a pointer to a job list structure (allocated */
/*                    before calling this function)                           */
/* @param  [Input] : agentVersion = the version of the Agent                  */
/* @return failure : 998 or a failed http code                                */
/*         success : 200                                                      */
/*                                                                            */
static int do_second_registration(struct SessionInfo* session, 
	struct ScheduledJob** pJobList, uint64_t agentVersion)
{
	char* url = NULL;
	char* reqString = NULL;
	char* respString = NULL;
	int httpRes = 998;
	struct SessionRegisterResp* resp = NULL;
	char* status;
	char schedule[10];
	struct SessionRegisterReq* sessionReq;
	sessionReq = SessionRegisterReq_new(ConfigData->ClientParameterPath);

	log_info("%s::%s(%d): Register 2nd Session, ask for enrollment jobs", LOG_INF);

	if(ConfigData->AgentName) 
		sessionReq->ClientMachine = strdup(ConfigData->AgentName);
	if(ConfigData->AgentId)
		sessionReq->AgentId = strdup(ConfigData->AgentId);

	sessionReq->AgentPlatform = PLAT_NATIVE;
	sessionReq->AgentVersion = agentVersion;
	/* Add the agent's capabilities, so the Platform knows what to expect */
	register_add_capabilities(sessionReq);
    /* Add any custom parameters for this customer */
    add_custom_client_parameters(sessionReq);

	/* Now add a parameter to let the registration handler know it */
	/* Needs to create the re-enrollment job on the Cert Store(s) defined in the Registration Handler */
	SessionRegisterReq_addNewClientParameter(sessionReq, "RegistrationRequest", PLATORM_ENROLL_STORES);
	
	reqString = SessionRegisterReq_toJson(sessionReq);
	SessionRegisterReq_free(sessionReq);
	url = config_build_url("/Session/Register", true);
	httpRes = http_post_json(url, ConfigData->Username, ConfigData->Password, 
			ConfigData->TrustStore, ConfigData->AgentCert, ConfigData->AgentKey, 
			ConfigData->AgentKeyPassword, reqString, &respString, 
			ConfigData->httpRetries, ConfigData->retryInterval); 

	if (0 == httpRes) {
        if (!respString) {
            log_error("%s::%s(%d) : Error, no session returned in response", LOG_INF);
            goto exit;
        }

		resp = SessionRegisterResp_fromJson(respString);
        if ( NULL == resp ) {
            log_error("%s::%s(%d) : Could not decode response", LOG_INF);
            httpRes = 997;
            goto exit;
        }
        log_debug("%s::%s(%d): response decoded.  Now parsing response.", LOG_INF);
        if( !AgentApiResult_log(resp->Result, NULL, NULL) ) {
            if(resp->Result.Status == STAT_ERR) {
                log_error("%s::%s(%d): Command reported an error during the second registration call", LOG_INF);
                httpRes = 997;
            }
        }

		if(resp->Session.Token)	{
			log_info("%s::%s(%d): New session %s contains %d jobs", LOG_INF, resp->Session.Token, resp->Session.Jobs_count);

            size_t l = strlen(resp->Session.Token);
            if (0 < l) {
                strcpy(session->Token, resp->Session.Token);
            } else {
                log_warn("%s::%s(%d) : Session does not contain a token", LOG_INF);
                session->Token[0] = '\0';
            }

            l = strlen(resp->Session.AgentId);
            if (0 < l) {
                strcpy(session->AgentId, resp->Session.AgentId);
            } else {
                log_warn("%s::%s(%d) : Session does not contain an AgentId", LOG_INF);
                session->AgentId[0] = '\0';
            }

			session->UnreachableCount = 0;

			sprintf(schedule, "I_%d", resp->Session.HeartbeatInterval);
			session->NextExecution = next_execution(schedule, time(NULL));  
			clear_job_schedules(pJobList);

			/* Schedule the jobs based on priority */
			prioritize_jobs(pJobList, resp);
		}
	}

exit:
	if (resp) SessionRegisterResp_free(resp); /* Note: This doesn't free Jobs */
    if (reqString) free(reqString);
    if (respString) free(respString);
    if (url) free(url);

	return httpRes;
} /* do_second_registration */

/**                                                                           */
/* Re-register the agent's cert with the platform..                           */
/*                                                                            */
/* @param  [Output] : session (allocated before calling) a session data       */
/*                    structure in which we populate the Token, AgentId,      */
/*                    and other information associated with the session       */
/* @param  [Output] : pJobList = a pointer to a job list structure (allocated */
/*                    before calling this function)                           */
/* @param  [Input] : agentVersion = the version of the Agent                  */
/* @param  [Input] : needNewAgentName = true to regen new agent               */
/* @return failure : 998 or a failed http code                                */
/*         success : 200                                                      */
/*                                                                            */
static int re_register_agent(struct SessionInfo* session, struct ScheduledJob** pJobList, uint64_t agentVersion,
	bool needNewAgentName)
{
	char* url = NULL;
	char* reqString = NULL;
	char* respString = NULL;
	int httpRes = 998;
	struct SessionRegisterResp* resp = NULL;
	char* status;
	enum AgentApiResultStatus statusCode;
	char schedule[10];
	struct SessionRegisterReq* sessionReq = SessionRegisterReq_new(ConfigData->ClientParameterPath);
    if (!sessionReq) {
        log_error("%s::%s(%d) : Error getting a new session request buffer", LOG_INF);
        goto exit;
    }

	log_info("%s::%s(%d): Re-registering the agent", LOG_INF);

	set_registration_parameters(sessionReq);

	/* Set up the registration specific session information */
	if ( !register_agent(sessionReq) ) {
		log_error("%s::%s(%d) : Error re-registering agent", LOG_INF);
		goto exit;
	}

	/* Send the request up to the platform */
	reqString = SessionRegisterReq_toJson(sessionReq);
	SessionRegisterReq_free(sessionReq);
    sessionReq = NULL;

	log_verbose("%s::%s(%d): Session Request:", LOG_INF);
	log_verbose("%s",reqString);
	url = config_build_url("/Session/Register", true);
    if (!url) {
        log_error("%s::%s(%d) : Error building URL", LOG_INF);
        goto exit;
    }

	httpRes = http_post_json(url, ConfigData->Username, ConfigData->Password,
			ConfigData->TrustStore, ConfigData->AgentCert, ConfigData->AgentKey,
			ConfigData->AgentKeyPassword, reqString, &respString,
			ConfigData->httpRetries,ConfigData->retryInterval); 

	if ( 0 == httpRes ) {
        if (!respString) {
            log_error("%s::%s(%d) : Error, no session returned in response", LOG_INF);
            goto exit;
        }

		log_trace("%s::%s(%d): decoding json response", LOG_INF);
		resp = SessionRegisterResp_fromJson(respString);
        if (resp) {
            log_trace("%s::%s(%d): response decoded.  Now parsing response.", LOG_INF);
        } else {
            log_error("%s::%s(%d) : No Session was found in the response", LOG_INF);
            goto exit;
        }

		if(resp->Session.Token) {
			if(resp->Session.Certificate) {
				log_trace("%s::%s(%d): Found certificate."
					"  Saving Agent Specific Keypair and Agent Specific Cert.", 
					LOG_INF);
				save_cert_key(ConfigData->AgentCert, ConfigData->AgentKey, 
					ConfigData->AgentKeyPassword, resp->Session.Certificate, 
					&status, &statusCode);
				if (needNewAgentName) {
					if (ConfigData->AgentId) free(ConfigData->AgentId);
					ConfigData->AgentId = strdup(resp->Session.AgentId);
					update_config_from_session(resp);
				}
			} else {
				log_trace("%s::%s(%d): Certificate not found", LOG_INF);
			}
			/* download & shcedule jobs */
			log_info("%s::%s(%d): New session %s contains %d jobs", LOG_INF, resp->Session.Token, resp->Session.Jobs_count);

            size_t l = strlen(resp->Session.AgentId);
            if (0 < l) {
                strcpy(session->AgentId, resp->Session.AgentId);
            } else {
                log_warn("%s::%s(%d) : No AgentId provided", LOG_INF);
                session->AgentId[0] = '\0';
            }

            l = strlen(resp->Session.Token);
            if (0 < l) {
                strcpy(session->Token, resp->Session.Token);
            } else {
                log_warn("%s::%s(%d) : No Token provided", LOG_INF);
                session->Token[0] = '\0';
            }

			session->UnreachableCount = 0;
			clear_job_schedules(pJobList);

			/* Schedule the jobs based on priority */
			prioritize_jobs(pJobList, resp);
		} else {
			log_error("%s::%s(%d): Agent re-registration did not succeed with error %s", LOG_INF, resp->Result.Error.Message);
		}
	} else {
		log_error("%s::%s(%d): Agent re-registration failed with error code %d", LOG_INF, httpRes);
	}

exit:
	if (resp) SessionRegisterResp_free(resp); /* Note this doesn't free Jobs */
	if (reqString) free(reqString);
	if (respString) free(respString);
	if (url) free(url);

	return httpRes;
} /* re_register_agent */

/**                                                                           */
/* Process the first registration response, which should include the Agent's  */
/* signed certificate (from the CA).                                          */
/* OR if we are not using agent certs, then make sure we got an Agent Id      */
/*                                                                            */
/* @param  [Input] : resp = the session response to parse                     */
/* @param  [Output] : status = any status message we need to pass to Keyfactor*/
/* @param  [Output] : statusCode = the status code to pass to Keyfactor       */
/* @return if an Agent Id was sent & we either got a certificate OR we are    */
/*         not using a agent cert then return = true                          */
/*         otherwise = false                                                  */
static bool do_first_registration_response(struct SessionRegisterResp* resp, char** status,
	enum AgentApiResultStatus* statusCode)
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
		if(resp->Session.Certificate) {
			bResult = true;
			log_info("%s::%s(%d): Agent certificate recieved from platform.  Saving Agent Specific Keypair and "
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
		if (bIdOk) bResult = true;
	}
	return bResult;
} /* do_first_registration_response */

/**                                                                           */
/* Schedule the jobs associated with the /Session/Register response           */
/*                                                                            */
/* @param  [Input] : resp = the platform response to parse                    */
/* @param  [Output] : session = the session data to populate                  */
/* @param  [Output] : schedule = string to print into                         */
/* @param  [Output] : pJobList = the head pointer to a linked list of jobs    */
static void do_normal_registration_response(struct SessionRegisterResp* resp, 
	struct SessionInfo* session, struct ScheduledJob** pJobList, char* schedule)
{
    if (!resp || !session || !pJobList || !schedule) {
        log_error("%s::%s(%d) : Invalid function call there is a NULL pointer passed to this function", LOG_INF);
        return;
    }

	log_info("%s::%s(%d): New session %s contains %d jobs", LOG_INF, resp->Session.Token, resp->Session.Jobs_count);

    size_t l = strlen((resp->Session.AgentId));
    if (l > 0) {
        strcpy(session->AgentId, resp->Session.AgentId);
    } else {
        log_warn("%s::%s(%d) : No agent id in session", LOG_INF);
        session->AgentId[0] = '\0';
    }

    l = strlen((resp->Session.Token));
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

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS***************************/
/******************************************************************************/

/** 																		  */
/* Register a session with the Keyfactor Platform.  If this is the first time */
/* the agent connects to the platform, then generate a keyPair and CSR to     */
/* send up to the platform. 												  */
/*																			  */
/* @param  [Output] : session (allocated before calling) a session data       */
/*                    structure in which we populate the Token, AgentId,      */
/*                    and other information associated with the session       */
/* @param  [Output] : pJobList = a pointer to a job list structure (allocated */
/*                    before calling this function)                           */
/* @param  [Input] : agentVersion = the version of the Agent                  */
/* @return failure : 998 or a failed http code 								  */
/*         success : 200 													  */
/*                                                                            */
int register_session(struct SessionInfo* session, struct ScheduledJob** pJobList, uint64_t agentVersion)
{
	char* url = NULL;
	char* reqString = NULL;
	char* respString = NULL;
	int httpRes = 998;
	struct SessionRegisterResp* resp = NULL;
	char* status;
	enum AgentApiResultStatus statusCode;
	char schedule[10];
	struct SessionRegisterReq* sessionReq = SessionRegisterReq_new(ConfigData->ClientParameterPath);
    if (NULL == sessionReq) {
        log_error("%s::%s(%d) : Error setting registration parameters", LOG_INF);
        goto exit;
    }
	bool firstAgentRegistration = false;
	bool bFirstRegistrationSuccess = false;

	log_info("%s::%s(%d): Registering new session", LOG_INF);

	set_registration_parameters(sessionReq);
	
	if(ConfigData->EnrollOnStartup)	{
		firstAgentRegistration = true; /* flag this as the first registration */
		if (ConfigData->UseAgentCert) {
			if ( !register_agent( sessionReq ) ) {
				log_error("%s::%s(%d) : Error setting up agent registration", LOG_INF);
				SessionRegisterReq_free( sessionReq );
				return 998;
			} else {
				log_trace("%s::%s(%d) : Successfully set up /Session/Register data.", LOG_INF);
	        }
		} else {
			log_trace("%s::%s(%d) : Skipping agent cert from configurtion", LOG_INF);
		}
	} else {
		if (ConfigData->UseAgentCert) {
	        /* Check the validity of the Agent cert if we aren't in the enrollment phase */
	        if (is_cert_active(ConfigData->AgentCert)) {
	            log_trace("%s::%s:(%d) : Agent cert checks OK", LOG_INF);
	        } else {
	            log_error("%s::%s(%d) : Agent cert has expired - resetting Agent as a new device", LOG_INF);
	            reset_agent();
	            return 998;
	        }
		}
    }

	/* Send the request up to the platform */
	reqString = SessionRegisterReq_toJson(sessionReq);
	SessionRegisterReq_free(sessionReq); 

	log_verbose("%s::%s(%d): Session Request:", LOG_INF);
	log_verbose("%s",reqString);
	url = config_build_url("/Session/Register", true);

#ifdef __DEBUG__
	log_info("%s::%s(%d): Skipping http POST command", LOG_INF);
	free(url);
	free(reqString);
	return 0;
#else /* __DEBUG__ */
	/* Run HTTP POST if we aren't in __DEBUG__ */
	httpRes = http_post_json(url, ConfigData->Username, ConfigData->Password, 
		ConfigData->TrustStore, ConfigData->AgentCert, ConfigData->AgentKey, 
		ConfigData->AgentKeyPassword, reqString, &respString, 
		ConfigData->httpRetries,ConfigData->retryInterval); 

	if(0 == httpRes) {
		log_trace("%s::%s(%d): decoding json response", LOG_INF);
		resp = SessionRegisterResp_fromJson(respString);
		if ( NULL == resp )	{
			log_error("%s::%s(%d) : Could not decode response", LOG_INF);
			httpRes = 997;
			goto exit;
		}
		log_trace("%s::%s(%d): Checking for token in response.", LOG_INF);
		if(resp->Session.Token)	{
			log_trace("%s::%s(%d) : Token found, parsing response.", LOG_INF);
			if( AgentApiResult_log(resp->Result, NULL, NULL) ) {
				if (firstAgentRegistration)	{
					bFirstRegistrationSuccess = do_first_registration_response(resp, &status, &statusCode);
 				} else {
 					do_normal_registration_response(resp, session, pJobList, schedule);
 				}
			} else if((resp->Result.Status == STAT_ERR || resp->Result.Status == STAT_WARN) &&
					resp->Result.Error.CodeString &&
                    ((0 == strcasecmp("A0100007", resp->Result.Error.CodeString)) ||
                     (0 == strcasecmp("A0100008", resp->Result.Error.CodeString))) ) {
				log_info("%s::%s(%d): Re-enrolling Agent certificate, WITH session token", LOG_INF);
				httpRes = re_register_agent(session, pJobList, agentVersion, false);
			} else {
				sprintf(schedule, "I_%d", session->Interval);
				session->NextExecution = next_execution(schedule,session->NextExecution);
			}
		} else { /* We have a response, but no token */
			AgentApiResult_log(resp->Result, NULL, NULL);
			if ((resp->Result.Status == STAT_ERR || resp->Result.Status == STAT_WARN) &&
				resp->Result.Error.CodeString && 
				((0 == strcasecmp("A0100007", resp->Result.Error.CodeString)) ||
                 (0 == strcasecmp("A0100008", resp->Result.Error.CodeString))) ) {
				log_info("%s::%s(%d): Re-enrolling Agent certificate, no session token", LOG_INF);
				httpRes = re_register_agent(session, pJobList, agentVersion, false);
			} else {
				log_error("%s::%s(%d): Session registration did not succeed with error %s", LOG_INF,
                          resp->Result.Error.Message);
				log_error("%s::%s(%d): Session registration provided CodeString of %s", LOG_INF,
                          resp->Result.Error.CodeString);
				sprintf(schedule, "I_%d", session->Interval);
				session->NextExecution = next_execution(schedule, session->NextExecution);
			}
		}

		/* Cleanup the response */
		log_trace("%s::%s(%d): Freeing session response", LOG_INF);
		if (firstAgentRegistration) {
			/* During the first agent registration call, jobs are */
			/* not scheduled.  Freeing the Register Response does */
			/* not free the jobs - as they are normally associated */
			/* with the linked list of prioritized jobs.           */
			/* Therefore, free any unassigned jobs before freeing */
			/* the response from the platform. */
			log_trace("%s::%s(%d) : Freeing session jobs", LOG_INF);
			SessionRegisterResp_freeJobs(resp);
		}
		SessionRegisterResp_free(resp); /* Note: Does not free Jobs */
		resp = NULL;
	} else {
		log_error("%s::%s(%d): Session registration failed with error code %d", LOG_INF, httpRes);
		char schedule[10];
		sprintf(schedule, "I_%d", session->Interval);
		session->NextExecution = next_execution(schedule, session->NextExecution);
	}

exit:
	if (reqString) free(reqString);
	if (respString) free(respString);
	if (url) free(url);

	/* If this was the first agent registration & we got a certificate */
    /* OR we aren't using agent certs,                                 */
	/* Then poke the platform a second time to force the re-enrollment */
	/* jobs to be generated.                                           */
	if (
		firstAgentRegistration &&  /* This is the first registration */
		bFirstRegistrationSuccess  /* and it was successful */
       ) {
		log_trace("%s::%s(%d) Performing second registration.", LOG_INF);
		httpRes = do_second_registration(session, pJobList, agentVersion);
		if (0 == httpRes) {
			log_info("%s::%s(%d): Re-enrollment jobs set up successfully",	LOG_INF);
		} else {
			/* Session failed, so we need to re-register the agent */
			/* on the next trigger */
			ConfigData->EnrollOnStartup = true;
			log_warn("%s::%s(%d) : Re-registering agent as second registration failed", LOG_INF);
		}
	}

	return httpRes;
#endif /* __DEBUG__ not defined */
} /* register_session */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/