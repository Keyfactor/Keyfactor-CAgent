/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
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
 * Modify the config.json file with the AgentId if EnrollOnStartup is true.
 * The AgentId is assigned by the platform during the inital call-in.
 * This should get set only once.
 *
 * Modify the config.json file when the session returns.
 * The config.json file holds both configuration parameters and persistent
 * variables.  That is variables that must exist beyond the Agent's instance.
 *
 * Examples of persistent variables are EnrollOnStartup and AgentId.
 *
 * @param  [Input] : config = the (possibly) modified Config Data Structure
 * @param  [Input] : sessionResp = the Platform's response
 * @returns none
 */
static void update_agentid_from_session(struct ConfigData* config,
	struct SessionRegisterResp* sessionResp)
{
	bool isChanged = false;

	if ( !config || !sessionResp )
	{
		return;
	}

	if(	sessionResp->Session.AgentId && config->EnrollOnStartup )
	{
		if(config->AgentId)
		{
			if(strcmp(sessionResp->Session.AgentId, config->AgentId) != 0)
			{
				log_trace("%s::%s(%d) : Received new AgentId.  "
					      "Updating AgentId in configuration", 
					__FILE__, __FUNCTION__, __LINE__);
				free(config->AgentId);
				config->AgentId = strdup(sessionResp->Session.AgentId);
				isChanged = true;
			}
		}
		else
		{
			log_trace("%s::%s(%d) : No AgentId assinged in config.  "
				      "Not modifying AgentId", 
				__FILE__, __FUNCTION__, __LINE__);
		}
	}

	if(isChanged)
	{
		log_trace("%s::%s(%d) : Saving configuration to file system", 
			__FILE__, __FUNCTION__, __LINE__);
		config_save(config);
	}
	return;
} /* update_agentid_from_session */

/**
 * Modify the config.json file when the session returns.
 * The config.json file holds both configuration parameters and persistent
 * variables.  That is variables that must exist beyond the Agent's instance.
 *
 * Examples of persistent variables are EnrollOnStartup and AgentId.
 *
 * @param  [Input] : config = the (possibly) modified Config Data Structure
 * @param  [Input] : sessionResp = the Platform's response
 * @returns none
 */
static void update_config_from_session(struct ConfigData* config,
	struct SessionRegisterResp* sessionResp)
{
	bool isChanged = false;

	if ( !config || !sessionResp ) return;
	if ( !config->EnrollOnStartup )	return;

	if(sessionResp->Session.Certificate && config->EnrollOnStartup)
	{
		log_trace("%s::%s(%d) : Received Agent Certificate.  "
			      "Turning off EnrollOnStartup.", 
			__FILE__, __FUNCTION__, __LINE__);
		isChanged = true;
		config->EnrollOnStartup = false;
	}

	if(isChanged)
	{
		log_trace("%s::%s(%d) : Saving configuration to file system", 
			__FILE__, __FUNCTION__, __LINE__);
		config_save(config);
	}
	return;
} /* update_config_from_session */

/**
 * Configure the registration request to ask for Agent Registration
 *
 * @param  - [Input] : config = the configuration for the agent
 * @param  - [Output] : sessionReq = the session where we need to add the 
 *                                   registration information
 * @return - success : 1
 *         - failure : anything else but 1
 */
static int register_agent(const struct ConfigData* config, \
	struct SessionRegisterReq* sessionReq)
{
	size_t csrLen = 0;
	char* message = strdup("");
	enum AgentApiResultStatus status = STAT_SUCCESS;

	log_verbose("%s::%s(%d): EnrollOnStartup = %s", \
		__FILE__, __FUNCTION__, __LINE__, \
		config->EnrollOnStartup ? "true" : "false");
	
	/* Generate the temporary keypair & store it in the ssl wrapper layer */
#if defined(__TPM__)
	if ( !generate_keypair(config->CSRKeyType, config->CSRKeySize, config->AgentKey) )
#else
	if ( !generate_keypair(config->CSRKeyType, config->CSRKeySize) )
#endif
	{
		log_error("%s::%s(%d) : Error generating keypair", \
			__FILE__, __FUNCTION__, __LINE__);
		return 999;
	}

	/* Get the CSR as a non-crypto specific string, the ssl wrapper does this:*/
	/*    1. Create a CSR request specific to the SSL implementation */
	/*    2. Add the subjects to the subject portion of the request */
	/*    3. Sign the request using the temporary private key in the 
				ssl wrapper*/
	/*    4. Convert the signed request into an ASCII string & return it */
	sessionReq->CSR = generate_csr(config->CSRSubject, &csrLen,\
		&message, &status);
	if ( message )
	{
		free(message); // right now, we don't do anything with this structure
	}

	return 1;
} // register_agent

/**
 * Take a session register response & parse the list of jobs.
 * Schedule those jobs based on the following priorities:
 *     1.) Store management ADD jobs (highest priority)
 *     2.) Reenrollment jobs
 *     3.) Store management non-ADD jobs
 *     4.) Inventory jobs
 *     5.) Log file retrieval jobs (lowest priority)
 *
 * @param  [Output] : pJobList = a pointer to the job list to populate.
 *                   allocated before calling this function
 * @param  [Input] : a session response
 * @return none
 */
static void prioritize_jobs(struct ScheduledJob** pJobList, \
	struct SessionRegisterResp* response)
{
	int i;
	struct SessionJob* job_to_schedule = NULL;

	log_verbose("%s::%s(%d) : Prioritizing jobs", \
		__FILE__, __FUNCTION__, __LINE__);

	/* Store management ADD jobs */
	for ( i = 0; response->Session.Jobs_count > i; i++ )
	{
		job_to_schedule = response->Session.Jobs[i];
		if ( 0 == strcasecmp(CAP_PEM_MANAGEMENT, job_to_schedule->JobTypeId) ) {
			if (MANAGEMENT_ADD_PRIORITY == job_to_schedule->Priority) {
				log_trace("%s::%s(%d) : Adding management ADD job %s", \
					__FILE__, __FUNCTION__, __LINE__, job_to_schedule->JobId);
				schedule_job(pJobList, job_to_schedule, time(NULL));
			}
		}
	}
	/* Reenrollment jobs */
	for ( i = 0; response->Session.Jobs_count > i; i++ )
	{
		job_to_schedule = response->Session.Jobs[i];
		if (0 == strcasecmp(CAP_PEM_REENROLLMENT, job_to_schedule->JobTypeId)) {
			log_trace("%s::%s(%d) : Adding reenrollment job %s", \
				__FILE__, __FUNCTION__, __LINE__, job_to_schedule->JobId);
			schedule_job(pJobList, job_to_schedule, time(NULL));
		}
	}
	/* Store management non-ADD jobs */
	for ( i = 0; response->Session.Jobs_count > i; i++ )
	{
		job_to_schedule = response->Session.Jobs[i];
		if ( 0 == strcasecmp(CAP_PEM_MANAGEMENT, job_to_schedule->JobTypeId) ) {
			if (MANAGEMENT_ADD_PRIORITY != job_to_schedule->Priority) {
				log_trace("%s::%s(%d) : Adding management non-ADD job %s", \
					__FILE__, __FUNCTION__, __LINE__, job_to_schedule->JobId);
				schedule_job(pJobList, job_to_schedule, time(NULL));
			}
		}
	}
	/* Inventory jobs */
	for ( i = 0; response->Session.Jobs_count > i; i++ )
	{
		job_to_schedule = response->Session.Jobs[i];
		if ( 0 == strcasecmp(CAP_PEM_INVENTORY, job_to_schedule->JobTypeId) ) {
			log_trace("%s::%s(%d) : Adding inventory job %s", \
				__FILE__, __FUNCTION__, __LINE__, job_to_schedule->JobId);
			schedule_job(pJobList, job_to_schedule, time(NULL));
		}
	}
	/* Log file retrieval jobs */
	for ( i = 0; response->Session.Jobs_count > i; i++ )
	{
		job_to_schedule = response->Session.Jobs[i];
		if ( 0 == strcasecmp(CAP_FETCH_LOGS, job_to_schedule->JobTypeId) ) {
			log_trace("%s::%s(%d) : Adding log retrieval job %s", \
				__FILE__, __FUNCTION__, __LINE__, job_to_schedule->JobId);
			schedule_job(pJobList, job_to_schedule, time(NULL));
		}
	}
	return;
} /* prioritize_jobs */

/**
 * Add the capabilities allowed in this version of the agent
 *
 * @param  - [Output] : sessionReq The session to modify
 * @return - success : true
 *           failure : false
 */
static bool register_add_capabilities(struct SessionRegisterReq* sessionReq)
{
	bool bResult = false;
	sessionReq->Capabilities_count = 4;
	sessionReq->Capabilities = calloc(sessionReq->Capabilities_count, \
		sizeof(char*));
	if ( sessionReq->Capabilities )
	{
		sessionReq->Capabilities[0] = strdup(CAP_PEM_INVENTORY);
		sessionReq->Capabilities[1] = strdup(CAP_PEM_MANAGEMENT);
		sessionReq->Capabilities[2] = strdup(CAP_PEM_REENROLLMENT);
		sessionReq->Capabilities[3] = strdup(CAP_FETCH_LOGS);
		bResult = true;
	}
	else
	{
		log_error("%s::%s(%d) : Out of memory",
			__FILE__, __FUNCTION__, __LINE__);
	}
	return bResult;
}

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * Register a session with the Keyfactor Platform.  If this is the first time 
 * the agent connects to the platform, then generate a keyPair and CSR to 
 * send up to the platform.
 *
 * @param  [Input] : config = Config.json converted to a data structure
 * @param  [Output] : session (allocated before calling) a session data
 *                    structure in which we populate the Token, AgentId,
 *                    and other information associated with the session
 * @param  [Output] : pJobList = a pointer to a job list structure (allocated
 *                    before calling this function)
 * @param  [Input] : agentVersion = the version of the Agent
 * @return failure : 998 or a failed http code
 *         success : 200 
 */
int register_session(struct ConfigData* config, struct SessionInfo* session, \
	struct ScheduledJob** pJobList, uint64_t agentVersion)
{
	char* url = NULL;
	char* reqString = NULL;
	char* respString = NULL;
	int httpRes = 998;
	struct SessionRegisterResp* resp = NULL;
	char* status;
	enum AgentApiResultStatus statusCode;
	char schedule[10];
	struct SessionRegisterReq* sessionReq = \
					SessionRegisterReq_new(config->ClientParameterPath);

	log_info("%s::%s(%d): Registering new session", \
		__FILE__, __FUNCTION__, __LINE__);

	if(config->AgentName) {
		sessionReq->ClientMachine = strdup(config->AgentName);
	}
	if(config->AgentId) {
		sessionReq->AgentId = strdup(config->AgentId);
	}

	sessionReq->AgentPlatform = PLAT_NATIVE;
	sessionReq->AgentVersion = agentVersion;
	if(config->EnrollOnStartup)	{
		/* Generate a keypair and a CSR to send up with this request */
		httpRes = register_agent(config, sessionReq);
		if ( 1 != httpRes )	{
			log_error("%s::%s(%d) : Error setting up agent registration", 
				__FILE__, __FUNCTION__, __LINE__);
			if ( sessionReq ) SessionRegisterReq_free( sessionReq );
			return 998;
		}
	}

	/* Add the agent's capabilities, so the Platform knows what to expect */
	register_add_capabilities(sessionReq);

	/* Send the request up to the platform */
	reqString = SessionRegisterReq_toJson(sessionReq);
	SessionRegisterReq_free(sessionReq);

	log_verbose("%s::%s(%d): Session Request:", \
		__FILE__, __FUNCTION__, __LINE__);
	log_verbose("%s",reqString);
	url = config_build_url(config, "/Session/Register", true);

#ifdef __DEBUG__
	log_info("%s::%s(%d): Skipping http POST command", \
		__FILE__, __FUNCTION__, __LINE__);
	free(url);
	free(reqString);
	return 0;
#else // Run HTTP POST if we aren't in __DEBUG__
	httpRes = http_post_json(url, config->Username, config->Password, \
		config->TrustStore, config->AgentCert, config->AgentKey, \
		config->AgentKeyPassword, reqString, &respString, \
		config->httpRetries,config->retryInterval); // BL-20654

	if(0 == httpRes)
	{
		log_trace("%s::%s(%d): decoding json response", \
			__FILE__, __FUNCTION__, __LINE__);
		resp = SessionRegisterResp_fromJson(respString);
		log_trace("%s::%s(%d): response decoded.  Now parsing response.", \
			__FILE__, __FUNCTION__, __LINE__);
		if(resp->Session.Token)
		{
			
			if(resp && AgentApiResult_log(resp->Result, NULL, NULL))
			{
				if(config->EnrollOnStartup) {
					/* Check to see if we should update the AgentId */
					log_trace("%s::%s(%d): Updating config from session", \
						__FILE__, __FUNCTION__, __LINE__);
					update_agentid_from_session(config, resp);
				}

				if(resp->Session.Certificate) {
					log_trace("%s::%s(%d): Found certificate.  Saving Agent "
						      "Specific Keypair and Agent Specific Cert.", \
						      __FILE__, __FUNCTION__, __LINE__);
					save_cert_key(config->AgentCert, config->AgentKey, \
						config->AgentKeyPassword, resp->Session.Certificate, \
						&status, &statusCode);
					update_config_from_session(config, resp);
				}
				else
				{
					log_trace("%s::%s(%d): Certificate not found", \
						__FILE__, __FUNCTION__, __LINE__);
 				}

				log_info("%s::%s(%d): New session %s contains %d jobs", \
					__FILE__, __FUNCTION__, __LINE__, resp->Session.Token, \
					resp->Session.Jobs_count);

				strcpy(session->AgentId, resp->Session.AgentId);
				strcpy(session->Token, resp->Session.Token);
				session->UnreachableCount = 0;

				sprintf(schedule, "I_%d", resp->Session.HeartbeatInterval);
				// TODO - Use time that was passed down
				session->NextExecution = next_execution(schedule, time(NULL));  
				clear_job_schedules(pJobList);

				/* Schedule the jobs based on priority */
				prioritize_jobs(pJobList, resp);
			}

			else if(resp && 
				    resp->Result.Status == STAT_ERR	&& 
					resp->Result.Error.CodeString && 
					strcasecmp("A0100007", resp->Result.Error.CodeString))
			{
				log_info("%s::%s(%d): Re-enrolling for authentication "
					     "certificate", __FILE__, __FUNCTION__, __LINE__);
			}

			else
			{
				sprintf(schedule, "I_%d", session->Interval);
				session->NextExecution = next_execution(schedule, \
					session->NextExecution);
			}
		}
		else
		{
			log_error("%s::%s(%d): Session registration did not succeed "
				      "with error %s", __FILE__, __FUNCTION__, __LINE__, \
				      resp->Result.Error.Message);
			sprintf(schedule, "I_%d", session->Interval);
			session->NextExecution = next_execution(schedule, \
						session->NextExecution);
		}
		if (resp) {
			log_trace("%s::%s(%d): Freeing session response", \
				__FILE__, __FUNCTION__, __LINE__);
			SessionRegisterResp_free(resp);
			resp = NULL;
		}
	}
	else
	{
		log_error("%s::%s(%d): Session registration failed with error code %d",\
				 __FILE__, __FUNCTION__, __LINE__, httpRes);

		char schedule[10];
		sprintf(schedule, "I_%d", session->Interval);
		session->NextExecution = next_execution(schedule, \
			session->NextExecution);
	}

	free(reqString);
	free(respString);
	free(url);

	return httpRes;
#endif   // If debug was defined, don't run HTTP POST
} /* register_session */

/**
 * A heartbeat session periodically contacts the Platform to determine if
 * any jobs have been scheduled, or if the session has expired, been 
 * abandoned, etc.
 *
 * @param  [Input] : config = Config.json converted to a data structure
 * @param  [Output] : session (allocated before calling) a session data
 *                    structure in which we populate the Token, AgentId,
 *                    and other information associated with the session
 * @param  [Output] : pJobList = a pointer to a job list structure (allocated
 *                    before calling this function)
 * @param  [Input] : agentVersion = the version of the Agent
 * @return failure : a failed http code
 *         success : 200 http response
 */
int heartbeat_session(struct ConfigData* config, struct SessionInfo* session, \
	struct ScheduledJob** pJobList, uint64_t agentVersion)
{
	char* url = NULL;
	struct SessionHeartbeatReq* heartbeatReq = SessionHeartbeatReq_new();

	log_info("%s::%s(%d)- Heartbeating current session", \
		__FILE__, __FUNCTION__, __LINE__);

	heartbeatReq->AgentPlatform = PLAT_NATIVE;
	heartbeatReq->ClientMachine = strdup(config->AgentName);
	heartbeatReq->SessionToken = strdup(session->Token);

	char* reqString = SessionHeartbeatReq_toJson(heartbeatReq);
	SessionHeartbeatReq_free(heartbeatReq);

	url = config_build_url(config, "/Session/Heartbeat", true);

	char* respString = NULL;

	int httpRes = http_post_json(url, config->Username, config->Password, \
		config->TrustStore, config->AgentCert, config->AgentKey, \
		config->AgentKeyPassword, reqString, &respString, \
		config->httpRetries,config->retryInterval); // BL-20654

	if(httpRes == 0)
	{
		struct SessionHeartbeatResp* resp = \
				SessionHeartbeatResp_fromJson(respString);

		if(resp && AgentApiResult_log(resp->Result, NULL, NULL))
		{
			if(resp->SessionValid)
			{
				char schedule[10];
				sprintf(schedule, "I_%d", resp->HeartbeatInterval);
				session->NextExecution = next_execution(schedule, \
					session->NextExecution);
				session->UnreachableCount = 0;
			}
			else
			{
				log_info("%s::%s(%d): session is invalid. Re-registering\n",\
					 __FILE__, __FUNCTION__, __LINE__);
				strcpy(session->Token, "");
				register_session(config, session, pJobList, agentVersion);
			}
		}
		else
		{
			char schedule[10];
			sprintf(schedule, "I_%d", session->Interval);
			session->NextExecution = next_execution(schedule, \
				session->NextExecution);
		}

		SessionHeartbeatResp_free(resp);
	}
	else
	{
		log_error("%s::%s(%d):  heartbeat failed with error code %d", \
			__FILE__, __FUNCTION__, __LINE__, httpRes);
		session->UnreachableCount++; // TODO - Use UnreachableCount

		char schedule[10];
		sprintf(schedule, "I_%d", session->Interval);
		session->NextExecution = next_execution(schedule, \
			session->NextExecution);
	}

	free(reqString);
	free(respString);
	free(url);

	return httpRes;
} /* heartbeat_session */
