/*
* Copyright 2018, Certified Security Solutions
* All Rights Reserved.
* This is UNPUBLISHED PROPRIETARY SOURCE CODE of Certified Security Solutions;
* the contents of this file may not be disclosed to third parties, copied
* or duplicated in any form, in whole or in part, without the prior
* written permission of Certified Security Solutions.
*/

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

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/evp.h>
#else
#include <openssl/evp.h>
#endif

#include <curl/curl.h>
#include "global.h"

#ifdef __RPI__
#include "rpi_gpio.h"
#endif

static void update_config_from_session(struct ConfigData* config,
										struct SessionRegisterResp* sessionResp)
{
	bool isChanged = false;
	if(config && sessionResp)
	{
		if(sessionResp->Session.Certificate && config->EnrollOnStartup)
		{
			isChanged = true;
			config->EnrollOnStartup = false;
		}

		if(sessionResp->Session.AgentId)
		{
			if(config->AgentId)
			{
				if(strcmp(sessionResp->Session.AgentId, config->AgentId) != 0)
				{
					free(config->AgentId);
					config->AgentId = strdup(sessionResp->Session.AgentId);
					isChanged = true;
				}
			}
			else
			{
				config->AgentId = strdup(sessionResp->Session.AgentId);
				isChanged = true;
			}
		}
		else
		{
			if(config->AgentId)
			{
				free(config->AgentId);
				config->AgentId = NULL;
				isChanged = true;
			}
		}
	}

	if(isChanged)
	{
		config_save(config);
	}
}

int register_session(struct ConfigData* config, struct SessionInfo* session, struct ScheduledJob** pJobList, uint64_t agentVersion)
{
	char* url = NULL;
	struct SessionRegisterReq* sessionReq = SessionRegisterReq_new(config->ClientParameterPath);

	log_info("session-register_session-Registering new session");

	sessionReq->AgentPlatform = PLAT_NATIVE;
	if(config->AgentName) {sessionReq->ClientMachine = strdup(config->AgentName);}
	if(config->AgentId) {sessionReq->AgentId = strdup(config->AgentId);}
	sessionReq->AgentVersion = agentVersion;

	EVP_PKEY* keypair = NULL;
	if(config->EnrollOnStartup){
		log_verbose("session-register_session-EnrollOnStartup = true, generating keypair");

		keypair = generate_keypair(config->CSRKeyType, config->CSRKeySize);
		X509_NAME* subject = parse_subject(config->CSRSubject);
		char* CSR = generate_csr(keypair, subject);
		X509_NAME_free(subject);
		sessionReq->CSR = CSR;
	}

	sessionReq->Capabilities_count = 3;
	sessionReq->Capabilities = calloc(3, sizeof(char*));
	sessionReq->Capabilities[0] = strdup(CAP_PEM_INVENTORY);
	sessionReq->Capabilities[1] = strdup(CAP_PEM_MANAGEMENT);
	sessionReq->Capabilities[2] = strdup(CAP_PEM_ENROLL);

	char* reqString = SessionRegisterReq_toJson(sessionReq);
	SessionRegisterReq_free(sessionReq);

	log_verbose("session-register_session-Session Request:");
	log_verbose("%s",reqString);

	url = config_build_url(config, "/Session/Register", true);
	log_verbose("session-register_session-url=%s",url);

#ifdef __DEBUG__
	log_info("session-register_session-Skipping http POST command");
	free(url);
	free(reqString);
	return 0;
#else
	char* respString = NULL;
	int httpRes = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, \
		config->ClientKey, config->ClientKeyPassword, reqString, &respString);

	log_verbose("session-register_session-Session Response:");
	log_verbose("%s",respString);

	if(httpRes == 0)
	{
		struct SessionRegisterResp* resp = SessionRegisterResp_fromJson(respString);
		if(resp->Session.Token)
		{
			if(resp && AgentApiResult_log(resp->Result, NULL, NULL))
			{
				update_config_from_session(config, resp);

				if(resp->Session.Certificate)
				{
					char* status;
					enum AgentApiResultStatus statusCode;
					save_cert_key(config->ClientCert, config->ClientKey, config->ClientKeyPassword, resp->Session.Certificate, keypair, &status, &statusCode);
					log_trace("Successfully returned from save_cert_key");
#ifdef __RPI__
					turn_on_led();
					sleep(1);
					turn_off_led();
					sleep(1);
					turn_on_led();
#endif
				}
				if(keypair)
				{
					EVP_PKEY_free(keypair);
				}

				log_info("session-register_session-New session %s contains %d jobs", resp->Session.Token, resp->Session.Jobs_count);

#ifdef __PLATFORM_FIXED__
				if ( (0 == strcasecmp(EMPTY_SESSION,resp->Session.Token)) && 
					 (true == config->EnrollOnStartup) )
				{
					/* An empty session means the agent hasn't been approved */
					/* turn off EnrollOnStartup in the configuration file */
					log_verbose("session-register_session -- Empty session recieved, turning off EnrollOnStartup");
					config->EnrollOnStartup = false;
					config_save(config);
				}
#endif

				strcpy(session->AgentId, resp->Session.AgentId);
				strcpy(session->Token, resp->Session.Token);
				session->UnreachableCount = 0;

				char schedule[10];
				sprintf(schedule, "I_%d", resp->Session.HeartbeatInterval);
				session->NextExecution = next_execution(schedule, time(NULL));  // TODO - Use time that was passed down
				clear_job_schedules(pJobList);

				for(int i = 0; i < resp->Session.Jobs_count; ++i)
				{
					struct SessionJob* currentJob = resp->Session.Jobs[i];
					schedule_job(pJobList, currentJob, time(NULL)); // TODO - Use time that was passed down
				}
			}

			else if(resp && 
				    resp->Result.Status == STAT_ERR	&& 
					resp->Result.Error.CodeString && 
					strcasecmp("A0100007", resp->Result.Error.CodeString))
			{
				log_info("session-register_session-Re-enrolling for authentication certificate");
				// TODO - Re-enroll for auth cert
				//EVP_PKEY* keyPair = generate_keypair(config->CSRKeyType, config->CSRKeySize);
			}

			else
			{
				char schedule[10];
				sprintf(schedule, "I_%d", session->Interval);
				session->NextExecution = next_execution(schedule, session->NextExecution);
			}
		}
		else
		{
			log_error("session-register_session-Session registration did not succeed with error %s", resp->Result.Error.Message);
			char schedule[10];
			sprintf(schedule, "I_%d", session->Interval);
			session->NextExecution = next_execution(schedule, session->NextExecution);
		}
		SessionRegisterResp_free(resp);
	}

	else
	{
		log_error("session-register_session-Session registration failed with error code %d", httpRes);

		char schedule[10];
		sprintf(schedule, "I_%d", session->Interval);
		session->NextExecution = next_execution(schedule, session->NextExecution);
	}

	free(reqString);
	free(respString);
	free(url);

	return httpRes;
#endif
}

int heartbeat_session(struct ConfigData* config, struct SessionInfo* session, struct ScheduledJob** pJobList, uint64_t agentVersion)
{
	char* url = NULL;
	struct SessionHeartbeatReq* heartbeatReq = SessionHeartbeatReq_new();

	log_info("session-heartbeat_session-Heartbeating current session");

	heartbeatReq->AgentPlatform = PLAT_NATIVE;
	heartbeatReq->ClientMachine = strdup(config->AgentName);
	heartbeatReq->SessionToken = strdup(session->Token);

	char* reqString = SessionHeartbeatReq_toJson(heartbeatReq);
	SessionHeartbeatReq_free(heartbeatReq);

	url = config_build_url(config, "/Session/Heartbeat", true);

	char* respString = NULL;
	int httpRes = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, \
		config->ClientKey, config->ClientKeyPassword, reqString, &respString);
	if(httpRes == 0)
	{
		struct SessionHeartbeatResp* resp = SessionHeartbeatResp_fromJson(respString);

		if(resp && AgentApiResult_log(resp->Result, NULL, NULL))
		{
			if(resp->SessionValid)
			{
				char schedule[10];
				sprintf(schedule, "I_%d", resp->HeartbeatInterval);
				session->NextExecution = next_execution(schedule, session->NextExecution);
				session->UnreachableCount = 0;
			}
			else
			{
				log_info("session-heartbeat_sessionSession is invalid. Re-registering\n");
				strcpy(session->Token, "");
				register_session(config, session, pJobList, agentVersion);
			}
		}
		else
		{
			char schedule[10];
			sprintf(schedule, "I_%d", session->Interval);
			session->NextExecution = next_execution(schedule, session->NextExecution);
		}

		SessionHeartbeatResp_free(resp);
	}
	else
	{
		log_error("session-heartbeat_sessionSession heartbeat failed with error code %d",httpRes);
		session->UnreachableCount++; // TODO - Use UnreachableCount

		char schedule[10];
		sprintf(schedule, "I_%d", session->Interval);
		session->NextExecution = next_execution(schedule, session->NextExecution);
	}

	free(reqString);
	free(respString);
	free(url);

	return httpRes;
}
