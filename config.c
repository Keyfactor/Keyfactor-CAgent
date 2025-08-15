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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "config.h"
#include "logging.h"
#include "lib/json.h"
#include "utils.h"
#include "global.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/
#define DATE_TIME_LEN 14 /* YYYYMMDDHHMMSS */

/******************************************************************************/
/*************************** GLOBAL VARIABLES *********************************/
/******************************************************************************/
bool config_loaded = false;
struct ConfigData* ConfigData;
char* config_location = NULL;
bool use_host_as_agent_name = false;

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
/* print the configuration parameters pulled from config.json                 */
/*                                                                            */
/* @param  - [Input] config = a pointer to the configuration data             */
/* @return - none                                                             */
/*                                                                            */
static void print_config( struct ConfigData* ConfigData )
{
	printf("\n\n          AgentId = %s\n", ConfigData->AgentId);
	printf("          AgentName = %s\n", ConfigData->AgentName);
	printf("          ClientParameterPath = %s\n", 
		ConfigData->ClientParameterPath);
	printf("          Hostname = %s\n", ConfigData->Hostname);
	printf("          Password = %s\n", ConfigData->Password);
	printf("          Username = %s\n", ConfigData->Username);
	printf("          VirtualDirectory = %s\n", ConfigData->VirtualDirectory);
	printf("          TrustStore = %s\n", ConfigData->TrustStore);
	printf("          UseAgentCert = %s\n", ConfigData->UseAgentCert ? "true" : "false");
	printf("          AgentCert = %s\n", ConfigData->AgentCert);
	printf("          AgentKey = %s\n", ConfigData->AgentKey);
	printf("          AgentKeyPassword = %s\n", ConfigData->AgentKeyPassword);
	printf("          UseSsl = %s\n", ConfigData->UseSsl ? "true" : "false");
	printf("          CSRKeyType = %s\n", ConfigData->CSRKeyType);
	printf("          CSRKeySize = %d\n", ConfigData->CSRKeySize);
	printf("          CSRSubject = %s\n", ConfigData->CSRSubject);
	printf("          EnrollOnStartup = %s\n", ConfigData->EnrollOnStartup ? "true" : "false");
	printf("          UseBootstrapCert = %s\n", ConfigData->UseBootstrapCert ? "true" : "false");
	printf("          BootstrapCert = %s\n", ConfigData->BootstrapCert);
	printf("          BootstrapKey = %s\n", ConfigData->BootstrapKey);
	printf("          LogFile = %s\n", ConfigData->LogFile);
	printf("          LogFileIndex = %lu\n", ConfigData->LogFileIndex);
	printf("          httpRetries = %d\n", ConfigData->httpRetries); 
	printf("          retryInterval = %d\n", ConfigData->retryInterval);
	printf("\n\n");
	return;
} /* print_config */

/**                                                                           */
/* Check that the minimum fields are populated & exist in the config.json file*/
/*                                                                            */
/* @params  - none                                                            */
/* @return  - true = all minimum data exists (it may not be right)            */
/*            false = otherwise                                               */
/*                                                                            */
static bool minimum_config_requirements( void )
{
	bool bResult = false;

	do {
		if (!ConfigData->AgentName) {
			log_error("%s::%s(%d) : Agent name is required in config file", LOG_INF);
			break;
		}

		if (1 > strlen(ConfigData->AgentName)) {
			log_error("%s::%s(%d) : Agent name must be at least one character long", LOG_INF);
			break;
		}

		if (!ConfigData->AgentId) {
			log_error("%s::%s(%d) : AgentId field must exist", LOG_INF);
			break;
		}

        if (ConfigData->UseAgentCert) {
        	if (!ConfigData->CSRSubject) {
        		log_error("%s::%s(%d) : Agent CSR subject must exist", LOG_INF);
        		break;
        	}

        	if (4 > strlen(ConfigData->CSRSubject)) {
        		log_error("%s::%s(%d) : Agent CSR subject must minimally be CN=x "
					"where x is a single character", LOG_INF);
        		break;
        	}

			if (!ConfigData->AgentCert) {
				log_error("%s::%s(%d) : Agent Cert file must be in the "
					"config.json file", LOG_INF);
				break;
			}

			if (!ConfigData->AgentKey) {
				log_error("%s::%s(%d) : Agent Key file must be in the "
					"config.json file", LOG_INF);
				break;
			}
        }

		if (!ConfigData->Hostname) {
			log_error("%s::%s(%d) : Hostname must be in the config.json file", LOG_INF);
			break;
		}

		if (7 > strlen(ConfigData->Hostname)) {
			log_error("%s::%s(%d) : Minimal hostname is 7 characters long x.x.x.x", LOG_INF);
			break;
		}

		if (ConfigData->UseBootstrapCert) {
			if (!ConfigData->BootstrapCert) {
				log_error("%s::%s(%d) : BootstrapCert filename is required if UseBootstrapCert is true", LOG_INF);
				break;
			}

			if (!ConfigData->BootstrapKey) {
				log_error("%s::%s(%d) : BootstrapKey filename is required if UseBootstrapCert is true", LOG_INF);
				break;
			}
		}

		bResult = true;
	} while(false);

	return bResult;
} /* minimum_config_requirements */

/**                                                                           */
/* Check that the agent cert & agent key directories exist                    */
/* and that the agent callout is actually a file and not a directory          */
/*                                                                            */
/* NOTE: Should run after minimum_config_requirements, so we can guarantee    */
/*       ConfigData->AgentCert and ConfigData->AgentKey are actually there.   */
/*                                                                            */
/* @param  - [Input] None                                                     */
/* @return - true = the directories exist and the pointer is to a file        */
/*         - false = otherwise                                                */
/*                                                                            */
static bool agent_directory_exists( void )
{
	bool bResult = false;
	char* directoryPart = NULL;

	do {
		if (ConfigData->UseAgentCert) {
			if (is_directory(ConfigData->AgentCert)) {
				log_error("%s::%s(%d) : %s is a directory. It must be a <path>/<filename>.", LOG_INF, ConfigData->AgentCert);
				break;
			}

			if (is_directory(ConfigData->AgentKey)) {
				log_error("%s::%s(%d) : %s is a directory. It must be a <path>/<filename>.", LOG_INF, ConfigData->AgentKey);
				break;
			}

			directoryPart = get_prefix_substring( ConfigData->AgentCert, '/' );
			if (directoryPart) {
				if ( !is_directory(directoryPart) ) {
					log_error("%s::%s(%d) : Directory %s does not exist", LOG_INF, directoryPart);
					break;
				}
				free(directoryPart);
			}

			directoryPart = get_prefix_substring( ConfigData->AgentKey, '/');
			if (directoryPart) {
				if ( !is_directory(directoryPart) ) {
					log_error("%s::%s(%d) : Directory %s does not exist",
						LOG_INF, directoryPart);
					break;
				}
				free(directoryPart);
			}
		} else {
			log_debug("%s::%s(%d) : Skipping agent directory check for certs and such", LOG_INF);
		}

		bResult = true;
	} while(false);

	return bResult;
} /* agent_directory_exits */

/**                                                                           */
/* Check the keypair type & if it is an ecc, make sure we implemented         */
/* that keysize                                                               */
/*                                                                            */
/* @param  - none                                                             */
/* @return - true  = good key type & size                                     */
/*           false = otherwise                                                */
/*                                                                            */
static bool keypair_sanity_check( void )
{
	bool bResult = false;

	if (0 == strcasecmp("ecc", ConfigData->CSRKeyType)  ||
	    0 == strcasecmp("ecdsa", ConfigData->CSRKeyType) )	{
		switch(ConfigData->CSRKeySize) {
			case 256:
			case 384:
			case 521:
			 bResult = true;
			 break;

			default:
			 log_error("%s::%s(%d) : %d is not an implemented ECC keysize", LOG_INF, ConfigData->CSRKeySize);
			 goto exit;
			 break; /* pedantry */
		}
	} else if (0 == strcasecmp("rsa", ConfigData->CSRKeyType)) {
		bResult = true; /* Key sizes can be of any reasonable length */
	} else {
		log_error("%s::%s(%d) : Error %s is an unknown key type", LOG_INF, ConfigData->CSRKeyType);
	}

exit:
	return bResult;
} /* keypair_sanity_check */

/**                                                                           */
/* Get the agent name and CN from the $HOSTNAME and datetime instead of the   */
/* config.json.                                                               */
/*                                                                            */
/* If this function fails, it does not modify AgentName and Subject in the    */
/* configuration file.                                                        */
/*                                                                            */
/* @param  - config = pointer to the configuration data structure to modify   */
/* @return - none                                                             */
/*                                                                            */
static void set_agent_name( struct ConfigData* config )
{
	bool bResult = false;

	char hostbuffer[256];
	struct hostent* host_entry;
	int hostname;
	size_t agentNameSz;

	struct tm* tm = NULL;
	time_t t;
	char tBuf[DATE_TIME_LEN+1];

	char* newAgentName = NULL;
	char* newSubject = NULL;

	log_verbose("%s::%s(%d) : Retrieving hostname", LOG_INF);
	hostname = gethostname(hostbuffer, sizeof(hostbuffer));
	if (-1 == hostname) {
		log_error("%s::%s(%d) : Failed to retrieve hostname from host OS", LOG_INF);
		goto cleanup;
	}
	log_info("%s::%s(%d) : Hostname found as %s", LOG_INF, hostbuffer);
	agentNameSz = strlen(hostbuffer);

	log_verbose("%s::%s(%d) : Retrieving time from OS", LOG_INF);
	if ( !time(&t) ) {
		log_error("%s::%s(%d) : Error getting time from OS", LOG_INF);
		goto cleanup;
	}
	tm = gmtime(&t);
	(void)strftime(tBuf, DATE_TIME_LEN+1, "%Y%m%d%H%M%S", tm);
	log_verbose("%s::%s(%d) : Date time is %s", LOG_INF, tBuf);
	agentNameSz += DATE_TIME_LEN;
	agentNameSz++; /* Remember to add one for the _ */
	agentNameSz++; /* And for the \0 */

	newAgentName = calloc(agentNameSz, sizeof(*newAgentName));
	if ( !newAgentName ) {
		log_error("%s::%s(%d) : Out of memory!", LOG_INF);
		goto cleanup;
	}
	(void)snprintf(newAgentName, agentNameSz, "%s_%s", hostbuffer, tBuf);

	if (config->UseAgentCert) {
		newSubject = calloc(agentNameSz+3, sizeof(*newSubject));
		if ( !newSubject )
		{
			log_error("%s::%s(%d) : Out of memory!", LOG_INF);
			goto cleanup;
		}
		(void)snprintf(newSubject, agentNameSz+3, "%s%s_%s", "CN=", hostbuffer, tBuf);
	}

	if (config->AgentName) {
		free(config->AgentName);
		config->AgentName = NULL;
		config->AgentName = newAgentName;
		log_info("%s::%s(%d) : Agent name set to %s", LOG_INF, config->AgentName);
	}

    if (config->UseAgentCert) {
		if (config->CSRSubject)	{
			free(config->CSRSubject);
			config->CSRSubject = NULL;
			config->CSRSubject = newSubject;
			log_info("%s::%s(%d) : Agent subject set to %s", LOG_INF, config->CSRSubject);
		}
	}

	bResult = true;

cleanup:
	return;
} /* set_agent_name */


/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* Convert a configuration json string into a configuration structure.  Call  */
/* this function directly if you are not using the config_load() function     */
/* to grab the configuration from the file config.json directly.              */
/*                                                                            */
/* For example:                                                               */
/* You are using a securely encoded file & need to decode it before the       */
/* json is readable.  Perform the decoding & pass the decoded string to this  */
/* function.                                                                  */
/*                                                                            */
/* NOTE: This configuration structure needs to be freed by calling            */
/*       ConfigData_free(ConfigData*) before ending the process thread.       */
/*                                                                            */
/* @param  - [Input] : buf = the configuration json string, NULL terminated   */
/* @return - success : a filled out configuration structure                   */
/*           failure : NULL                                                   */
/*                                                                            */
struct ConfigData* config_decode(const char* buf)
{
	struct ConfigData* config = NULL;
	/* The entire configuration file is in buf, so now decode it */
	JsonNode* jsonRoot = json_decode(buf);
	if(jsonRoot) {
		config = calloc(1, sizeof(struct ConfigData));
		if ( NULL == config ) {
			log_error("%s::%s(%d) : Out of memory! ", LOG_INF);
			return NULL;
		}

		config->AgentId = json_get_member_string(jsonRoot, "AgentId");
		if (config->AgentId) {
			if ( (UUID_LEN-1) > strlen(config->AgentId) ) {
				/* The GUID is malformed, reallocate the size */
				log_trace("%s::%s(%d) : Resizing agent id to %lu bytes", 
					LOG_INF, UUID_LEN * sizeof(*(config->AgentId)) );
				config->AgentId = 
				realloc(config->AgentId, UUID_LEN * sizeof(*(config->AgentId)));
			}
		}
		config->AgentName = json_get_member_string(jsonRoot, "AgentName");
		config->ClientParameterPath = json_get_member_string(jsonRoot, "ClientParameterPath");
		config->Hostname = json_get_member_string(jsonRoot, "Hostname");
		config->Password = json_get_member_string(jsonRoot, "Password");
		config->Username = json_get_member_string(jsonRoot, "Username");
		config->VirtualDirectory = json_get_member_string(jsonRoot, "VirtualDirectory");
		config->TrustStore = json_get_member_string(jsonRoot, "TrustStore");
		config->UseAgentCert = json_get_member_bool(jsonRoot, "UseAgentCert", true);
		if (config->UseAgentCert) {
			config->AgentCert = json_get_member_string(jsonRoot, "AgentCert");
			config->AgentKey = json_get_member_string(jsonRoot, "AgentKey");
			config->AgentKeyPassword = json_get_member_string(jsonRoot, "AgentKeyPassword");
			config->CSRKeyType = json_get_member_string(jsonRoot, "CSRKeyType");
			config->CSRKeySize =json_get_member_number(jsonRoot,"CSRKeySize",0);
			config->CSRSubject = json_get_member_string(jsonRoot, "CSRSubject");
        }
		config->UseSsl = json_get_member_bool(jsonRoot, "UseSsl", true);
		config->EnrollOnStartup = json_get_member_bool(jsonRoot, "EnrollOnStartup", false);
		config->UseBootstrapCert = json_get_member_bool(jsonRoot, "UseBootstrapCert", false);
		config->BootstrapCert = json_get_member_string(jsonRoot, "BootstrapCert");
		config->BootstrapKey = json_get_member_string(jsonRoot, "BootstrapKey");
		config->BootstrapKeyPassword = json_get_member_string(jsonRoot,	"BootstrapKeyPassword");
		config->LogFile = json_get_member_string(jsonRoot, "LogFile");
		config->LogFileIndex = json_get_member_number(jsonRoot, "LogFileIndex", 0);
		config->httpRetries = json_get_member_number(jsonRoot, "httpRetries",1); 
		if(1 > config->httpRetries) { /* verify minimum value */
			config->httpRetries = 1;
		}
		config->retryInterval = json_get_member_number(jsonRoot, "retryInterval", 1);

		json_delete(jsonRoot);

		if (use_host_as_agent_name && config->EnrollOnStartup) {
			set_agent_name(config);
		}

		if ( is_log_verbose() ) {
			log_verbose("%s::%s(%d) : Config parameters follow:", LOG_INF);
			print_config( config );
		}

		config_loaded = true;
	} else {
		log_error("%s::%s(%d) : Contents of %s are not valid JSON",	LOG_INF, config_location);
	}

	return config;
} /* config_decode */

/**                                                                           */
/* Load data from the configuration file into the configuration data          */
/* structure The configuration file "config.json" must be in the same         */
/* directory as the agent (unless the -c switch is used to specify)           */
/*                                                                            */
/* @param  - none                                                             */
/* @return - a reference to a filled out ConfigData element                   */
/*           NULL on error                                                    */
/*                                                                            */
struct ConfigData* config_load( void )
{
	char buf[MAX_CONFIG_FILE_LEN]; 

	if (file_exists(config_location)) {
		FILE* fp = fopen(config_location, "r");
		if(fp) {
			size_t len = fread(buf, 1, MAX_CONFIG_FILE_LEN-1, fp);
			buf[len++] = '\0';
			fclose(fp);
		} else {
			int err = errno;
			log_error("%s::%s(%d) : Unable to open config file %s: %s", LOG_INF, config_location, strerror(err));
			return NULL;
		}
	} else {
		log_error("%s::%s(%d) : Either %s does not exist or is a directory", LOG_INF, config_location);
		return NULL;
	}

	return config_decode(buf);
} /* config_load */

/**                                                                           */
/* Convert the configuration data structure into a json string. Call          */
/* this function directly if you are not using the config_save() function     */
/* to save the configuration to the file config.json file directly.           */
/*                                                                            */
/* For example:                                                               */
/* You are using a securely encoded file & need to encode it before saving    */
/* the file to disk.                                                          */
/*                                                                            */
/* @return - A json encoded string                                            */
/*                                                                            */
char* config_to_json( void )
{
	JsonNode* jsonRoot = json_mkobject();
	if(ConfigData->AgentId)	{
		json_append_member(jsonRoot, "AgentId", json_mkstring(ConfigData->AgentId));
	}
	if(ConfigData->AgentName) {
		json_append_member(jsonRoot, "AgentName", json_mkstring(ConfigData->AgentName));
	}
	if(ConfigData->ClientParameterPath)	{
		json_append_member(jsonRoot, "ClientParameterPath", json_mkstring(ConfigData->ClientParameterPath));
	}
	if(ConfigData->Hostname) {
		json_append_member(jsonRoot, "Hostname", json_mkstring(ConfigData->Hostname));
	}
	if(ConfigData->Password) {
		json_append_member(jsonRoot, "Password", json_mkstring(ConfigData->Password));
	}
	if(ConfigData->Username) {
		json_append_member(jsonRoot, "Username", json_mkstring(ConfigData->Username));
	}
	if(ConfigData->VirtualDirectory) {
		json_append_member(jsonRoot, "VirtualDirectory", json_mkstring(ConfigData->VirtualDirectory));
	}
	if(ConfigData->TrustStore) {
		json_append_member(jsonRoot, "TrustStore", json_mkstring(ConfigData->TrustStore));
	}
	if(ConfigData->AgentCert) {
		json_append_member(jsonRoot, "AgentCert", json_mkstring(ConfigData->AgentCert));
	}
	if(ConfigData->AgentKey) {
		json_append_member(jsonRoot, "AgentKey", json_mkstring(ConfigData->AgentKey));
	}
	if(ConfigData->AgentKeyPassword) {
		json_append_member(jsonRoot, "AgentKeyPassword", json_mkstring(ConfigData->AgentKeyPassword));
	}
	if(ConfigData->CSRKeyType) {
		json_append_member(jsonRoot, "CSRKeyType", json_mkstring(ConfigData->CSRKeyType));
	}
	if(ConfigData->CSRKeySize) {
		json_append_member(jsonRoot, "CSRKeySize", json_mknumber(ConfigData->CSRKeySize));
	}
	if(ConfigData->CSRSubject) {
		json_append_member(jsonRoot, "CSRSubject", json_mkstring(ConfigData->CSRSubject));
	}
	json_append_member(jsonRoot, "EnrollOnStartup", json_mkbool(ConfigData->EnrollOnStartup));
	if(ConfigData->UseBootstrapCert) {
		json_append_member(jsonRoot, "UseBootstrapCert", json_mkbool(ConfigData->UseBootstrapCert));
	}
	if(ConfigData->BootstrapCert) {
		json_append_member(jsonRoot, "BootstrapCert", json_mkstring(ConfigData->BootstrapCert));
	}
	if(ConfigData->BootstrapKey) {
		json_append_member(jsonRoot,"BootstrapKey",	json_mkstring(ConfigData->BootstrapKey));
	}
	if(ConfigData->BootstrapKeyPassword) {
		json_append_member(jsonRoot,"BootstrapKeyPassword", json_mkstring(ConfigData->BootstrapKeyPassword));
	}
	json_append_member(jsonRoot, "UseSsl", json_mkbool(ConfigData->UseSsl));
	if(ConfigData->LogFile)	{
		json_append_member(jsonRoot, "LogFile", json_mkstring(ConfigData->LogFile));
	}
	json_append_member(jsonRoot, "LogFileIndex", json_mknumber(ConfigData->LogFileIndex));
	if(ConfigData->httpRetries)	{
		json_append_member(jsonRoot, "httpRetries", json_mknumber(ConfigData->httpRetries));
	}
	if(ConfigData->retryInterval) {
		json_append_member(jsonRoot, "retryInterval", json_mknumber(ConfigData->retryInterval));
	}
	if(ConfigData->UseAgentCert) {
		json_append_member(jsonRoot, "UseAgentCert", json_mkbool(ConfigData->UseAgentCert));
    }

	char* confString = json_stringify(jsonRoot, "\t");
	json_delete(jsonRoot);

	return confString;
} /* config_to_json */

/**
 * Save the configuration structure to "config.json" on the file system
 *
 * @return - success : true
 *           failure : false
 */
bool config_save( void )
{
	bool bResult = false;
	char* confString = config_to_json();
	
	char eol[1] = {'\n'};
	FILE* fp = fopen(config_location, "w");
	if(fp) {
		fwrite(confString, 1, strlen(confString), fp);
		fwrite(eol, 1, 1, fp);
		free(confString);
		fclose(fp);
		bResult = true;
	} else {
		int err = errno;
		log_error("%s::%s(%d) : Unable to open config file %s: %s", LOG_INF, config_location, strerror(err));
	}

	return bResult;
} /* config_save */

/**                                                                           */
/* Sanity check on the configuration file to check for errors before          */
/* launching.  Should run after the log files are up and running to           */
/* log errors to disk.                                                        */
/*                                                                            */
/* @param  - none, operates on the global ConfigData variable                 */
/* @return - success : true                                                   */
/*           failure : false                                                  */
/*                                                                            */
bool validate_configuration( void )
{
	bool bResult = false;

	do
	{
		log_debug("%s::%s(%d) : Checking config minimimum requirements", LOG_INF);
		if (!minimum_config_requirements()) {
			log_error("%s::%s(%d) : Config missing minimum requirements", LOG_INF);
			break;
		}
		log_debug("%s::%s(%d) : Config meets minimum requirements", LOG_INF);

		log_debug("%s::%s(%d) : Checking that the agent directory exists", LOG_INF);
		if (!agent_directory_exists()) {
			log_error("%s::%s(%d) : Agent configuration is bad", LOG_INF);
			break;
		}
		log_debug("%s::%s(%d) : Agent directory exists", LOG_INF);

		log_debug("%s::%s(%d) : Checking that the trust store exists", LOG_INF);
		if (!file_exists(ConfigData->TrustStore)) {
			log_error("%s::%s(%d) : Trust store location is bad or file not found", LOG_INF);
			break;
		}
		log_debug("%s::%s(%d) : The trust store exists", LOG_INF);

		if (ConfigData->UseAgentCert) {
			log_debug("%s::%s(%d) : Checking that the keypair looks ok", LOG_INF);
			if (!keypair_sanity_check()) {
				log_error("%s::%s(%d) : Keypair is not valid", LOG_INF);
				break;
			}
			log_debug("%s::%s(%d) : The keypair looks ok", LOG_INF);
		}

		log_verbose("%s::%s(%d) : Config meets minimum requirements", LOG_INF);
		bResult = true;
	} while(false);

	return bResult;
} /* validate_configuration */

/**                                                                           */
/* Build the url from information in the config data and the relative         */
/* endpoint passed from the platform.  NOTE: v7.4+ of the platform            */
/* has a bug where it will always pass KeyfactorAgents/ make sure to          */
/* strip that from the string passed in relPath.                              */
/*                                                                            */
/* @param  - [Input] : relPath = the endpoint the Platfrom wants to hit       */
/* @param  - [Input] : vdirFromConfig = yes if you need to use a proxy at the */
/*                     platform side.  no otherwise.                          */
/* @return - success : a completed URL                                        */
/*           failure : NULL                                                   */
/*                                                                            */
char* config_build_url(const char* relPath, bool vdirFromConfig)
{
	char* url = NULL;
	char* relPathStripped = NULL;

	if(ConfigData && relPath) {
		if ( true == ConfigData->UseSsl ) {
			url = strdup("https://");
		} else {
			url = strdup("http://");
		}
        if (!url) {
            log_error("%s::%s(%d) : Out of memory", LOG_INF);
            return NULL;
        }

		log_trace("%s::%s(%d) : url = %s",	LOG_INF, url);

		url = realloc(url, (strlen(url)+strlen(ConfigData->Hostname)+1) ); /* parasoft-suppress BD-RES-LEAKS "Freed by calling function" */
        if (!url) {
            log_error("%s::%s(%d) : Out of memory", LOG_INF);
            return NULL;
        }
		strcat(url, ConfigData->Hostname);
		log_trace("%s::%s(%d) : Added Hostname to url is now = %s",LOG_INF, url);
		
		if(vdirFromConfig)	{
			url = realloc( url, (strlen(url) + strlen(ConfigData->VirtualDirectory)+2) );
			strcat(url, "/");
			strcat(url, ConfigData->VirtualDirectory);
			log_trace("%s::%s(%d) : Added Virutal Directory to url is now = %s", LOG_INF, url);
		}

		if(strcspn(relPath, "/") != 0)	{
			url = realloc( url, (strlen(url)+2) );
			strcat(url, "/");
			log_trace("%s::%s(%d) : Added / to url is now = %s", LOG_INF, url);
		}

		/* Remove KeyfactorAgents/ from the relPath                           */
		/* TODO: Remove this if statement and replace with                    */
		/*       strcat(url, relPath); Once the platform changes              */ 
		/*       to not send KeyfactorAgents                                  */
		log_trace("%s::%s(%d) : Stripping KeyfactorAgents/ from %s", LOG_INF, relPath);
		relPathStripped = util_strip_string(relPath, "KeyfactorAgents/");
		log_trace("%s::%s(%d) : New relPath = %s", LOG_INF, relPathStripped);
		url = realloc( url, (strlen(url)+strlen(relPathStripped)+1) );
        if (!url) {
            log_error("%s::%s(%d) : Out of memory", LOG_INF);
            return NULL;
        }
		strcat(url, relPathStripped);
		log_trace("%s::%s(%d) : url = %s", LOG_INF, url);
	} else {
		log_error("%s::%s(%d) : Unable to build url: Invalid arguments", LOG_INF);
	}

	if ( relPathStripped ) {
		free(relPathStripped);
	}
	log_trace("%s::%s(%d) : url = %s", LOG_INF, url);
	return url;
} /* config_build_url */

/**                                                                           */
/* Release memory associated with the ConfigData element                      */
/*                                                                            */
/* @return none                                                               */
/*                                                                            */
void ConfigData_free( void )
{
	if(ConfigData) {
		if(ConfigData->AgentId) {
			free(ConfigData->AgentId);
			ConfigData->AgentId = NULL;
		}
		if(ConfigData->AgentName) {
			free(ConfigData->AgentName);
			ConfigData->AgentName = NULL;
		}
		if(ConfigData->ClientParameterPath) {
			free(ConfigData->ClientParameterPath);
			ConfigData->ClientParameterPath = NULL;
		}
		if(ConfigData->Hostname) {
			free(ConfigData->Hostname);
			ConfigData->Hostname = NULL;
		}
		if(ConfigData->Password) {
			free(ConfigData->Password);
			ConfigData->Password = NULL;
		}
		if(ConfigData->Username) {
			free(ConfigData->Username);
			ConfigData->Username = NULL;
		}
		if(ConfigData->VirtualDirectory) {
			free(ConfigData->VirtualDirectory);
			ConfigData->VirtualDirectory = NULL;
		}
		if(ConfigData->TrustStore) {
			free(ConfigData->TrustStore);
			ConfigData->TrustStore = NULL;
		}
		if(ConfigData->AgentCert) {
			free(ConfigData->AgentCert);
			ConfigData->AgentCert = NULL;
		}
		if(ConfigData->AgentKey) {
			free(ConfigData->AgentKey);
			ConfigData->AgentKey = NULL;
		}
		if(ConfigData->AgentKeyPassword) {
			free(ConfigData->AgentKeyPassword);
			ConfigData->AgentKeyPassword = NULL;
		}
		if(ConfigData->CSRKeyType) {
			free(ConfigData->CSRKeyType);
			ConfigData->CSRKeyType = NULL;
		}
		if(ConfigData->CSRSubject) {
			free(ConfigData->CSRSubject);
			ConfigData->CSRSubject = NULL;
		}
		if(ConfigData->LogFile) {
			free(ConfigData->LogFile);
			ConfigData->LogFile = NULL;
		}
		if(ConfigData->BootstrapCert) {
			free(ConfigData->BootstrapCert);
			ConfigData->BootstrapCert = NULL;
		}
		if(ConfigData->BootstrapKey) {
			free(ConfigData->BootstrapKey);
			ConfigData->BootstrapKey = NULL;
		}
		if(ConfigData->BootstrapKeyPassword) {
			free(ConfigData->BootstrapKeyPassword);
			ConfigData->BootstrapKeyPassword = NULL;
		}

		free(ConfigData);
	}
	config_loaded = false;
	return;
} /* ConfigData_free */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/