/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file config.c */
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

/**
	print the configuration parameters pulled from config.json
	@param  - [Input] config = a pointer to the configuration data
	@return - none
 */
static void print_config( struct ConfigData *config )
{
	printf("\n\n          AgentId = %s\n", config->AgentId);
	printf("          AgentName = %s\n", config->AgentName);
	printf("          ClientParameterPath = %s\n",
										config->ClientParameterPath);
	printf("          Hostname = %s\n", config->Hostname);
	printf("          Password = %s\n", config->Password);
	printf("          Username = %s\n", config->Username);
	printf("          VirtualDirectory = %s\n", config->VirtualDirectory);
	printf("          TrustStore = %s\n", config->TrustStore);
	printf("          AgentCert = %s\n", config->AgentCert);
	printf("          AgentKey = %s\n", config->AgentKey);
	printf("          AgentKeyPassword = %s\n", config->AgentKeyPassword);
	printf("          UseSsl = %s\n", config->UseSsl ? "true" : "false");
	printf("          CSRKeyType = %s\n", config->CSRKeyType);
	printf("          CSRKeySize = %d\n", config->CSRKeySize);
	printf("          CSRSubject = %s\n", config->CSRSubject);
	printf("          EnrollOnStartup = %s\n",
									config->EnrollOnStartup ? "true" : "false");
	printf("          Serialize = %s\n", config->Serialize ? "true" : "false");
	printf("          SerialFile = %s\n", config->SerialFile);
	printf("          httpRetries = %d\n", config->httpRetries); /* BL-20654 */
	printf("          retryInterval = %d\n", config->retryInterval);/*BL-20654*/
	printf("\n\n");
	return;
} /* print_config */

/**
 * Convert a configuration json string into a configuration structure.  Call
 * this function directly if you are not using the config_load() function
 * to grab the configuration from the file config.json directly.  
 *
 * For example:
 * You are using a securely encoded file & need to decode it before the
 * json is readable.  Perform the decoding & pass the decoded string to this
 * function.
 *
 * NOTE: This configuration structure needs to be freed by calling 
 *       ConfigData_free(ConfigData*) before ending the process thread.
 *
 * @param  - [Input] : buf = the configuration json string, NULL terminated
 * @return - success : a filled out configuration structure
 *           failure : NULL
 */
struct ConfigData* config_decode(const char* buf)
{
	struct ConfigData* config = NULL;
	/* The entire configuration file is in buf, so now decode it */
	JsonNode* jsonRoot = json_decode(buf);
	if(jsonRoot)
	{
		config = calloc(1, sizeof(struct ConfigData));
		if ( NULL == config )
		{
			log_error("%s::%s(%d) : Out of memory! ", \
				__FILE__, __FUNCTION__, __LINE__);
			return NULL;
		}

		config->AgentId = json_get_member_string(jsonRoot, "AgentId");
		if ( (UUID_LEN-1) > strlen(config->AgentId) )
		{
			/* The GUID is malformed, reallocate the size */
			log_trace("%s::%s(%d) : Resizing agent id to %lu bytes", \
				__FILE__, __FUNCTION__, __LINE__, \
				UUID_LEN * sizeof(*(config->AgentId)) );
			config->AgentId = realloc(config->AgentId, 
				UUID_LEN * sizeof(*(config->AgentId)) );
		}
		config->AgentName = json_get_member_string(jsonRoot, "AgentName");
		config->ClientParameterPath = 
					json_get_member_string(jsonRoot, "ClientParameterPath");
		config->Hostname = json_get_member_string(jsonRoot, "Hostname");
		config->Password = json_get_member_string(jsonRoot, "Password");
		config->Username = json_get_member_string(jsonRoot, "Username");
		config->VirtualDirectory = 
					   json_get_member_string(jsonRoot, "VirtualDirectory");
		config->TrustStore = json_get_member_string(jsonRoot, "TrustStore");
		config->AgentCert = json_get_member_string(jsonRoot, "AgentCert");
		config->AgentKey = json_get_member_string(jsonRoot, "AgentKey");
		config->AgentKeyPassword = 
					json_get_member_string(jsonRoot, "AgentKeyPassword");
		config->UseSsl = json_get_member_bool(jsonRoot, "UseSsl", true);
		config->CSRKeyType = json_get_member_string(jsonRoot, "CSRKeyType");
		config->CSRKeySize =json_get_member_number(jsonRoot,"CSRKeySize",0);
		config->CSRSubject = json_get_member_string(jsonRoot, "CSRSubject");
		config->EnrollOnStartup = 
				json_get_member_bool(jsonRoot, "EnrollOnStartup", false);
		config->Serialize = 
				json_get_member_bool(jsonRoot, "Serialize", false);
		config->SerialFile = json_get_member_string(jsonRoot, "SerialFile");
		config->LogFile = json_get_member_string(jsonRoot, "LogFile");
		config->httpRetries = \
			json_get_member_number(jsonRoot, "httpRetries", 1); /* BL20654 */
		if(1 > config->httpRetries) /* BL20654 - verify minimum value */
		{
			config->httpRetries = 1;
		}
		config->retryInterval = json_get_member_number(jsonRoot, \
			"retryInterval", 1); /* BL20564 */

		json_delete(jsonRoot);

		if ( is_log_verbose() )
		{
			log_verbose("%s::%s(%d) : Config parameters follow:", \
				__FILE__, __FUNCTION__, __LINE__);
			print_config( config );
		}
	}
	else
	{
		log_error("%s::%s(%d) : Contents of %s are not valid JSON", 
					__FILE__, __FUNCTION__, __LINE__, CONFIG_LOCATION);
	}

	return config;
} /* config_decode */

/**
 * Load data from the configuration file into the configuration data structure
 * The configuration file "config.json" must be in the same directory as
 * the agent.
 *
 * @param  - none
 * @return - a reference to a filled out ConfigData element
 */
struct ConfigData* config_load()
{
	char buf[MAX_CONFIG_FILE_LEN]; 

	FILE* fp = fopen(CONFIG_LOCATION, "r");
	if(fp)
	{	
		size_t len = fread(buf, 1, MAX_CONFIG_FILE_LEN-1, fp);
		buf[len++] = '\0';
		fclose(fp);
	}
	else
	{
		int err = errno;
		log_error("%s::%s(%d) : Unable to open config file %s: %s", \
					__FILE__, __FUNCTION__, __LINE__, \
					CONFIG_LOCATION, strerror(err));
		return NULL;
	}

	return config_decode(buf);
} /* config_load */

/**
 * Convert the configuration data structure into a json string. Call
 * this function directly if you are not using the config_save() function
 * to save the configuration to the file config.json file directly.
 * 
 * For example:
 * You are using a securely encoded file & need to encode it before saving
 * the file to disk.  
 *
 * @param  - [Input] config = a reference to a filled out ConfigData element
 * @return - A json encoded string
 */
char* config_to_json(struct ConfigData* config)
{
	JsonNode* jsonRoot = json_mkobject();
	if(config->AgentId)	{
		json_append_member(jsonRoot, "AgentId", \
							json_mkstring(config->AgentId));
	}
	if(config->AgentName) {
		json_append_member(jsonRoot, "AgentName", \
							json_mkstring(config->AgentName));
	}
	if(config->ClientParameterPath)	{
		json_append_member(jsonRoot, "ClientParameterPath", \
							json_mkstring(config->ClientParameterPath));
	}
	if(config->Hostname) {
		json_append_member(jsonRoot, "Hostname", \
							json_mkstring(config->Hostname));
	}
	if(config->Password) {
		json_append_member(jsonRoot, "Password", \
							json_mkstring(config->Password));
	}
	if(config->Username) {
		json_append_member(jsonRoot, "Username", \
							json_mkstring(config->Username));
	}
	if(config->VirtualDirectory) {
		json_append_member(jsonRoot, "VirtualDirectory", \
							json_mkstring(config->VirtualDirectory));
	}
	if(config->TrustStore) {
		json_append_member(jsonRoot, "TrustStore", \
							json_mkstring(config->TrustStore));
	}
	if(config->AgentCert) {
		json_append_member(jsonRoot, "AgentCert", \
							json_mkstring(config->AgentCert));
	}
	if(config->AgentKey) {
		json_append_member(jsonRoot, "AgentKey", \
							json_mkstring(config->AgentKey));
	}
	if(config->AgentKeyPassword) {
		json_append_member(jsonRoot, "AgentKeyPassword", \
							json_mkstring(config->AgentKeyPassword));
	}
	if(config->CSRKeyType) {
		json_append_member(jsonRoot, "CSRKeyType", \
							json_mkstring(config->CSRKeyType));
	}
	if(config->CSRKeySize) {
		json_append_member(jsonRoot, "CSRKeySize", \
							json_mknumber(config->CSRKeySize));
	}
	if(config->CSRSubject) {
		json_append_member(jsonRoot, "CSRSubject", \
							json_mkstring(config->CSRSubject));
	}
	json_append_member(jsonRoot, "EnrollOnStartup", \
							json_mkbool(config->EnrollOnStartup));
	json_append_member(jsonRoot, "UseSsl", \
							json_mkbool(config->UseSsl));
	json_append_member(jsonRoot, "Serialize", \
							json_mkbool(config->Serialize));
	if(config->SerialFile) {
		json_append_member(jsonRoot, "SerialFile", \
							json_mkstring(config->SerialFile));
	}
	if(config->LogFile)	{
		json_append_member(jsonRoot, "LogFile", \
			json_mkstring(config->LogFile));
	}
	/* Begin BL-20654 */
	if(config->httpRetries)	{
		json_append_member(jsonRoot, "httpRetries", \
			json_mknumber(config->httpRetries));
	}
	if(config->retryInterval) {
		json_append_member(jsonRoot, "retryInterval", \
			json_mknumber(config->retryInterval));
	}
	/* End BL-20654 */

	char* confString = json_stringify(jsonRoot, "\t");
	json_delete(jsonRoot);

	return confString;
} /* config_to_json */

/**
 * Save the configuration structure to "config.json" on the file system
 *
 * @param  - [Input] config = a reference to a filled out ConfigData element
 * @return - success : true
 *           failure : false
 */
bool config_save(struct ConfigData* config)
{
	bool bResult = false;
	char* confString = config_to_json(config);
	
	char eol[1] = {'\n'};
	FILE* fp = fopen(CONFIG_LOCATION, "w");
	if(fp)
	{
		fwrite(confString, 1, strlen(confString), fp);
		fwrite(eol, 1, 1, fp);
		free(confString);
		fclose(fp);
		bResult = true;
	}
	else
	{
		int err = errno;
		log_error("%s::%s(%d) : Unable to open config file %s: %s", 
					__FILE__, __FUNCTION__, __LINE__, \
					CONFIG_LOCATION, strerror(err));
	}

	return bResult;
} /* config_save */

/**
 * Build the url from information in the config data and the relative 
 * endpoint passed from the platform.  NOTE: v7.4+ of the platform 
 * has a bug where it will always pass KeyfactorAgents/ make sure to 
 * strip that from the string passed in relPath.
 *
 * @param  - [Input] : config = configuration data structure
 * @param  - [Input] : relPath = the endpoint the Platfrom wants to hit
 * @param  - [Input] : vdirFromConfig = yes if you need to use a proxy at the 
 *                     platform side.  no otherwise.
 * @return - success : a completed URL
 *           failure : NULL
 */
char* config_build_url(struct ConfigData* config, const char* relPath, \
	bool vdirFromConfig)
{
	char* url = NULL;
	char* relPathStripped = NULL;

	if(config && relPath)
	{
		if ( true == config->UseSsl ) {
			url = strdup("https://");
		}
		else {
			url = strdup("http://");
		}
		log_trace("%s::%s(%d) : url = %s",
			__FILE__, __FUNCTION__, __LINE__, url);

		url = realloc(url, (strlen(url)+strlen(config->Hostname)+1) );
		strcat(url, config->Hostname);
		log_trace("%s::%s(%d) : Added Hostname to url is now = %s",
			__FILE__, __FUNCTION__, __LINE__, url);
		
		if(vdirFromConfig)	{	
			url = realloc( url, \
				(strlen(url)+strlen(config->VirtualDirectory)+2) );
			strcat(url, "/");
			strcat(url, config->VirtualDirectory);
			log_trace("%s::%s(%d) : Added Virutal Directory to url is now = %s",
			__FILE__, __FUNCTION__, __LINE__, url);
		}

		if(strcspn(relPath, "/") != 0)	{
			url = realloc( url, (strlen(url)+2) );
			strcat(url, "/");
			log_trace("%s::%s(%d) : Added / to url is now = %s",
			__FILE__, __FUNCTION__, __LINE__, url);
		}

		/* Remove KeyfactorAgents/ from the relPath */
		//TODO: Remove this if statement and replace with strcat(url, relPath);
		//      Once the platform changes to not send KeyfactorAgents/

		log_trace("%s::%s(%d) : Stripping KeyfactorAgents/ from %s", \
			__FILE__, __FUNCTION__, __LINE__, relPath);
		relPathStripped = util_strip_string(relPath, "KeyfactorAgents/");
		log_trace("%s::%s(%d) : New relPath = %s", \
			__FILE__, __FUNCTION__, __LINE__, relPathStripped);
		url = realloc( url, (strlen(url)+strlen(relPathStripped)+1) );
		strcat(url, relPathStripped);
		log_trace("%s::%s(%d) : url = %s",
			__FILE__, __FUNCTION__, __LINE__, url);
	}
	else {
		log_error("%s::%s(%d) : Unable to build url: Invalid arguments", \
			__FILE__, __FUNCTION__, __LINE__);
	}

	if ( relPathStripped ) {
		free(relPathStripped);
	}
	log_trace("%s::%s(%d) : url = %s", __FILE__, __FUNCTION__, __LINE__, url);
	return url;
} /* config_build_url */

/**
 * Release memory associated with the ConfigData element
 *
 * @param  - [Input] : config = a reference to a ConfigData element
 * @return none
 */
void ConfigData_free(struct ConfigData* config)
{
	if(config)
	{
		if(config->AgentId)	{
			free(config->AgentId);
			config->AgentId = NULL;
		}
		if(config->AgentName) {
			free(config->AgentName);
			config->AgentName = NULL;
		}
		if(config->ClientParameterPath) {
			free(config->ClientParameterPath);
			config->ClientParameterPath = NULL;
		}
		if(config->Hostname) {
			free(config->Hostname);
			config->Hostname = NULL;
		}
		if(config->Password) {
			free(config->Password);
			config->Password = NULL;
		}
		if(config->Username) {
			free(config->Username);
			config->Username = NULL;
		}
		if(config->VirtualDirectory) {
			free(config->VirtualDirectory);
			config->VirtualDirectory = NULL;
		}
		if(config->TrustStore) {
			free(config->TrustStore);
			config->TrustStore = NULL;
		}
		if(config->AgentCert) 	{
			free(config->AgentCert);
			config->AgentCert = NULL;
		}
		if(config->AgentKey) {
			free(config->AgentKey);
			config->AgentKey = NULL;
		}
		if(config->AgentKeyPassword) {
			free(config->AgentKeyPassword);
			config->AgentKeyPassword = NULL;
		}
		if(config->CSRKeyType) {
			free(config->CSRKeyType);
			config->CSRKeyType = NULL;
		}
		if(config->CSRSubject) {
			free(config->CSRSubject);
			config->CSRSubject = NULL;
		}
		if(config->SerialFile) {
			free(config->SerialFile);
			config->SerialFile = NULL;
		}
		if(config->LogFile) {
			free(config->LogFile);
			config->LogFile = NULL;
		}

		free(config);
	}
} /* ConfigData_free */