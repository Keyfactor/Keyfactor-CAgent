/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "config.h"
#include "logging.h"
#include "lib/json.h"

#define MODULE "config-"
#define CONFIG_FILE_LEN 4096 // Config file should never be this long

/***************************************************************************//**
	print the configuration parameters pulled from config.json
	@param a pointer to the configuration data
	@returns none
 ******************************************************************************/
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
	printf("          ClientCert = %s\n", config->ClientCert);
	printf("          ClientKey = %s\n", config->ClientKey);
	printf("          ClientKeyPassword = %s\n", config->ClientKeyPassword);
	printf("          UseSsl = %s\n", config->UseSsl ? "true" : "false");
	printf("          CSRKeyType = %s\n", config->CSRKeyType);
	printf("          CSRKeySize = %d\n", config->CSRKeySize);
	printf("          CSRSubject = %s\n", config->CSRSubject);
	printf("          EnrollOnStartup = %s\n",
									config->EnrollOnStartup ? "true" : "false");
	printf("          AutoGenerateId = %s\n",
									config->AutoGenerateId ? "true" : "false");
	printf("          Serialize = %s\n", config->Serialize ? "true" : "false");
	printf("          SerialFile = %s\n", config->SerialFile);
	printf("\n\n");
	return;
} // print_config

/***************************************************************************//**
 * Load data from the configuration file into the configuration data structure
 * @param none
 * @returns a reference to a filled out ConfigData element
 ******************************************************************************/
struct ConfigData* config_load()
{
	#undef FUNCTION
	#define FUNCTION "config_load-"
	struct ConfigData* config = NULL;

	FILE* fp = fopen(CONFIG_LOCATION, "r");
	if(fp)
	{
		char buf[CONFIG_FILE_LEN]; 
		size_t len = fread(buf, 1, CONFIG_FILE_LEN-1, fp);
		buf[len++] = '\0';

		JsonNode* jsonRoot = json_decode(buf);
		if(jsonRoot)
		{
			config = calloc(1, sizeof(struct ConfigData));
			if ( NULL == config )
			{
				log_error("%s%sOut of memory! ",MODULE,FUNCTION);
				return NULL;
			}

			config->AgentId = json_get_member_string(jsonRoot, "AgentId");
			config->AgentName = json_get_member_string(jsonRoot, "AgentName");
			config->ClientParameterPath = 
						json_get_member_string(jsonRoot, "ClientParameterPath");
			config->Hostname = json_get_member_string(jsonRoot, "Hostname");
			config->Password = json_get_member_string(jsonRoot, "Password");
			config->Username = json_get_member_string(jsonRoot, "Username");
			config->VirtualDirectory = 
						   json_get_member_string(jsonRoot, "VirtualDirectory");
			config->TrustStore = json_get_member_string(jsonRoot, "TrustStore");
			config->ClientCert = json_get_member_string(jsonRoot, "ClientCert");
			config->ClientKey = json_get_member_string(jsonRoot, "ClientKey");
			config->ClientKeyPassword = 
						json_get_member_string(jsonRoot, "ClientKeyPassword");
			config->UseSsl = json_get_member_bool(jsonRoot, "UseSsl", true);
			config->CSRKeyType = json_get_member_string(jsonRoot, "CSRKeyType");
			config->CSRKeySize =json_get_member_number(jsonRoot,"CSRKeySize",0);
			config->CSRSubject = json_get_member_string(jsonRoot, "CSRSubject");
			config->EnrollOnStartup = 
					json_get_member_bool(jsonRoot, "EnrollOnStartup", false);
			config->AutoGenerateId =
					json_get_member_bool(jsonRoot, "AutoGenerateId", false);
			config->Serialize = 
					json_get_member_bool(jsonRoot, "Serialize", false);
			config->SerialFile = json_get_member_string(jsonRoot, "SerialFile");

			json_delete(jsonRoot);

			if ( is_log_verbose() )
			{
				log_verbose("%s%sConfig parameters follow:",MODULE,FUNCTION);
				print_config( config );
			}
		}
		else
		{
			log_error("%s%s-Contents of %s are not valid JSON", 
						MODULE, FUNCTION, CONFIG_LOCATION);
		}

		fclose(fp);
	}
	else
	{
		int err = errno;
		log_error("%s%s-Unable to open config file %s: %s", 
					MODULE, FUNCTION, CONFIG_LOCATION, strerror(err));
	}

	return config;
} //config_load

/***************************************************************************//**
 * Save data from the configuration data structure into the configuration file
 * @param a reference to a filled out ConfigData element
 * @returns none
 ******************************************************************************/
void config_save(struct ConfigData* config)
{
	#undef FUNCTION
	#define FUNCTION "config_save-"
	JsonNode* jsonRoot = json_mkobject();
	if(config->AgentId)
	{
		json_append_member(jsonRoot, "AgentId", 
							json_mkstring(config->AgentId));
	}
	if(config->AgentName)
	{
		json_append_member(jsonRoot, "AgentName", 
							json_mkstring(config->AgentName));
	}
	if(config->ClientParameterPath)
	{
		json_append_member(jsonRoot, "ClientParameterPath", 
							json_mkstring(config->ClientParameterPath));
	}
	if(config->Hostname)
	{
		json_append_member(jsonRoot, "Hostname", 
							json_mkstring(config->Hostname));
	}
	if(config->Password)
	{
		json_append_member(jsonRoot, "Password", 
							json_mkstring(config->Password));
	}
	if(config->Username)
	{
		json_append_member(jsonRoot, "Username", 
							json_mkstring(config->Username));
	}
	if(config->VirtualDirectory)
	{
		json_append_member(jsonRoot, "VirtualDirectory", 
							json_mkstring(config->VirtualDirectory));
	}
	if(config->TrustStore)
	{
		json_append_member(jsonRoot, "TrustStore", 
							json_mkstring(config->TrustStore));
	}
	if(config->ClientCert)
	{
		json_append_member(jsonRoot, "ClientCert", 
							json_mkstring(config->ClientCert));
	}
	if(config->ClientKey)
	{
		json_append_member(jsonRoot, "ClientKey", 
							json_mkstring(config->ClientKey));
	}
	if(config->ClientKeyPassword)
	{
		json_append_member(jsonRoot, "ClientKeyPassword", 
							json_mkstring(config->ClientKeyPassword));
	}
	if(config->CSRKeyType)
	{
		json_append_member(jsonRoot, "CSRKeyType", 
							json_mkstring(config->CSRKeyType));
	}
	if(config->CSRKeySize)
	{
		json_append_member(jsonRoot, "CSRKeySize", 
							json_mknumber(config->CSRKeySize));
	}
	if(config->CSRSubject)
	{
		json_append_member(jsonRoot, "CSRSubject", 
							json_mkstring(config->CSRSubject));
	}
	json_append_member(jsonRoot, "EnrollOnStartup", 
							json_mkbool(config->EnrollOnStartup));
	json_append_member(jsonRoot, "UseSsl", 
							json_mkbool(config->UseSsl));
	json_append_member(jsonRoot, "AutoGenerateId",
							json_mkbool(config->AutoGenerateId));
	json_append_member(jsonRoot, "Serialize", 
							json_mkbool(config->Serialize));
	if(config->SerialFile)
	{
		json_append_member(jsonRoot, "SerialFile", 
							json_mkstring(config->SerialFile));
	}

	FILE* fp = fopen(CONFIG_LOCATION, "w");
	if(fp)
	{
		char* confString = json_stringify(jsonRoot, "\t");

		fwrite(confString, 1, strlen(confString), fp);

		free(confString);
		fclose(fp);
	}
	else
	{
		int err = errno;
		log_error("%s%s-Unable to open config file %s: %s", 
					MODULE, FUNCTION, CONFIG_LOCATION, strerror(err));
	}

	json_delete(jsonRoot);
} // config_save


char* config_build_url(struct ConfigData* config, const char* relPath, bool vdirFromConfig)
{
	#undef FUNCTION
	#define FUNCTION "config_build_url-"
	char* url = NULL;

	if(config && relPath)
	{
		url = malloc(250);
		strcpy(url, (config->UseSsl ? "https://" : "http://"));
		strcat(url, config->Hostname);

		if(vdirFromConfig)
		{
			strcat(url, "/");
			strcat(url, config->VirtualDirectory);
		}

		if(strcspn(relPath, "/") != 0)
		{
			strcat(url, "/");
		}

		/* Remove KeyfactorAgents/ from the relPath */
		//TODO: Remove this if statement and replace with strcat(url, relPath);
		//      Once the platform changes to not send KeyfactorAgents/
		if ( false == config->EnrollOnStartup )
		{
			log_trace("%s%s-Stripping KeyfactorAgents/ from %s", MODULE, FUNCTION, relPath);
			util_strip_string(relPath, "KeyfactorAgents/");
			log_trace("%s%s-New relPath = %s",MODULE, FUNCTION, relPath);
		}
		strcat(url, relPath);
	}
	else
	{
		log_error("%s%s-Unable to build url: Invalid arguments", MODULE, FUNCTION);
	}

	return url;
}

/***************************************************************************//**
 * Release memory associated with the ConfigData element
 * @param a reference to a ConfigData element
 * @returns none
 ******************************************************************************/
void ConfigData_free(struct ConfigData* config)
{
	#undef FUNCTION
	#define FUNCTION ConfigData_free
	if(config)
	{
		if(config->AgentId)
		{
			free(config->AgentId);
			config->AgentId = NULL;
		}
		if(config->AgentName)
		{
			free(config->AgentName);
			config->AgentName = NULL;
		}
		if(config->ClientParameterPath)
		{
			free(config->ClientParameterPath);
			config->ClientParameterPath = NULL;
		}
		if(config->Hostname)
		{
			free(config->Hostname);
			config->Hostname = NULL;
		}
		if(config->Password)
		{
			free(config->Password);
			config->Password = NULL;
		}
		if(config->Username)
		{
			free(config->Username);
			config->Username = NULL;
		}
		if(config->VirtualDirectory)
		{
			free(config->VirtualDirectory);
			config->VirtualDirectory = NULL;
		}
		if(config->TrustStore)
		{
			free(config->TrustStore);
			config->TrustStore = NULL;
		}
		if(config->ClientCert)
		{
			free(config->ClientCert);
			config->ClientCert = NULL;
		}
		if(config->ClientKey)
		{
			free(config->ClientKey);
			config->ClientKey = NULL;
		}
		if(config->ClientKeyPassword)
		{
			free(config->ClientKeyPassword);
			config->ClientKeyPassword = NULL;
		}
		if(config->CSRKeyType)
		{
			free(config->CSRKeyType);
			config->CSRKeyType = NULL;
		}
		if(config->CSRSubject)
		{
			free(config->CSRSubject);
			config->CSRSubject = NULL;
		}
		if(config->SerialFile)
		{
			free(config->SerialFile);
			config->SerialFile = NULL;
		}

		free(config);
	}
} // ConfigData_free
