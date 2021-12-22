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
#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdbool.h>
#include <stddef.h>

#define MAX_CONFIG_FILE_LEN 4096 /* Config file should never be this long */
#define DATE_TIME_LEN 14 /* YYYYMMDDHHMMSS */

struct ConfigData
{
	char*  Hostname; /**< The hostname of the Keyfactor Platform */
	char*  VirtualDirectory; /**< The proxy used by the Platform */
	bool   UseSsl;           /**< true = https, false = http */
	char*  AgentId;          /**< Set by the platform during registration */
	char*  AgentName;        /**< Set by the agent's config.json file */
	char*  ClientParameterPath; /**< Any Agent Registration Parameters */
	char*  Username;        /**< DOMAIN\username for the Keyfactor Platform */
	char*  Password;        /**< Password for the Keyfactor Platform */
	char*  TrustStore;      /**< File with the certificates the agent trusts */
	char*  AgentCert;      /**< File with the Agent's cert */
	char*  AgentKey;       /**< File with the Agent's private key */
	char*  AgentKeyPassword; /**< Password to decrypt the Agent's priv key */
	char*  CSRKeyType;     /**< The key type to use for the Agent (ECC/RSA) */
	int    CSRKeySize;     /**<  The key size for the Agent */
	char*  CSRSubject;     /**< Subject for the agent CSR. Must be valid X509 */
	bool   EnrollOnStartup; /**< Persistent variable. True until agent enrolls*/
	bool   UseBootstrapCert; /**< True if agent uses bootstrap certs to enroll*/
	char*  BootstrapCert; /**< Path & filename of bootstrap cert */
	char*  BootstrapKey; /**< Path & filename of the bootstrap key */
	char*  BootstrapKeyPassword; /**< String holding password for key */
	bool   Serialize; /**< true = use a serialization file for CN */
	char*  SerialFile; /**< File with the serialization data */
	int    httpRetries; /**< # of times to retry a failed HTTP connection */
	int    retryInterval; /**< Interval (in seconds) between HTTP retries */
	char*  LogFile; /**< File where agent logs are stored. */
    size_t LogFileIndex; /**< Last byte written to the log file */
};

/******************************************************************************/
/***************************** GLOBAL VARIABLES *******************************/
/******************************************************************************/
extern struct ConfigData* ConfigData;
extern bool config_loaded;
extern char* config_location;
extern bool use_host_as_agent_name;

/******************************************************************************/
/***************************** GLOBAL FUNCTIONS *******************************/
/******************************************************************************/

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
struct ConfigData* config_decode(const char* buf);

/**
 * Load data from the configuration file into the configuration data structure
 * The configuration file "config.json" must be in the same directory as
 * the agent.
 *
 * NOTE: This configuration structure needs to be freed by calling 
 *       ConfigData_free(ConfigData*) before ending the process thread.
 *
 * @param  - none
 * @return - a reference to a filled out ConfigData element
 */
struct ConfigData* config_load( void );

/**
 * Convert the configuration data structure into a json string. Call
 * this function directly if you are not using the config_save() function
 * to save the configuration to the file config.json file directly.
 * 
 * For example:
 * You are using a securely encoded file & need to encode it before saving
 * the file to disk.  
 *
 * @return - A json encoded string
 */
char* config_to_json( void );

/**
 * Save the configuration structure to "config.json" on the file system
 *
 * @param  - [Input] config = a reference to a filled out ConfigData element
 * @return - success : true
 *           failure : false
 */
bool config_save( void );

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
char* config_build_url(const char* relPath, bool vdirFromConfig);

/**
 * Sanity check on the configuration file to check for errors before launching
 * Should run after the log files are up and running to log errors to disk.
 *
 * @param  - none, operates on the global ConfigData variable
 * @return - success : true
 *           failure : false
 */
bool validate_configuration( void );

/**
 * Release memory associated with the ConfigData element
 *
 * @returns none
 */
void ConfigData_free( void );

#endif /* __CONFIG_H__ */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/