/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file config.h */
#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdbool.h>

#define CONFIG_LOCATION "config.json"
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
	bool   Serialize; /**< true = use a serialization file for CN */
	char*  SerialFile; /**< File with the serialization data */
	int    httpRetries; /**< # of times to retry a failed HTTP connection */
	int    retryInterval; /**< Interval (in seconds) between HTTP retries */
	char*  LogFile; /**< File where agent logs are stored. */
};

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
struct ConfigData* config_load();

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
char* config_to_json(struct ConfigData* config);

/**
 * Save the configuration structure to "config.json" on the file system
 *
 * @param  - [Input] config = a reference to a filled out ConfigData element
 * @return - success : true
 *           failure : false
 */
bool config_save(struct ConfigData* config);

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
	bool vdirFromConfig);

/**
 * Release memory associated with the ConfigData element
 *
 * @param  - [Input] : config = a reference to a ConfigData element
 * @returns none
 */
void ConfigData_free(struct ConfigData* config);

#endif /* __CONFIG_H__ */
