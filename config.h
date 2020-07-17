/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#ifndef CONFIG_H_
#define CONFIG_H_

#include <stdbool.h>

#define CONFIG_LOCATION "config.json"

struct ConfigData
{
	char* Hostname;
	char* VirtualDirectory;
	bool  UseSsl;
	char* AgentId;
	char* AgentName;
	char* ClientParameterPath;
	char* Username;
	char* Password;
	char* TrustStore;
	char* ClientCert;
	char* ClientKey;
	char* ClientKeyPassword;
	char* CSRKeyType;
	char* CSRSubject;
	int   CSRKeySize;
	bool  EnrollOnStartup;
	bool  AutoGenerateId;
	bool  Serialize;
	char* SerialFile;
	char* LogFile;
};

struct ConfigData* config_load();

void config_save(struct ConfigData* config);

char* config_build_url(struct ConfigData* config, const char* relPath, bool vdirFromConfig);

void ConfigData_free(struct ConfigData* config);

#endif /* CONFIG_H_ */
