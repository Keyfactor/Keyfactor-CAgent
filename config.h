/*
* Copyright 2018, Certified Security Solutions
* All Rights Reserved.
* This is UNPUBLISHED PROPRIETARY SOURCE CODE of Certified Security Solutions;
* the contents of this file may not be disclosed to third parties, copied
* or duplicated in any form, in whole or in part, without the prior
* written permission of Certified Security Solutions.
*/


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
};

struct ConfigData* config_load();

void config_save(struct ConfigData* config);

char* config_build_url(struct ConfigData* config, const char* relPath, bool vdirFromConfig);

void ConfigData_free(struct ConfigData* config);

#endif /* CONFIG_H_ */
