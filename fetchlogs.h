/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file fetchlogs.h */
#ifndef KEYFACTOR_FETCHLOGS_H_
#define KEYFACTOR_FETCHLOGS_H_

#include "dto.h"
#include "config.h"

int cms_job_fetchLogs(struct SessionJob* jobInfo, struct ConfigData* config, \
					  char* sessionToken);

#endif /* KEYFACTOR_FETCHLOGS_H_ */