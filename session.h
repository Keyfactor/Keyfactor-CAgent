/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file session.h */
#ifndef CSS_SESSION_H
#define CSS_SESSION_H

#include <time.h>
#include "constants.h"
#include "config.h"
#include "schedule.h"

struct SessionInfo
{
	char Token[GUID_SIZE];
	char AgentId[GUID_SIZE];
	time_t NextExecution;
	int UnreachableCount;
	int Interval;
};

enum CSRType
{
	AGENT,
	CGM
};

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
	struct ScheduledJob** pJobList, uint64_t agentVersion);

int heartbeat_session(struct ConfigData* config, struct SessionInfo* session, \
	struct ScheduledJob** pJobList, uint64_t agentVersion);

#endif
