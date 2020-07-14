/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#ifndef CSS_SESSION_H
#define CSS_SESSION_H

struct SessionInfo
{
	char Token[GUID_SIZE];
	char AgentId[GUID_SIZE];
	time_t NextExecution;
	int UnreachableCount;
	int Interval;
};

int register_session(struct ConfigData* config, struct SessionInfo* session, struct ScheduledJob** pJobList, uint64_t agentVersion);

int heartbeat_session(struct ConfigData* config, struct SessionInfo* session, struct ScheduledJob** pJobList, uint64_t agentVersion);

#endif
