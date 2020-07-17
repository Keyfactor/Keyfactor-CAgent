/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#ifndef CSS_CONSTANTS_H
#define CSS_CONSTANTS_H

#define CAP_PEM_INVENTORY "a809ce1f-1eea-4738-a38e-15708c89c981"
#define CAP_PEM_MANAGEMENT "1d411b36-ae72-433f-9f3f-8593e836a1af"
#define CAP_PEM_ENROLL "AA015D10-CFFC-41F7-A9A4-C9615F6F3BDF"
#define FETCH_LOGS "0D8CF0C8-56CA-4B8A-B16A-C062018E170D"

#define EMPTY_SESSION "c0ffee00-feed-f00d-cafe-c0ffeec0ffee"

// 32 hex chars + 4 dashes + 1 NULL-terminator
#define GUID_SIZE 37

enum InventoryStatus
{
	INV_STAT_ADD = 1,
	INV_STAT_MOD = 2,
	INV_STAT_REM = 3,
	INV_STAT_UNCH = 4
};

enum AgentPlatform
{
	PLAT_UNK = 0,
	PLAT_NET = 1,
	PLAT_JAVA = 2,
	PLAT_MAC = 3,
	PLAT_ANDROID = 4,
	PLAT_NATIVE = 5
};

enum AgentApiResultStatus
{
	STAT_UNK = 0,
	STAT_SUCCESS = 1,
	STAT_WARN = 2,
	STAT_ERR = 3
};

enum JobCompleteStatus
{
	JOB_COMP_UNK = 0,
	JOB_COMP_PROC = 1,
	JOB_COMP_SUCCESS = 2,
	JOB_COMP_WARN = 3,
	JOB_COMP_ERR = 4
};

enum OperationType
{
	OP_UNK = 0,
	OP_INV = 1,
	OP_ADD = 2,
	OP_REM = 3,
	OP_CREATE = 4,
	OP_CREATE_ADD = 5
};

#endif
