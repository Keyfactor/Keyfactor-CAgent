/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file dto.h */
#ifndef CSS_DTO_H
#define CSS_DTO_H

#include <stdbool.h>
#include <stdint.h>
#include "constants.h"


struct AgentApiResult
{
	enum AgentApiResultStatus Status;
	struct 
	{
		int Code;
		char* Message;
		char* CodeString;
	} Error;
};

struct ClientParameter
{
	char* Key;
	char* Value;
};

struct SessionRegisterReq
{
	char* TenantId;
	char* ClientMachine;
	enum AgentPlatform AgentPlatform;
	char** Capabilities;
	int Capabilities_count;
	uint64_t AgentVersion;
	char* AgentId;
	struct ClientParameter** ClientParameters;
	int ClientParameters_count;
	char* CSR;
};

struct SessionJob
{
	char* JobTypeId;
	char* JobId;
	char* ConfigurationEndpoint;
	char* CompletionEndpoint;
	char* Cron;
	char* Schedule;
	int Priority;
};

struct SessionRegisterResp
{
	struct AgentApiResult Result;
	struct 
	{
		char* Token;
		char* AgentId;
		int HeartbeatInterval;
		struct SessionJob** Jobs;
		int Jobs_count;
		struct ClientParameter** ClientParameters;
		int ClientParameters_count;
		char* ClientMachine;
		char* Certificate;
	} Session;
};

struct SessionHeartbeatReq
{
	char* SessionToken;
	char* TenantId;
	char* ClientMachine;
	enum AgentPlatform AgentPlatform;
};

struct SessionHeartbeatResp
{
	struct AgentApiResult Result;
	int HeartbeatInterval;
	bool SessionValid;
};

struct CommonConfigReq
{
	char* SessionToken;
	char* JobId;
};

struct CommonCompleteReq
{
	char* SessionToken;
	char* JobId;
	enum JobCompleteStatus Status;
	uint64_t AuditId;
	char* Message;
};

struct CommonCompleteResp
{
	struct AgentApiResult Result;
};

struct ManagementConfigResp
{
	uint64_t AuditId;
	bool JobCancelled;
	struct AgentApiResult Result;
	struct 
	{
		enum OperationType OperationType;
		char* ClientMachine;
		char* StorePath;
		char* StorePassword;
		int StoreType;
		int Category;
		char* Alias;
		bool PrivateKeyEntry;
		char* EntryPassword;
		char* Thumbprint;
		char* EntryContents;
		char* PfxPassword;
		bool Overwrite;
		char* PrivateKeyPath;
	} Job;
};

struct ManagementCompleteResp
{
	struct AgentApiResult Result;
	char* InventoryJob;
};

struct InventoryCurrentItem
{
	char* Alias;
	bool PrivateKeyEntry;
	char** Thumbprints;
	int Thumbprints_count;
};

struct InventoryConfigResp
{
	char* InventoryEndpoint;
	uint64_t AuditId;
	bool JobCancelled;
	struct AgentApiResult Result;
	struct 
	{
		char* ClientMachine;
		char* StorePath;
		char* StorePassword;
		int Category;
		struct InventoryCurrentItem** Inventory;
		int Inventory_count;
	} Job;
};

struct InventoryUpdateItem
{
	char* Alias;
	bool PrivateKeyEntry;
	int ItemStatus;
	bool UseChainLevel;
	char** Certificates;
	int Certificates_count;
};

struct InventoryUpdateList
{
	int count;
	struct InventoryUpdateItem** items;
};

struct InventoryUpdateReq
{
	char* SessionToken;
	char* JobId;
	struct InventoryUpdateList Inventory;
};

struct InventoryUpdateResp
{
	struct AgentApiResult Result;
};

struct EnrollmentConfigResp
{
	uint64_t AuditId;
	bool JobCancelled;
	struct AgentApiResult Result;
	char* Entropy;
	int KeySize;
	char* KeyType;
	char* Subject;
	char* ClientMachine;
	char* StorePath;
	char* StorePassword;
	char* EnrollEndpoint;
	char* PrivateKeyPath;
	char* Properties;
};

struct EnrollmentEnrollReq
{
	char* SessionToken;
	char* JobId;
	char* CSRText;
};

struct EnrollmentEnrollResp
{
	struct AgentApiResult Result;
	char* Certificate;
};

struct EnrollmentCompleteResp
{
	struct AgentApiResult Result;
	char* InventoryJob;
};

struct FetchLogsConfigResp
{
	int64_t AuditId;
	bool JobCancelled;
	struct AgentApiResult Result;
	int32_t MaxCharactersToReturn;
};

struct FetchLogsCompleteReq
{
	char* Log;
	
	char* SessionToken;
	char* JobId;
	enum JobCompleteStatus Status;
	uint64_t AuditId;
	char* Message;
};

bool AgentApiResult_log(struct AgentApiResult result, char** pMessage, \
	enum AgentApiResultStatus* pStatus);

struct SessionRegisterReq* SessionRegisterReq_new(char* clientParamPath);

void SessionRegisterReq_free(struct SessionRegisterReq* req);

char* SessionRegisterReq_toJson(struct SessionRegisterReq* req);

void SessionRegisterResp_free(struct SessionRegisterResp* resp);

struct SessionRegisterResp* SessionRegisterResp_fromJson(char* jsonString);

void SessionJob_free(struct SessionJob* job);

struct SessionHeartbeatReq* SessionHeartbeatReq_new();

void SessionHeartbeatReq_free(struct SessionHeartbeatReq* req);

char* SessionHeartbeatReq_toJson(struct SessionHeartbeatReq* req);

void SessionHeartbeatResp_free(struct SessionHeartbeatResp* resp);

struct SessionHeartbeatResp* SessionHeartbeatResp_fromJson(char* jsonString);

struct CommonConfigReq* CommonConfigReq_new();

void CommonConfigReq_free(struct CommonConfigReq* req);

char* CommonConfigReq_toJson(struct CommonConfigReq* req);

struct CommonCompleteReq* CommonCompleteReq_new();

void CommonCompleteReq_free(struct CommonCompleteReq* req);

char* CommonCompleteReq_toJson(struct CommonCompleteReq* req);

void CommonCompleteResp_free(struct CommonCompleteResp* resp);

struct CommonCompleteResp* CommonCompleteResp_fromJson(char* jsonString);

void ManagementConfigResp_free(struct ManagementConfigResp* resp);

struct ManagementConfigResp* ManagementConfigResp_fromJson(char* jsonString);

void ManagementCompleteResp_free(struct ManagementCompleteResp* resp);

struct ManagementCompleteResp* ManagementCompleteResp_fromJson(char* jsonString);

void InventoryConfigResp_free(struct InventoryConfigResp* resp);

struct InventoryConfigResp* InventoryConfigResp_fromJson(char* jsonString);

void InventoryUpdateReq_free(struct InventoryUpdateReq* req);

char* InventoryUpdateReq_toJson(struct InventoryUpdateReq* req);

void InventoryUpdateResp_free(struct InventoryUpdateResp* resp);

struct InventoryUpdateResp* InventoryUpdateResp_fromJson(char* jsonString);

void EnrollmentConfigResp_free(struct EnrollmentConfigResp* resp);

struct EnrollmentConfigResp* EnrollmentConfigResp_fromJson(char* jsonString);

void EnrollmentEnrollReq_free(struct EnrollmentEnrollReq* req);

char* EnrollmentEnrollReq_toJson(struct EnrollmentEnrollReq* req);

void EnrollmentEnrollResp_free(struct EnrollmentEnrollResp* resp);

struct EnrollmentEnrollResp* EnrollmentEnrollResp_fromJson(char* jsonString);

void EnrollmentCompleteResp_free(struct EnrollmentCompleteResp* resp);

struct EnrollmentCompleteResp* EnrollmentCompleteResp_fromJson(char* jsonString);

void FetchLogsConfigResp_free(struct FetchLogsConfigResp* req);

struct FetchLogsConfigResp* FetchLogsConfigResp_fromJson(char* jsonString);

void FetchLogsCompleteReq_free(struct FetchLogsCompleteReq* req);

char* FetchLogsCompleteReq_toJson(struct FetchLogsCompleteReq* req);

struct FetchLogsCompleteReq* FetchLogsCompleteReq_new();

bool SessionRegisterReq_addNewClientParameter(struct SessionRegisterReq* req, \
	const char* key, const char* value);

#endif
