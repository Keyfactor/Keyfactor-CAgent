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
#ifndef CSS_DTO_H
#define CSS_DTO_H

#define _POSIX_C_SOURCE 200809L   // POSIX.1-2008

#include <stdbool.h>
#include <stdint.h>
#include "constants.h"


typedef struct {
	enum AgentApiResultStatus Status;
	struct 
	{
		int Code;
		char* Message;
		char* CodeString;
	} Error;
} AgentApiResult_t;

typedef struct {
	char* Key;
	char* Value;
} ClientParameter_t;

typedef struct {
	char* TenantId;
	char* ClientMachine;
	enum AgentPlatform AgentPlatform;
	char** Capabilities;
	int Capabilities_count;
	uint64_t AgentVersion;
	char* AgentId;
	ClientParameter_t** ClientParameters;
	int ClientParameters_count;
	char* CSR;
} SessionRegisterReq_t;

typedef struct {
	char* JobTypeId;
	char* JobId;
	char* ConfigurationEndpoint;
	char* CompletionEndpoint;
	char* Cron;
	char* Schedule;
	int Priority;
} SessionJob_t;

typedef struct {
	AgentApiResult_t Result;
	struct 
	{
		char* Token;
		char* AgentId;
		int HeartbeatInterval;
		SessionJob_t** Jobs;
		int Jobs_count;
		ClientParameter_t** ClientParameters;
		int ClientParameters_count;
		char* ClientMachine;
		char* Certificate;
	} Session;
} SessionRegisterResp_t;

typedef struct {
	char* SessionToken;
	char* JobId;
} CommonConfigReq_t;

typedef struct {
	char* SessionToken;
	char* JobId;
	enum JobCompleteStatus Status;
	uint64_t AuditId;
	char* Message;
} CommonCompleteReq_t;

typedef struct {
	AgentApiResult_t Result;
} CommonCompleteResp_t;

typedef struct {
	uint64_t AuditId;
	bool JobCancelled;
	AgentApiResult_t Result;
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
} ManagementConfigResp_t;

typedef struct {
	AgentApiResult_t Result;
	char* InventoryJob;
} ManagementCompleteResp_t;

typedef struct {
	char* Alias;
	bool PrivateKeyEntry;
	char** Thumbprints;
	int Thumbprints_count;
} InventoryCurrentItem_t;

typedef struct {
	char* InventoryEndpoint;
	uint64_t AuditId;
	bool JobCancelled;
	AgentApiResult_t Result;
	struct 
	{
		char* ClientMachine;
		char* StorePath;
		char* StorePassword;
		int Category;
		InventoryCurrentItem_t** Inventory;
		int Inventory_count;
	} Job;
} InventoryConfigResp_t;

typedef struct {
	char* Alias;
	bool PrivateKeyEntry;
	int ItemStatus;
	bool UseChainLevel;
	char** Certificates;
	int Certificates_count;
} InventoryUpdateItem_t;

typedef struct {
	int count;
	InventoryUpdateItem_t** items;
} InventoryUpdateList_t;

typedef struct {
	char* SessionToken;
	char* JobId;
	InventoryUpdateList_t Inventory;
} InventoryUpdateReq_t;

typedef struct {
	AgentApiResult_t Result;
} InventoryUpdateResp_t;

typedef struct {
	uint64_t AuditId;
	bool JobCancelled;
	AgentApiResult_t Result;
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
} EnrollmentConfigResp_t;

typedef struct {
	char* SessionToken;
	char* JobId;
	char* CSRText;
} EnrollmentEnrollReq_t;

typedef struct {
	AgentApiResult_t Result;
	char* Certificate;
} EnrollmentEnrollResp_t;

typedef struct {
	AgentApiResult_t Result;
	char* InventoryJob;
} EnrollmentCompleteResp_t;

typedef struct {
	int64_t AuditId;
	bool JobCancelled;
	AgentApiResult_t Result;
	int32_t MaxCharactersToReturn;
} FetchLogsConfigResp_t;

typedef struct {
  char* Log;
  char* SessionToken;
  char* JobId;
  enum JobCompleteStatus Status;
  uint64_t AuditId;
  char* Message;
} FetchLogsCompleteReq_t;

bool AgentApiResult_log(AgentApiResult_t result, char** pMessage, \
	enum AgentApiResultStatus* pStatus);

SessionRegisterReq_t* SessionRegisterReq_new(char* clientParamPath);

void SessionRegisterReq_free(SessionRegisterReq_t* req);

char* SessionRegisterReq_toJson(SessionRegisterReq_t* req);

void SessionRegisterResp_free(SessionRegisterResp_t* resp);

SessionRegisterResp_t* SessionRegisterResp_fromJson(char* jsonString);

void SessionRegisterResp_freeJobs(SessionRegisterResp_t*);

void SessionJob_free(SessionJob_t* job);

CommonConfigReq_t* CommonConfigReq_new();

void CommonConfigReq_free(CommonConfigReq_t* req);

char* CommonConfigReq_toJson(CommonConfigReq_t* req);

CommonCompleteReq_t* CommonCompleteReq_new();

void CommonCompleteReq_free(CommonCompleteReq_t* req);

char* CommonCompleteReq_toJson(CommonCompleteReq_t* req);

void CommonCompleteResp_free(CommonCompleteResp_t* resp);

CommonCompleteResp_t* CommonCompleteResp_fromJson(char* jsonString);

void ManagementConfigResp_free(ManagementConfigResp_t* resp);

ManagementConfigResp_t* ManagementConfigResp_fromJson(char* jsonString);

void ManagementCompleteResp_free(ManagementCompleteResp_t* resp);

ManagementCompleteResp_t* ManagementCompleteResp_fromJson(char* jsonString);

void InventoryConfigResp_free(InventoryConfigResp_t* resp);

InventoryConfigResp_t* InventoryConfigResp_fromJson(char* jsonString);

void InventoryUpdateReq_free(InventoryUpdateReq_t* req);

char* InventoryUpdateReq_toJson(InventoryUpdateReq_t* req);

void InventoryUpdateResp_free(InventoryUpdateResp_t* resp);

InventoryUpdateResp_t* InventoryUpdateResp_fromJson(char* jsonString);

void EnrollmentConfigResp_free(EnrollmentConfigResp_t* resp);

EnrollmentConfigResp_t* EnrollmentConfigResp_fromJson(char* jsonString);

void EnrollmentEnrollReq_free(EnrollmentEnrollReq_t* req);

char* EnrollmentEnrollReq_toJson(EnrollmentEnrollReq_t* req);

void EnrollmentEnrollResp_free(EnrollmentEnrollResp_t* resp);

EnrollmentEnrollResp_t* EnrollmentEnrollResp_fromJson(char* jsonString);

void EnrollmentCompleteResp_free(EnrollmentCompleteResp_t* resp);

EnrollmentCompleteResp_t* EnrollmentCompleteResp_fromJson(char* jsonString);

void FetchLogsConfigResp_free(FetchLogsConfigResp_t* req);

FetchLogsConfigResp_t* FetchLogsConfigResp_fromJson(char* jsonString);

void FetchLogsCompleteReq_free(FetchLogsCompleteReq_t* req);

char* FetchLogsCompleteReq_toJson(FetchLogsCompleteReq_t* req);

FetchLogsCompleteReq_t* FetchLogsCompleteReq_new();

bool SessionRegisterReq_addNewClientParameter(SessionRegisterReq_t* req, \
	const char* key, const char* value);

#endif
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
