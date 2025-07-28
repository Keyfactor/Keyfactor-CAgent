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

#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

/* These are the GUIDs of the capabilities supported by the Agent */
#define CAP_PEM_INVENTORY "a809ce1f-1eea-4738-a38e-15708c89c981"
#define CAP_PEM_MANAGEMENT "1d411b36-ae72-433f-9f3f-8593e836a1af"
#define CAP_PEM_REENROLLMENT "aa015d10-cffc-41f7-a9a4-c9615f6f3bdf"
#define CAP_FETCH_LOGS "0D8CF0C8-56CA-4B8A-B16A-C062018E170D"

/* KF v9 adds in text Capabilities - they are defined in agent.c */
extern const char* cap_pem_inventory;
extern const char* cap_pem_management;
extern const char* cap_pem_reenrollment;
extern const char* cap_fetch_logs;

/* The following capabilities are not implemented in the C-Agent */
#define CAP_AWS_INVENTORY "afb8c78d-1436-4c93-a8e7-0218c2cb6955"
#define CAP_AWS_MANAGEMENT "56c1e4f9-366c-44b3-8cae-1b8f39e2026c"
#define CAP_F5_INVENTORY "9b04e8de-e2ce-4a50-bd3f-31037d3ee751"
#define CAP_F5_MANAGEMENT "e9a34338-c99f-46da-94d2-4f97dc6943af"
#define CAP_FTP_INVENTORY "76f99194-c129-4954-b76e-11c80816643e"
#define CAP_FTP_MANAGEMENT "4ae72d54-7f91-4359-9da5-e1f633031070"
#define CAP_IIS_INVENTORY "5b9cf048-e95f-4331-a510-0cdfabac1703"
#define CAP_IIS_MANAGEMENT "ce2325e3-801c-4576-9b0a-5fdcaf66aa88"
#define CAP_IIS_REENROLLMENT "b80019d6-df3d-4a8c-9e60-1977b806f545"
#define CAP_JKS_DISCOVERY "74d9f7c5-b2ac-4f21-a72b-29b5adc90651"
#define CAP_JKS_INVENTORY "67b63010-d738-47c3-87a2-9f289466c881"
#define CAP_JKS_MANAGEMENT "b614f9e2-c56b-421c-b548-03d42eb32f8a"
#define CAP_JKS_REENROLLMENT "48743e90-108e-4dc3-b81c-7fb830215d1f"
#define CAP_NETSCALER_INVENTORY "78ff1c19-893f-4e5e-90a5-0459f1823778"
#define CAP_NETSCALER_MANAGEMENT "b7c94ad1-8a33-45ea-98b3-d77ca14e7830"
#define CAP_PEM_DISCOVERY "e98151de-53ad-4b99-b52a-f37118ec0c5c"

#define EMPTY_SESSION "c0ffee00-feed-f00d-cafe-c0ffeec0ffee"

/* 32 hex chars + 4 dashes + 1 NULL-terminator */
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

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/