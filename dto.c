/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include "dto.h"
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include "lib/json.h"
#include "logging.h"
#include <string.h>
#include <stdbool.h>

#define MODULE "dto-"

static void AgentApiResult_free(struct AgentApiResult result)
{
	#undef FUNCTION
	#define FUNCTION "AgentApiResult_free-"
	if(result.Error.Message)
	{
		free(result.Error.Message);
		result.Error.Message = NULL;
	}
	if(result.Error.CodeString)
	{
		free(result.Error.CodeString);
		result.Error.CodeString = NULL;
	}
}

static struct AgentApiResult AgentApiResult_fromJsonNode(JsonNode* jsonResult)
{
	#undef FUNCTION
	#define FUNCTION "AgentApiResult_fromJsonNode-"
	struct AgentApiResult result;

	if(jsonResult)
	{
		result.Status = json_get_member_number(jsonResult, "Status", 0);

		JsonNode* jsonError = json_find_member(jsonResult, "Error");
		result.Error.Code = json_get_member_number(jsonError, "Code", 0);
		result.Error.CodeString = json_get_member_string(jsonError, "CodeString");
		result.Error.Message = json_get_member_string(jsonError, "Message");
	}

	return result;
}

bool AgentApiResult_log(struct AgentApiResult result, char** pMessage, enum AgentApiResultStatus* pStatus)
{
	#undef FUNCTION
	#define FUNCTION "AgentApiResult_log-"
	if(pStatus && *pStatus < result.Status)
	{
		*pStatus = result.Status;
	}

	if(result.Status == STAT_ERR || result.Status == STAT_WARN)
	{
		int messageLen = 20;
		char* intro = result.Status == STAT_ERR ? "Error" : "Warning";
		if(result.Error.Message && result.Error.CodeString)
		{
			messageLen = 20 + strlen(result.Error.Message) + strlen(result.Error.CodeString);
			
		}
		else if(result.Error.Message)
		{
			messageLen = 20 + strlen(result.Error.Message);
		}
		
		
		char buf[messageLen];
		sprintf(buf, "%s: %s (%s)\n", intro, result.Error.Message, result.Error.CodeString);
		log_error("%s%s-%s", MODULE, FUNCTION, buf);

		if(pMessage)
		{
			*pMessage = realloc(*pMessage, strlen(*pMessage) + messageLen);
			strcat(*pMessage, buf);
		}
	}

	return result.Status != STAT_ERR;
}

static struct ClientParameter* ClientParameter_new(const char* key, const char* value)
{
	#undef FUNCTION
	#define FUNCTION "ClientParameter_new-"
	struct ClientParameter* cp = calloc(1, sizeof(struct ClientParameter));
	cp->Key = strdup(key);
	cp->Value = strdup(value);

	return cp;
}

static void ClientParameter_free(struct ClientParameter* cliParam)
{
	#undef FUNCTION
	#define FUNCTION "ClientParameter_free-"
	if(cliParam)
	{
		if(cliParam->Key)
		{
			free(cliParam->Key);
			cliParam->Key = NULL;
		}
		if(cliParam->Value)
		{
			free(cliParam->Value);
			cliParam->Value = NULL;
		}
		free(cliParam);
	}
}

struct SessionRegisterReq* SessionRegisterReq_new(char* clientParamPath)
{
	#undef FUNCTION
	#define FUNCTION "SessionHeartbeatReq_new-"
	struct SessionRegisterReq* req = calloc(1, sizeof(struct SessionRegisterReq));

	req->Capabilities_count = 0;

	req->TenantId = strdup("00000000-0000-0000-0000-000000000000");

	req->ClientParameters_count = 0;

	if(clientParamPath)
	{
		FILE* fp = fopen(clientParamPath, "r");
		if(fp)
		{
			char buf[4096]; // Client parameter file should never be anywhere near this long
			size_t len = fread(buf, 1, 4095, fp);
			buf[len++] = '\0';

			JsonNode* jsonRoot = json_decode(buf);
			if(jsonRoot && jsonRoot->tag == JSON_OBJECT)
			{
				JsonNode* curNode;
				int nodeCount = 0;
				json_foreach(curNode, jsonRoot) // Loop first to get count
				{
					if(curNode->tag == JSON_STRING){ nodeCount++;}
				}

				req->ClientParameters = calloc(nodeCount, sizeof(struct ClientParameter*));
				req->ClientParameters_count = nodeCount;

				nodeCount = 0;
				json_foreach(curNode, jsonRoot)
				{
					if(curNode->tag == JSON_STRING && curNode->key && curNode->string_)
					{
						req->ClientParameters[nodeCount++] = ClientParameter_new(curNode->key, curNode->string_);
					}
				}

				json_delete(jsonRoot);
			}
			else
			{
				log_error("dto-SessionRegisterReq_new%s%sContents of %s are not valid JSON", MODULE, FUNCTION, clientParamPath);
			}
		}
		else
		{
			int err = errno;
			log_error("%s%sUnable to open client parameter file %s: %s", MODULE, FUNCTION, clientParamPath, strerror(err));
		}
	}

	return req;
}

void SessionRegisterReq_free(struct SessionRegisterReq* req)
{
	#undef FUNCTION
	#define FUNCTION "SessionRegisterReq_free-"
	if(req)
	{
		if(req->TenantId)
		{
			free(req->TenantId);
			req->TenantId = NULL;
		}
		if(req->ClientMachine)
		{
			free(req->ClientMachine);
			req->ClientMachine = NULL;
		}
		if(req->CSR)
		{
			free(req->CSR);
			req->CSR = NULL;
		}
		if(req->AgentId)
		{
			free(req->AgentId);
			req->AgentId = NULL;
		}
		
		if(req->ClientParameters)
		{
			for(int i = 0; i < req->ClientParameters_count; ++i)
			{
				ClientParameter_free(req->ClientParameters[i]);
				req->ClientParameters[i] = NULL;
			}
			free(req->ClientParameters);
			req->ClientParameters = NULL;
		}
		if(req->Capabilities)
		{
			for(int i = 0; i < req->Capabilities_count; ++i)
			{
				free(req->Capabilities[i]);
				req->Capabilities[i] = NULL;
			}
			free(req->Capabilities);
			req->Capabilities = NULL;
		}
		free(req);
	}
}

char* SessionRegisterReq_toJson(struct SessionRegisterReq* req)
{
	#undef FUNCTION
	#define FUNCTION "SessionRegisterReq_toJson-"
	char* jsonString = NULL;

	if(req)
	{
		JsonNode* jsonRoot = json_mkobject();
		json_append_member(jsonRoot, "AgentPlatform", json_mknumber(req->AgentPlatform));
		json_append_member(jsonRoot, "AgentVersion", json_mknumber(req->AgentVersion));

		if(req->TenantId)
		{
			json_append_member(jsonRoot, "TenantId", json_mkstring(req->TenantId));
		}
		else
		{
			json_append_member(jsonRoot, "TenantId", json_mknull());
		}
		if(req->ClientMachine)
		{
			json_append_member(jsonRoot, "ClientMachine", json_mkstring(req->ClientMachine));
		}
		else
		{
			json_append_member(jsonRoot, "ClientMachine", json_mknull());
		}
		if(req->CSR)
		{
			json_append_member(jsonRoot, "CSR", json_mkstring(req->CSR));
		}
		else
		{
			json_append_member(jsonRoot, "CSR", json_mknull());
		}
		if(req->AgentId)
		{
			json_append_member(jsonRoot, "AgentId", json_mkstring(req->AgentId));
		}
		else
		{
			json_append_member(jsonRoot, "AgentId", json_mknull());
		}

		JsonNode* jsonCaps = json_mkarray();
		if(req->Capabilities)
		{
			for(int i = 0; i < req->Capabilities_count; ++i)
			{
				if(req->Capabilities[i])
				{
					json_append_element(jsonCaps, json_mkstring(req->Capabilities[i]));
				}
			}
		}
		json_append_member(jsonRoot, "Capabilities", jsonCaps);
		
		JsonNode* jsonCliParams = json_mkobject();
		if(req->ClientParameters)
		{
			for(int i = 0; i < req->ClientParameters_count; ++i)
			{
				if(req->ClientParameters[i])
				{
					json_append_member(jsonCliParams, req->ClientParameters[i]->Key, json_mkstring(req->ClientParameters[i]->Value));
				}
			}
		}
		json_append_member(jsonRoot, "ClientParameters", jsonCliParams);

		jsonString = json_encode(jsonRoot);
		json_delete(jsonRoot);
	}

	return jsonString;
}

void SessionJob_free(struct SessionJob* job)
{
	#undef FUNCTION
	#define FUNCTION "SessionJob_free-"
	if(job)
	{
		if(job->CompletionEndpoint)
		{
			free(job->CompletionEndpoint);
			job->CompletionEndpoint = NULL;
		}
		if(job->ConfigurationEndpoint)
		{
			free(job->ConfigurationEndpoint);
			job->ConfigurationEndpoint = NULL;
		}
		if(job->Cron)
		{
			free(job->Cron);
			job->Cron = NULL;
		}
		if(job->JobId)
		{
			free(job->JobId);
			job->JobId = NULL;
		}
		if(job->JobTypeId)
		{
			free(job->JobTypeId);
			job->JobTypeId = NULL;
		}
		if(job->Schedule)
		{
			free(job->Schedule);
			job->Schedule = NULL;
		}
		free(job);
	}
}

void SessionRegisterResp_free(struct SessionRegisterResp* resp)
{
	#undef FUNCTION
	#define FUNCTION "SessionRegisterResp_free-"
	if(resp)
	{
		AgentApiResult_free(resp->Result);
		if(resp->Session.AgentId)
		{
			free(resp->Session.AgentId);
			resp->Session.AgentId = NULL;
		}
		if(resp->Session.Token)
		{
			free(resp->Session.Token);
			resp->Session.Token = NULL;
		}
		if(resp->Session.ClientMachine)
		{
			free(resp->Session.ClientMachine);
			resp->Session.ClientMachine = NULL;
		}
		if(resp->Session.Certificate)
		{
			free(resp->Session.Certificate);
			resp->Session.Certificate = NULL;
		}
		if(resp->Session.Jobs)
		{
			// Ownership of these will be handed off
//			for(int i = 0; i < resp->Session.Jobs_count; ++i)
//			{
//				SessionJob_free(resp->Session.Jobs[i]);
//				resp->Session.Jobs[i] = NULL;
//			}
			free(resp->Session.Jobs);
			resp->Session.Jobs = NULL;
		}
		if(resp->Session.ClientParameters)
		{
			for(int i = 0; i < resp->Session.ClientParameters_count; ++i)
			{
				ClientParameter_free(resp->Session.ClientParameters[i]);
				resp->Session.ClientParameters[i] = NULL;
			}
			free(resp->Session.ClientParameters);
			resp->Session.ClientParameters = NULL;
		}
		free(resp);
	}
}

static struct SessionJob* SessionJob_fromJsonNode(JsonNode* jsonJob)
{
	#undef FUNCTION
	#define FUNCTION "SessionJob_fromJsonNode-"
	struct SessionJob* job = NULL;
	if(jsonJob)
	{
		job = calloc(1, sizeof(struct SessionJob));
		job->CompletionEndpoint = json_get_member_string(jsonJob, "CompletionEndpoint");
		job->ConfigurationEndpoint = json_get_member_string(jsonJob, "ConfigurationEndpoint");
		job->Cron = json_get_member_string(jsonJob, "Cron");
		job->JobId = json_get_member_string(jsonJob, "JobId");
		job->JobTypeId = json_get_member_string(jsonJob, "JobTypeId");
		job->Schedule = json_get_member_string(jsonJob, "Schedule");
		job->Priority = json_get_member_number(jsonJob, "Priority", 5);
	}

	return job;
}

struct SessionRegisterResp* SessionRegisterResp_fromJson(char* jsonString)
{
	#undef FUNCTION
	#define FUNCTION "SessionRegisterResp_fromJson-"
	struct SessionRegisterResp* resp = NULL;
	if(jsonString)
	{
		JsonNode* jsonRoot = json_decode(jsonString);
		if(jsonRoot)
		{
			resp = calloc(1, sizeof(struct SessionRegisterResp));

			JsonNode* jsonSession = json_find_member(jsonRoot, "Session");
			if(jsonSession)
			{
				resp->Session.Token = json_get_member_string(jsonSession, "Token");
				resp->Session.AgentId = json_get_member_string(jsonSession, "AgentId");
				resp->Session.Certificate = json_get_member_string(jsonSession, "Certificate");
				resp->Session.ClientMachine = json_get_member_string(jsonSession, "ClientMachine");
				resp->Session.HeartbeatInterval = json_get_member_number(jsonSession, "HeartbeatInterval", 5);

				JsonNode* jsonJobs = json_find_member(jsonSession, "Jobs");
				int jobCount = json_array_size(jsonJobs);
				resp->Session.Jobs_count = jobCount;
				resp->Session.Jobs = calloc(jobCount, sizeof(struct SessionJob*));

				JsonNode* jsonTmp;
				int current = 0;
				json_foreach(jsonTmp, jsonJobs)
				{
					resp->Session.Jobs[current++] = SessionJob_fromJsonNode(jsonTmp);
				}

				JsonNode* jsonParams = json_find_member(jsonSession, "ClientParameters");
				if(jsonParams && jsonParams->tag == JSON_OBJECT)
				{
					current = 0;
					json_foreach(jsonTmp, jsonParams)
					{
						current++;
					}

					resp->Session.ClientParameters = calloc(current, sizeof(struct ClientParameter*));
					current = 0;
					json_foreach(jsonTmp, jsonParams)
					{
						if(jsonTmp && jsonTmp->tag == JSON_STRING && jsonTmp->string_)
						{
							resp->Session.ClientParameters[current++] = ClientParameter_new(jsonTmp->key, jsonTmp->string_);
						}
					}
					resp->Session.ClientParameters_count = current;
				}
			}

			JsonNode* jsonResult = json_find_member(jsonRoot, "Result");
			if(jsonResult)
			{
				resp->Result = AgentApiResult_fromJsonNode(jsonResult);
			}

			json_delete(jsonRoot);
		}
	}

	return resp;
}

struct SessionHeartbeatReq* SessionHeartbeatReq_new()
{
	#undef FUNCTION
	#define FUNCTION "SessionHeartbeatReq_new-"
	struct SessionHeartbeatReq* req = calloc(1, sizeof(struct SessionHeartbeatReq));

	req->TenantId = strdup("00000000-0000-0000-0000-000000000000");

	return req;
}

void SessionHeartbeatReq_free(struct SessionHeartbeatReq* req)
{
	#undef FUNCTION
	#define FUNCTION "SessionHeartbeatReq_free-"
	if(req)
	{
		if(req->TenantId)
		{
			free(req->TenantId);
			req->TenantId = NULL;
		}
		if(req->ClientMachine)
		{
			free(req->ClientMachine);
			req->ClientMachine = NULL;
		}
		if(req->SessionToken)
		{
			free(req->SessionToken);
			req->SessionToken = NULL;
		}
		free(req);
	}
}

char* SessionHeartbeatReq_toJson(struct SessionHeartbeatReq* req)
{
	#undef FUNCTION
	#define FUNCTION "SessionHeartbeatReq_toJson-"
	char* jsonString = NULL;

	if(req)
	{
		JsonNode* jsonRoot = json_mkobject();
		json_append_member(jsonRoot, "AgentPlatform", json_mknumber(req->AgentPlatform));
		if(req->TenantId)
		{
			json_append_member(jsonRoot, "TenantId", json_mkstring(req->TenantId));
		}
		else
		{
			json_append_member(jsonRoot, "TenantId", json_mknull());
		}
		if(req->ClientMachine)
		{
			json_append_member(jsonRoot, "ClientMachine", json_mkstring(req->ClientMachine));
		}
		else
		{
			json_append_member(jsonRoot, "ClientMachine", json_mknull());
		}
		if(req->SessionToken)
		{
			json_append_member(jsonRoot, "SessionToken", json_mkstring(req->SessionToken));
		}
		else
		{
			json_append_member(jsonRoot, "SessionToken", json_mknull());
		}

		jsonString = json_encode(jsonRoot);
		json_delete(jsonRoot);
	}

	return jsonString;
}

void SessionHeartbeatResp_free(struct SessionHeartbeatResp* resp)
{
	#undef FUNCTION
	#define FUNCTION "SessionHeartbeatResp_free-"
	if(resp)
	{
		AgentApiResult_free(resp->Result);
		free(resp);
	}
}

struct SessionHeartbeatResp* SessionHeartbeatResp_fromJson(char* jsonString)
{
	#undef FUNCTION
	#define FUNCTION "SessionHeartbeatResp_fromJson-"
	struct SessionHeartbeatResp* resp = NULL;
	if(jsonString)
	{
		JsonNode* jsonRoot = json_decode(jsonString);
		if(jsonRoot)
		{
			resp = calloc(1, sizeof(struct SessionHeartbeatResp));

			resp->HeartbeatInterval = json_get_member_number(jsonRoot, "HeartbeatInterval", 5);
			resp->SessionValid = json_get_member_bool(jsonRoot, "SessionValid", false);

			JsonNode* jsonResult = json_find_member(jsonRoot, "Result");
			if(jsonResult)
			{
				resp->Result = AgentApiResult_fromJsonNode(jsonResult);
			}

			json_delete(jsonRoot);
		}
	}

	return resp;
}

struct CommonConfigReq* CommonConfigReq_new()
{
	#undef FUNCTION
	#define FUNCTION "CommonConfigReq_new-"
	return calloc(1, sizeof(struct CommonConfigReq));
}

void CommonConfigReq_free(struct CommonConfigReq* req)
{
	#undef FUNCTION
	#define FUNCTION "CommonCompleteReq_free-"
	if(req)
	{
		if(req->JobId)
		{
			free(req->JobId);
			req->JobId = NULL;
		}
		if(req->SessionToken)
		{
			free(req->SessionToken);
			req->SessionToken = NULL;
		}
		free(req);
	}
}

char* CommonConfigReq_toJson(struct CommonConfigReq* req)
{
	#undef FUNCTION
	#define FUNCTION "CommonConfigReq_toJson-"
	char* jsonString = NULL;

	if(req)
	{
		JsonNode* jsonRoot = json_mkobject();
		if(req->SessionToken)
		{
			json_append_member(jsonRoot, "SessionToken", json_mkstring(req->SessionToken));
		}
		else
		{
			json_append_member(jsonRoot, "SessionToken", json_mknull());
		}
		if(req->JobId)
		{
			json_append_member(jsonRoot, "JobId", json_mkstring(req->JobId));
		}
		else
		{
			json_append_member(jsonRoot, "JobId", json_mknull());
		}

		jsonString = json_encode(jsonRoot);
		json_delete(jsonRoot);
	}

	return jsonString;
}

struct CommonCompleteReq* CommonCompleteReq_new()
{
	#undef FUNCTION
	#define FUNCTION "CommonCompleteReq_new-"
	return calloc(1, sizeof(struct CommonCompleteReq));
}

void CommonCompleteReq_free(struct CommonCompleteReq* req)
{
	#undef FUNCTION
	#define FUNCTION "CommonCompleteReq_free-"
	if(req)
	{
		if(req->JobId)
		{
			free(req->JobId);
			req->JobId = NULL;
		}
		if(req->SessionToken)
		{
			free(req->SessionToken);
			req->SessionToken = NULL;
		}
		if(req->Message)
		{
			free(req->Message);
			req->Message = NULL;
		}
		free(req);
	}
}

char* CommonCompleteReq_toJson(struct CommonCompleteReq* req)
{
	#undef FUNCTION
	#define FUNCTION "CommonCompleteReq_toJson-"
	char* jsonString = NULL;

	if(req)
	{
		JsonNode* jsonRoot = json_mkobject();
		json_append_member(jsonRoot, "Status", json_mknumber((double)req->Status));
		json_append_member(jsonRoot, "AuditId", json_mknumber((double)req->AuditId));
		if(req->JobId)
		{
			json_append_member(jsonRoot, "JobId", json_mkstring(req->JobId));
		}
		else
		{
			json_append_member(jsonRoot, "JobId", json_mknull());
		}
		if(req->Message)
		{
			json_append_member(jsonRoot, "Message", json_mkstring(req->Message));
		}
		else
		{
			json_append_member(jsonRoot, "Message", json_mknull());
		}

		if(req->SessionToken)
		{
			json_append_member(jsonRoot, "SessionToken", json_mkstring(req->SessionToken));
		}
		else
		{
			json_append_member(jsonRoot, "SessionToken", json_mknull());
		}

		jsonString = json_encode(jsonRoot);
		json_delete(jsonRoot);
	}

	return jsonString;
}

void CommonCompleteResp_free(struct CommonCompleteResp* resp)
{
	#undef FUNCTION
	#define FUNCTION "CommonCompleteResp_free-"
	if(resp)
	{
		AgentApiResult_free(resp->Result);
		free(resp);
	}
}

struct CommonCompleteResp* CommonCompleteResp_fromJson(char* jsonString)
{
	#undef FUNCTION
	#define FUNCTION "CommonCompleteResp_fromJson-"
	struct CommonCompleteResp* resp = NULL;
	if(jsonString)
	{
		JsonNode* jsonRoot = json_decode(jsonString);
		if(jsonRoot)
		{
			resp = calloc(1, sizeof(struct CommonCompleteResp));

			JsonNode* jsonResult = json_find_member(jsonRoot, "Result");
			if(jsonResult)
			{
				resp->Result = AgentApiResult_fromJsonNode(jsonResult);
			}

			json_delete(jsonRoot);
		}
	}

	return resp;
}

void ManagementConfigResp_free(struct ManagementConfigResp* resp)
{
	#undef FUNCTION
	#define FUNCTION "ManagmentConfigResp_free-"
	if(resp)
	{
		AgentApiResult_free(resp->Result);
		if(resp->Job.Alias)
		{
			free(resp->Job.Alias);
			resp->Job.Alias = NULL;
		}
		if(resp->Job.ClientMachine)
		{
			free(resp->Job.ClientMachine);
			resp->Job.ClientMachine = NULL;
		}
		if(resp->Job.StorePath)
		{
			free(resp->Job.StorePath);
			resp->Job.StorePath = NULL;
		}
		if(resp->Job.StorePassword)
		{
			free(resp->Job.StorePassword);
			resp->Job.StorePassword = NULL;
		}
		if(resp->Job.EntryPassword)
		{
			free(resp->Job.EntryPassword);
			resp->Job.EntryPassword = NULL;
		}
		if(resp->Job.Thumbprint)
		{
			free(resp->Job.Thumbprint);
			resp->Job.Thumbprint = NULL;
		}
		if(resp->Job.EntryContents)
		{
			free(resp->Job.EntryContents);
			resp->Job.EntryContents = NULL;
		}
		if(resp->Job.PfxPassword)
		{
			free(resp->Job.PfxPassword);
			resp->Job.PfxPassword = NULL;
		}
		if(resp->Job.PrivateKeyPath)
		{
			free(resp->Job.PrivateKeyPath);
			resp->Job.PrivateKeyPath = NULL;
		}
		free(resp);
	}
}

struct ManagementConfigResp* ManagementConfigResp_fromJson(char* jsonString)
{
	#undef FUNCTION
	#define FUNCTION "ManagementConfigResp_fromJson-"
	struct ManagementConfigResp* resp = NULL;
	if(jsonString)
	{
		JsonNode* jsonRoot = json_decode(jsonString);
		if(jsonRoot)
		{
			resp = calloc(1, sizeof(struct ManagementConfigResp));

			resp->AuditId = json_get_member_number(jsonRoot, "AuditId", 0);
			resp->JobCancelled = json_get_member_bool(jsonRoot, "JobCancelled", false);

			JsonNode* jsonResult = json_find_member(jsonRoot, "Result");
			if(jsonResult)
			{
				resp->Result = AgentApiResult_fromJsonNode(jsonResult);
			}
			JsonNode* jsonJob = json_find_member(jsonRoot, "Job");
			if(jsonJob)
			{
				resp->Job.Alias = json_get_member_string(jsonJob, "Alias");
				resp->Job.Category = json_get_member_number(jsonJob, "Category", 0);
				resp->Job.ClientMachine = json_get_member_string(jsonJob, "ClientMachine");
				resp->Job.EntryContents = json_get_member_string(jsonJob, "EntryContents");
				resp->Job.EntryPassword = json_get_member_string(jsonJob, "EntryPassword");
				resp->Job.OperationType = json_get_member_number(jsonJob, "OperationType", 0);
				resp->Job.Overwrite = json_get_member_bool(jsonJob, "Overwrite", false);
				resp->Job.PfxPassword = json_get_member_string(jsonJob, "PfxPassword");
				resp->Job.PrivateKeyEntry = json_get_member_bool(jsonJob, "PrivateKeyEntry", false);
				resp->Job.StorePassword = json_get_member_string(jsonJob, "StorePassword");
				resp->Job.StorePath = json_get_member_string(jsonJob, "StorePath");
				resp->Job.StoreType = json_get_member_number(jsonJob, "StoreType", 0);
				resp->Job.Thumbprint = json_get_member_string(jsonJob, "Thumbprint");

				JsonNode* jsonProps = NULL;
				char* propString = json_get_member_string(jsonJob, "Properties");
				if(propString && (jsonProps = json_decode(propString)))
				{
					resp->Job.PrivateKeyPath = json_get_member_string(jsonProps, "PrivateKeyPath");
				}
				free(propString);
				json_delete(jsonProps);
			}

			json_delete(jsonRoot);
		}
	}

	return resp;
}

void ManagementCompleteResp_free(struct ManagementCompleteResp* resp)
{
	#undef FUNCTION
	#define FUNCTION "ManagementCompleteResp_free-"
	if(resp)
	{
		AgentApiResult_free(resp->Result);

		if(resp->InventoryJob)
		{
			free(resp->InventoryJob);
			resp->InventoryJob = NULL;
		}

		free(resp);
	}
}

struct ManagementCompleteResp* ManagementCompleteResp_fromJson(char* jsonString)
{
	#undef FUNCTION
	#define FUNCTION "ManagementCompleteResp_fromJson-"
	struct ManagementCompleteResp* resp = NULL;
	if(jsonString)
	{
		JsonNode* jsonRoot = json_decode(jsonString);
		if(jsonRoot)
		{
			resp = calloc(1, sizeof(struct ManagementCompleteResp));

			JsonNode* jsonResult = json_find_member(jsonRoot, "Result");
			if(jsonResult)
			{
				resp->Result = AgentApiResult_fromJsonNode(jsonResult);
			}

			resp->InventoryJob = json_get_member_string(jsonRoot, "InventoryJob");

			json_delete(jsonRoot);
		}
	}

	return resp;
}

static void InventoryCurrentItem_free(struct InventoryCurrentItem* item)
{
	#undef FUNCTION
	#define FUNCTION "InventoryCurrentItem_free-"
	if(item)
	{
		if(item->Alias)
		{
			free(item->Alias);
			item->Alias = NULL;
		}
		if(item->Thumbprints)
		{
			for(int i = 0; i < item->Thumbprints_count; ++i)
			{
				free(item->Thumbprints[i]);
				item->Thumbprints[i] = NULL;
			}
			free(item->Thumbprints);
			item->Thumbprints = NULL;
		}
		free(item);
	}
}

static struct InventoryCurrentItem* InventoryCurrentItem_fromJsonNode(JsonNode* node)
{
	#undef FUNCTION
	#define FUNCTION "InventoryCurrentItem_fromJsonNode-"
	struct InventoryCurrentItem* result = NULL;

	if(node)
	{
		result = calloc(1, sizeof(struct InventoryCurrentItem));

		result->Alias = json_get_member_string(node, "Alias");
		result->PrivateKeyEntry = json_get_member_bool(node, "PrivateKeyEntry", false);

		JsonNode* jsonThumbs = json_find_member(node, "Thumbprints");
		if(jsonThumbs)
		{
			int thumbCount = json_array_size(jsonThumbs);
			result->Thumbprints_count = thumbCount;
			result->Thumbprints = calloc(thumbCount, sizeof(char*));

			int current = 0;
			JsonNode* jsonTmp = NULL;
			json_foreach(jsonTmp, jsonThumbs)
			{
				result->Thumbprints[current++] = json_get_value_string(jsonTmp);
			}
		}
	}

	return result;
}

void InventoryConfigResp_free(struct InventoryConfigResp* resp)
{
	#undef FUNCTION
	#define FUNCTION "InventoryConfigResp_free-"
	if(resp)
	{
		AgentApiResult_free(resp->Result);
		if(resp->InventoryEndpoint)
		{
			free(resp->InventoryEndpoint);
			resp->InventoryEndpoint = NULL;
		}
		if(resp->Job.ClientMachine)
		{
			free(resp->Job.ClientMachine);
			resp->Job.ClientMachine = NULL;
		}
		if(resp->Job.StorePath)
		{
			free(resp->Job.StorePath);
			resp->Job.StorePath = NULL;
		}
		if(resp->Job.StorePassword)
		{
			free(resp->Job.StorePassword);
			resp->Job.StorePassword = NULL;
		}
		if(resp->Job.Inventory)
		{
			for(int i = 0; i < resp->Job.Inventory_count; ++i)
			{
				InventoryCurrentItem_free(resp->Job.Inventory[i]);
				resp->Job.Inventory[i] = NULL;
			}
			free(resp->Job.Inventory);
			resp->Job.Inventory = NULL;
		}
		free(resp);
	}
}

struct InventoryConfigResp* InventoryConfigResp_fromJson(char* jsonString)
{
	#undef FUNCTION
	#define FUNCTION "InventoryConfigResp_fromJson-"
	struct InventoryConfigResp* resp = NULL;
	if(jsonString)
	{
		JsonNode* jsonRoot = json_decode(jsonString);
		if(jsonRoot)
		{
			resp = calloc(1, sizeof(struct InventoryConfigResp));

			resp->AuditId = json_get_member_number(jsonRoot, "AuditId", 0);
			resp->JobCancelled = json_get_member_bool(jsonRoot, "JobCancelled", false);
			resp->InventoryEndpoint = json_get_member_string(jsonRoot, "InventoryEndpoint");

			JsonNode* jsonResult = json_find_member(jsonRoot, "Result");
			if(jsonResult)
			{
				resp->Result = AgentApiResult_fromJsonNode(jsonResult);
			}
			JsonNode* jsonJob = json_find_member(jsonRoot, "Job");
			if(jsonJob)
			{
				resp->Job.Category = json_get_member_number(jsonJob, "Category", 0);
				resp->Job.ClientMachine = json_get_member_string(jsonJob, "ClientMachine");
				resp->Job.StorePassword = json_get_member_string(jsonJob, "StorePassword");
				resp->Job.StorePath = json_get_member_string(jsonJob, "StorePath");

				JsonNode* jsonInv = json_find_member(jsonJob, "Inventory");
				if(jsonInv)
				{
					int invCount = json_array_size(jsonInv);
					resp->Job.Inventory_count = invCount;
					resp->Job.Inventory = calloc(invCount, sizeof(struct InventoryCurrentItem*));

					JsonNode* jsonTmp;
					int current = 0;
					json_foreach(jsonTmp, jsonInv)
					{
						resp->Job.Inventory[current++] = InventoryCurrentItem_fromJsonNode(jsonTmp);
					}
				}
			}

			json_delete(jsonRoot);
		}
	}

	return resp;
}

static void InventoryUpdateItem_free(struct InventoryUpdateItem* item)
{
	#undef FUNCTION
	#define FUNCTION "InventoryUpdateItem_free-"
	if(item)
	{
		if(item->Alias)
		{
			free(item->Alias);
			item->Alias = NULL;
		}
		if(item->Certificates)
		{
			for(int i = 0; i < item->Certificates_count; ++i)
			{
				free(item->Certificates[i]);
				item->Certificates[i] = NULL;
			}
			free(item->Certificates);
			item->Certificates = NULL;
		}
		free(item);
	}
}

static JsonNode* InventoryUpdateItem_toJsonNode(struct InventoryUpdateItem* updateItem)
{
	#undef FUNCTION
	#define FUNCTION "InventoryUpdateItem_toJsonNode-"
	JsonNode* result = NULL;

	if(updateItem)
	{
		result = json_mkobject();
		json_append_member(result, "PrivateKeyEntry", json_mkbool(updateItem->PrivateKeyEntry));
		json_append_member(result, "UseChainLevel", json_mkbool(updateItem->UseChainLevel));
		json_append_member(result, "ItemStatus", json_mknumber(updateItem->ItemStatus));
		if(updateItem->Alias)
		{
			json_append_member(result, "Alias", json_mkstring(updateItem->Alias));
		}
		else
		{
			json_append_member(result, "Alias", json_mknull());
		}

		JsonNode* jsonCerts = json_mkarray();
		if(updateItem->Certificates)
		{
			for(int i = 0; i < updateItem->Certificates_count; ++i)
			{
				json_append_element(jsonCerts, json_mkstring(updateItem->Certificates[i]));
			}
		}
		json_append_member(result, "Certificates", jsonCerts);
	}

	return result;
}

void InventoryUpdateReq_free(struct InventoryUpdateReq* req)
{
	#undef FUNCTION
	#define FUNCTION "InventoryUpdateReq_free-"
	if(req)
	{
		if(req->JobId)
		{
			free(req->JobId);
			req->JobId = NULL;
		}
		if(req->SessionToken)
		{
			free(req->SessionToken);
			req->SessionToken = NULL;
		}

		for(int i = 0; i < req->Inventory.count; ++i)
		{
			InventoryUpdateItem_free(req->Inventory.items[i]);
			req->Inventory.items[i] = NULL;
		}
		free(req);
	}
}

char* InventoryUpdateReq_toJson(struct InventoryUpdateReq* req)
{
	#undef FUNCTION
	#define FUNCTION "InventoryUpdateReq_toJson-"
	char* jsonString = NULL;

	if(req)
	{
		JsonNode* jsonRoot = json_mkobject();
		if(req->SessionToken)
		{
			json_append_member(jsonRoot, "SessionToken", json_mkstring(req->SessionToken));
		}
		else
		{
			json_append_member(jsonRoot, "SessionToken", json_mknull());
		}
		if(req->JobId)
		{
			json_append_member(jsonRoot, "JobId", json_mkstring(req->JobId));
		}
		else
		{
			json_append_member(jsonRoot, "JobId", json_mknull());
		}

		JsonNode* jsonInv = json_mkarray();

		for(int i = 0; i < req->Inventory.count; ++i)
		{
			json_append_element(jsonInv, InventoryUpdateItem_toJsonNode(req->Inventory.items[i]));
		}
		json_append_member(jsonRoot, "Inventory", jsonInv);

		jsonString = json_encode(jsonRoot);
		json_delete(jsonRoot);
	}

	return jsonString;
}

void InventoryUpdateResp_free(struct InventoryUpdateResp* resp)
{
	#undef FUNCTION
	#define FUNCTION "InventoryUpdateResp_free-"
	if(resp)
	{
		AgentApiResult_free(resp->Result);
		free(resp);
	}
}

struct InventoryUpdateResp* InventoryUpdateResp_fromJson(char* jsonString)
{
	#undef FUNCTION
	#define FUNCTION "InventoryUpdateResp_fromJson-"
	struct InventoryUpdateResp* resp = NULL;
	if(jsonString)
	{
		JsonNode* jsonRoot = json_decode(jsonString);
		if(jsonRoot)
		{
			resp = calloc(1, sizeof(struct InventoryUpdateResp));

			JsonNode* jsonResult = json_find_member(jsonRoot, "Result");
			if(jsonResult)
			{
				resp->Result = AgentApiResult_fromJsonNode(jsonResult);
			}

			json_delete(jsonRoot);
		}
	}

	return resp;
}

void EnrollmentConfigResp_free(struct EnrollmentConfigResp* resp)
{
	#undef FUNCTION
	#define FUNCTION 'EnrollmentConfigResp_free-'
	if(resp)
	{
		AgentApiResult_free(resp->Result);

		if(resp->Entropy)
		{
			free(resp->Entropy);
			resp->Entropy = NULL;
		}
		if(resp->KeyType)
		{
			free(resp->KeyType);
			resp->KeyType = NULL;
		}
		if(resp->Subject)
		{
			free(resp->Subject);
			resp->Subject = NULL;
		}
		if(resp->ClientMachine)
		{
			free(resp->ClientMachine);
			resp->ClientMachine = NULL;
		}
		if(resp->StorePath)
		{
			free(resp->StorePath);
			resp->StorePath = NULL;
		}
		if(resp->StorePassword)
		{
			free(resp->StorePassword);
			resp->StorePassword = NULL;
		}
		if(resp->EnrollEndpoint)
		{
			free(resp->EnrollEndpoint);
			resp->EnrollEndpoint = NULL;
		}
		if(resp->PrivateKeyPath)
		{
			free(resp->PrivateKeyPath);
			resp->PrivateKeyPath = NULL;
		}

		free(resp);
	}
}

struct EnrollmentConfigResp* EnrollmentConfigResp_fromJson(char* jsonString)
{
	#undef FUNCTION
	#define FUNCTION "EnrollmentConfigResp_fromJson-"
	log_verbose("%s%sjsonString: %s", MODULE, FUNCTION, jsonString);
	struct EnrollmentConfigResp* resp = NULL;
	if(jsonString)
	{
		JsonNode* jsonRoot = json_decode(jsonString);
		if(jsonRoot)
		{
			resp = calloc(1, sizeof(struct EnrollmentConfigResp));

			JsonNode* jsonResult = json_find_member(jsonRoot, "Result");
			if(jsonResult)
			{
				resp->Result = AgentApiResult_fromJsonNode(jsonResult);
			}

			resp->AuditId = json_get_member_number(jsonRoot, "AuditId", 0);
			resp->JobCancelled = json_get_member_bool(jsonRoot, "JobCancelled", false);

			resp->ClientMachine = json_get_member_string(jsonRoot, "ClientMachine");
			resp->Entropy = json_get_member_string(jsonRoot, "Entropy");
			resp->KeyType = json_get_member_string(jsonRoot, "KeyType");
			resp->Subject = json_get_member_string(jsonRoot, "Subject");
			resp->StorePath = json_get_member_string(jsonRoot, "StorePath");
			resp->StorePassword = json_get_member_string(jsonRoot, "StorePassword");
			resp->EnrollEndpoint = json_get_member_string(jsonRoot, "EnrollEndpoint");
			

			JsonNode* keySizeNode = json_find_member(jsonRoot, "KeySize");
			if(keySizeNode && keySizeNode->tag == JSON_NUMBER)
			{
				resp->KeySize = keySizeNode->number_;
			}
			else if(keySizeNode && keySizeNode->tag == JSON_STRING)
			{
				int tmp;
				if(sscanf(keySizeNode->string_, "%d", &tmp) == 1)
				{
					resp->KeySize = tmp;
				}
			}

			JsonNode* jsonProps = NULL;
			resp->Properties = json_get_member_string(jsonRoot, "Properties");
			if(resp->Properties && (jsonProps = json_decode(resp->Properties)))
			{
				log_verbose("%s%sProperties: %s", MODULE, FUNCTION, resp->Properties);
				log_verbose("%s%sseparatePrivateKey as bool: %d", MODULE, FUNCTION, json_get_member_bool(jsonProps, "separatePrivateKey", false));
				log_verbose("%s%sprivateKeyPath: %s", MODULE, FUNCTION, json_get_member_string(jsonProps, "privateKeyPath"));
				bool theBool = json_get_member_bool(jsonProps, "separatePrivateKey", false);
				if(theBool) {
					resp->PrivateKeyPath = json_get_member_string(jsonProps, "privateKeyPath");
				}
				else resp->PrivateKeyPath = NULL;
			}
			json_delete(jsonProps);

			json_delete(jsonRoot);
		}
	}

	return resp;
}

void EnrollmentEnrollReq_free(struct EnrollmentEnrollReq* req)
{
	#undef FUNCTION
	#define FUNCTION "EnrollmentEnrollReq_free-"
	if(req)
	{
		if(req->JobId)
		{
			free(req->JobId);
			req->JobId = NULL;
		}
		if(req->SessionToken)
		{
			free(req->SessionToken);
			req->SessionToken = NULL;
		}

		if(req->CSRText)
		{
			free(req->CSRText);
			req->CSRText = NULL;
		}


		free(req);
	}
}

char* EnrollmentEnrollReq_toJson(struct EnrollmentEnrollReq* req)
{
	#undef FUNCTION
	#define FUNCTION "EnrollmentEnrollReq_toJson-"
	char* jsonString = NULL;

	if(req)
	{
		JsonNode* jsonRoot = json_mkobject();
		if(req->SessionToken)
		{
			json_append_member(jsonRoot, "SessionToken", json_mkstring(req->SessionToken));
		}
		else
		{
			json_append_member(jsonRoot, "SessionToken", json_mknull());
		}
		if(req->JobId)
		{
			json_append_member(jsonRoot, "JobId", json_mkstring(req->JobId));
		}
		else
		{
			json_append_member(jsonRoot, "JobId", json_mknull());
		}

		if(req->CSRText)
		{
			json_append_member(jsonRoot, "CSRText", json_mkstring(req->CSRText));
		}
		else
		{
			json_append_member(jsonRoot, "CSRText", json_mknull());
		}

		jsonString = json_encode(jsonRoot);
		json_delete(jsonRoot);
	}

	return jsonString;
}

void EnrollmentEnrollResp_free(struct EnrollmentEnrollResp* resp)
{
	#undef FUNCTION
	#define FUNCTION "EnrollmentEnrollResp_free-"
	if(resp)
	{
		AgentApiResult_free(resp->Result);

		if(resp->Certificate)
		{
			free(resp->Certificate);
			resp->Certificate = NULL;
		}

		free(resp);
	}
}

struct EnrollmentEnrollResp* EnrollmentEnrollResp_fromJson(char* jsonString)
{
	#undef FUNCTION
	#define FUNCTION "EnrollmentEnrollResp_fromJson-"
	struct EnrollmentEnrollResp* resp = NULL;
	if(jsonString)
	{
		JsonNode* jsonRoot = json_decode(jsonString);
		if(jsonRoot)
		{
			resp = calloc(1, sizeof(struct EnrollmentEnrollResp));

			JsonNode* jsonResult = json_find_member(jsonRoot, "Result");
			if(jsonResult)
			{
				resp->Result = AgentApiResult_fromJsonNode(jsonResult);
			}

			resp->Certificate = json_get_member_string(jsonRoot, "Certificate");

			json_delete(jsonRoot);
		}
	}

	return resp;
}

void EnrollmentCompleteResp_free(struct EnrollmentCompleteResp* resp)
{
	#undef FUNCTION
	#define FUNCTION "EnrollmentCompleteResp_free-"
	if(resp)
	{
		AgentApiResult_free(resp->Result);

		if(resp->InventoryJob)
		{
			free(resp->InventoryJob);
			resp->InventoryJob = NULL;
		}

		free(resp);
	}
}

struct EnrollmentCompleteResp* EnrollmentCompleteResp_fromJson(char* jsonString)
{
	#undef FUNCTION
	#define FUNCTION "EnrollmentCompleteResp_fromJson-"
	struct EnrollmentCompleteResp* resp = NULL;
	if(jsonString)
	{
		JsonNode* jsonRoot = json_decode(jsonString);
		if(jsonRoot)
		{
			resp = calloc(1, sizeof(struct EnrollmentCompleteResp));

			JsonNode* jsonResult = json_find_member(jsonRoot, "Result");
			if(jsonResult)
			{
				resp->Result = AgentApiResult_fromJsonNode(jsonResult);
			}

			resp->InventoryJob = json_get_member_string(jsonRoot, "InventoryJob");

			json_delete(jsonRoot);
		}
	}

	return resp;
}
