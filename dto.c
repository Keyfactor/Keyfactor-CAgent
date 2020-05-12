/*
This C Agent Reference Implementation uses the OpenSSL encryption libraries, 
which are not included as a part of this distribution.  For hardware key storage 
or TPM support, libraries such as WolfSSL may also be used in place of OpenSSL.

NOTE: usage of this file and the SDK is subject to the 
following SOFTWARE DEVELOPMENT KIT LICENSE: 

THIS IS A LICENSE AGREEMENT between you and Certified Security Solutions, Inc.,
 6050 Oak Tree Boulevard, Suite 450, Independence, Ohio 44131 (“CSS”).  This 
 License Agreement accompanies the Software Development Kit(s) (“SDK,” as 
 defined below) for CSS Products (defined below) licensed to you by CSS.  This 
 copy of the SDK is licensed to You as the end user or the representative of 
 your employer.  You represent that CSS, a licensee of one or more CSS Products
 , or a third-party working on behalf of such a licensee has authorized you to
 download this SDK.  YOU AGREE THAT THIS LICENSE AGREEMENT IS ENFORCEABLE AND 
 THAT YOUR USE OF THE SDK CONSTITUTES ACCEPTANCE OF THE AGREEMENT TERMS.  If 
 you do not agree to the terms of this Agreement, do not use this SDK.  
1. DEFINITIONS.
In this License Agreement: 
(a) “SDK” means the CSS software development kit, including any sample code, 
tools, utilities, documentation, and related explanatory materials and 
includes any upgrades, modified versions, updates, additions, and copies of 
the SDK;  
(b) “CSS Products” means[ CSS’s CMS application programs, technologies and 
software, including but not limited to CMS Enterprise, CMS Sapphire, CMS 
Topaz, and CMS VerdeTTo,] that are or may be made available for licensing, 
including any modified versions or upgrades thereof.  This License Agreement
 does not govern use of CSS Products, which are governed by separate written
 license agreements; and
(c) “You” and “your” refer to any person or entity acquiring or using the 
SDK under the terms of this License Agreement.
2. ROYALTY-FREE DEVELOPMENT LICENSE. Subject to the restrictions contained 
in this Section 2, CSS grants you limited a nonexclusive, nontransferable, 
royalty-free license to use the items in the SDK only for the purpose of 
development of software designed to interoperate with licensed CSS Products 
either on Your own behalf or on behalf of a licensee of one or more CSS
 Products.
(a) Under this License Agreement, you may use, modify, or merge all or 
portions of any sample code included in the SDK with your software .  Any 
modified or merged portion of sample code is subject to this License 
Agreement.  You are required to include CSS’s copyright notices in your 
software. You may make a reasonable, limited number of copies of the SDK to 
be used by your employees or contractors as provided herein, and not for 
general business purposes, and such employees or contractors shall be 
subject to the obligations and restrictions in this License Agreement.  
Except in accordance with the preceding sentence, you may not assign, 
sublicense, or otherwise transfer your rights or obligations granted under 
this License Agreement without the prior written consent of CSS. Any 
attempted assignment, sublicense, or transfer without such prior written 
consent shall be void and of no effect.  CSS may assign or transfer this 
License Agreement in whole or in part, and it will inure to the benefit of 
any successor or assign of CSS.
(b) Under this License Agreement, if you use, modify, or merge all or 
portions of any sample code included in the SDK with your software, you may
distribute it as part of your products solely on a royalty-free 
non-commercial basis.  Any right to distribute any part of the SDK or any 
modified, merged, or derivative version on a royalty-bearing or other 
commercial basis is subject to separate approval, and possibly the 
imposition of a royalty, by CSS.
(c) Except as expressly permitted in paragraphs 2(a) and 2(b), you may not
 sell, sublicense, rent, loan, or lease any portion of the SDK to any third
 party. You may not decompile, reverse engineer, or otherwise access or 
 attempt to access the source code for any part of the SDK not made
 available to you in source code form, nor make or attempt to make any
 modification to the SDK or remove, obscure, interfere with, or circumvent 
 any feature of the SDK, including without limitation any copyright or 
 other intellectual property notices, security, or access control mechanism.
 
3. PROPRIETARY RIGHTS. The items contained in the SDK are the intellectual
 property of CSS and are protected by United States and international 
 copyright and other intellectual property law. You agree to protect all 
 copyright and other ownership interests of CSS  in all items in the SDK 
 supplied to you under this License Agreement. You agree that all copies 
 of the items in the SDK, reproduced for any reason by you, will contain 
 the same copyright notices, and other proprietary notices as appropriate,
 as appear on or in the master items delivered by CSS in the SDK. CSS 
 retains title and ownership of the items in the SDK, the media on which 
 it is recorded, and all subsequent copies, regardless of the form or media
 in or on which the original and other copies may exist.  You may use CSS’s
 trade names, trademarks and service marks only as may be required to 
 accurately describe your products and to provide copyright notice as 
 required herein.
Except as expressly granted above, this License Agreement does not grant 
you any rights under any patents, copyrights, trade secrets, trademarks or 
any other rights in respect to the items in the SDK.
4. FEEDBACK. You are encouraged to provide CSS with comments, bug reports, 
feedback, enhancements, or modifications proposed or suggested by you for 
the SDK or any CSS Product (“Feedback”). If provided, CSS will treat such 
Feedback as non-confidential notwithstanding any notice to the contrary you 
may include in any accompanying communication, and CSS shall have the right
 to use such Feedback at its discretion, including, but not limited to, the
 incorporation of such suggested changes into the SDK or any CSS Product. 
 You hereby grant CSS a perpetual, irrevocable, transferable, sublicensable,
 royalty-free, worldwide, nonexclusive license under all rights necessary to
 so incorporate and use your Feedback for any purpose, including to make 
 and sell products and services.  
5. TERM. This License Agreement is effective until terminated.  CSS has 
the right to terminate this License Agreement immediately, without judicial
 intervention, if you fail to comply with any term herein. Upon any such
 termination you must remove all full and partial copies of the items in 
 the SDK from your computer and discontinue the use of the items in the 
 SDK.
6. DISCLAIMER OF WARRANTY. CSS licenses the SDK to you on an “AS-IS” basis.
 CSS makes no representation with respect to the adequacy of any items in
 the SDK, whether or not used by you in the development of any products, 
 for any particular purpose or with respect to their adequacy to produce 
 any particular result. CSS shall not be liable for loss or damage arising
 out of this License Agreement or from the distribution or use of your 
 products containing portions of the SDK. TO THE FULLEST EXTENT PERMITTED 
 BY LAW, CSS DISCLAIMS ALL WARRANTIES, EITHER EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO IMPLIED CONDITIONS OR WARRANTIES OF MERCHANTABILITY AND
 FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT OF ANY THIRD PARTY 
 RIGHT IN RESPECT OF THE ITEMS IN THE SDK.
CSS is under no obligation to provide any support under this License 
Agreement, including upgrades or future versions of the SDK or any portions
 thereof, to you, any end user or to any other party. 
7. LIMITATION OF LIABILITY. Notwithstanding any other provisions of this 
License Agreement, CSS’s liability to you under this License Agreement 
shall be limited to the amount you paid for the SDK or $10, whichever is 
less.
IN NO EVENT WILL CSS BE LIABLE TO YOU FOR ANY CONSEQUENTIAL, INDIRECT, 
INCIDENTAL, PUNITIVE, OR SPECIAL DAMAGES, INCLUDING DAMAGES FOR ANY LOST 
PROFITS, LOST SAVINGS, LOSS OF DATA, COSTS, FEES OR EXPENSES OF ANY KIND OR
 NATURE, ARISING OUT OF ANY PROVISION OF THIS LICENSE AGREEMENT OR THE USE
 OR INABILITY TO USE THE ITEMS IN THE SDK, EVEN IF A CSS REPRESENTATIVE HAS
 BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES, OR FOR ANY CLAIM BY ANY 
 PARTY. 
8. INDEMNIFICATION. You agree to indemnify, hold harmless, and defend CSS
 from and against any claims or lawsuits, including attorneys’ fees, that 
 arise or result from the use and distribution of your products that 
 contain or are based upon any portion of the SDK, provided that CSS gives
 you prompt written notice of any such claim, tenders the defense or 
 settlement of such a claim to you at your expense, and cooperates with 
 you, at your expense, in defending or settling any such claim.
9. CHOICE OF LAW. This Agreement will be governed by and construed in 
accordance with the substantive laws of the United States and the State of
 Ohio.  Federal and state courts located in Cuyahoga County, Ohio shall 
 have exclusive jurisdiction over all disputes relating to this Agreement.
 This Agreement will not be governed by the conflict of law rules of any 
 jurisdiction or the United Nations Convention on Contracts for the 
 International Sale of Goods, the application of which is expressly 
 excluded.
10. COMPLIANCE WITH EXPORT CONTROL LAWS. You agree that any of your 
products that include any part of the SDK will not be shipped, transferred
 or exported into any country or used in any manner prohibited by the 
 United States Export Administration Act and that you will comply with 
 all applicable export control laws. All rights to use the SDK are granted 
 on condition that such rights are forfeited if you fail to comply with the
 terms of this Agreement.
11. NON-BLOCKING OF CSS DEVELOPMENT. You acknowledge that CSS is currently 
developing or may develop technologies and products in the future that have
 or may have design and/or functionality similar to products that you may
 develop based on your license herein. Nothing in this Agreement shall
 impair, limit or curtail CSS’s right to continue with its development, 
 maintenance and/or distribution of CSS’s technology or products. You agree
 that you shall not assert any patent that you own against CSS, its 
 subsidiaries or affiliates, or their customers, direct or indirect, 
 agents and contractors for the manufacture, use, import, licensing, offer
 for sale or sale of any CSS Products.
12. OPEN SOURCE SOFTWARE. Notwithstanding anything to the contrary, you
 are not licensed to (and you agree that you will not) integrate or use 
 this SDK with any Viral Open Source Software or otherwise take any action
 that could require disclosure, distribution, or licensing of all or any 
 part of the SDK in source code form, for the purpose of making derivative
 works, or at no charge. For the purposes of this Section 12, “Viral Open
 Source Software” shall mean software licensed under the GNU General 
 Public License, the GNU Lesser General Public License, or any other 
 license terms that could require, or condition your use, modification, or
 distribution of such software on, the disclosure, distribution, or 
 licensing of any other software in source code form, for the purpose of
 making derivative works, or at no charge. Any violation of the foregoing
 provision shall immediately terminate all of your licenses and other 
 rights to the SDK granted under this Agreement.
13. WAIVER. None of the provisions of this License Agreement shall be 
deemed to have been waived by any act or acquiescence on the part of CSS, 
its agents or employees, but only by an instrument in writing signed by an 
officer of CSS.
14.  INTEGRATION. When conflicting language exists between this License 
Agreement and any other agreement included in the SDK, this License 
Agreement shall supersede. If either you or CSS employ attorneys to enforce
 any rights arising out of or relating to this License Agreement, the 
 prevailing party shall be entitled to recover reasonable attorneys’ fees. 
 You acknowledge that you have read this License Agreement, understand it
 and that it is the complete and exclusive statement of your agreement 
 with CSS that supersedes any prior agreement, oral or written, between 
 CSS and you with respect to the licensing of the SDK. No variation of 
 the terms of this License Agreement will be enforceable against CSS unless
 CSS gives its express consent, in writing signed by an officer of CSS. 
15.  GOVERNMENT LICENSE.  If the SDK is licensed to the U.S. Government
 or any agency thereof, it will be considered to be “commercial computer 
 software” or “commercial computer software documentation,” as those terms 
 are used in 48 CFR § 12.212 or 48 CFR § 227.7202, and is being licensed 
 with only those rights as are granted to all other licensees as set forth 
 in this Agreement.*/


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
