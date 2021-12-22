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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fetchlogs.h"
#include "logging.h"
#include "httpclient.h"

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
static int get_fetchlogs_config(const char* sessionToken, const char* jobId, 
    const char* endpoint, struct FetchLogsConfigResp** pConf)
{
    char* url = NULL;

    log_verbose("%s::%s(%d) : Sending config request: %s", LOG_INF, jobId);
    struct CommonConfigReq* req = NULL;
    req = CommonConfigReq_new();
    req->JobId = strdup(jobId);
    req->SessionToken = strdup(sessionToken);

    char* jsonReq = CommonConfigReq_toJson(req);
    char* jsonResp = NULL;

    url = config_build_url(endpoint, true);

    int res = http_post_json(url, ConfigData->Username, ConfigData->Password, 
                            ConfigData->TrustStore, ConfigData->AgentCert, 
                            ConfigData->AgentKey, ConfigData->AgentKeyPassword,
                            jsonReq, &jsonResp, ConfigData->httpRetries, 
                            ConfigData->retryInterval);

    if(res == 0)
    {
        *pConf = FetchLogsConfigResp_fromJson(jsonResp);
    }
    else 
    {
        log_error("%s::%s(%d) : Config retrieval failed with error code %d", 
            LOG_INF, res);
    }

    free(jsonReq);
    free(jsonResp);
    CommonConfigReq_free(req);
    free(url);

    return res;
}

static int get_logs(char* logFilePath, int maxCharactersToRead, char** log)
{
    FILE* pLog;
    char* logContent = NULL;

    if((pLog = fopen(logFilePath, "r")) == NULL)
    {
        log_error("%s::%s(%d) : Failed to open log file.", LOG_INF);
        return 1;
    }
    if(fseek(pLog, 0, SEEK_END) != 0)
    {
        log_error("%s::%s(%d) : End of file not found.", LOG_INF);
        goto fail;
    }
    long int fileSize = ftell(pLog);
    if(fseek(pLog, -1 * maxCharactersToRead, SEEK_END) != 0)
    {
        rewind(pLog);
    }

    if(fileSize - ftell(pLog) == maxCharactersToRead)
    {
        while(true)
        {
            if ((char)fgetc(pLog) == '\n')
            {
                (void)fseek(pLog, 1, SEEK_CUR);
                break;
            }
            else if(fgetc(pLog) == EOF)
            {
                if(fseek(pLog, -1 * maxCharactersToRead, SEEK_END) != 0)
                {
                    (void)rewind(pLog);
                }
                break;
            }
            else 
            {
                (void)fseek(pLog, 1, SEEK_CUR);
            }
        }
    }

    logContent = calloc((size_t)maxCharactersToRead, sizeof(*logContent));
    if (!logContent)
    {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        goto fail;
    }
    size_t readCount = fread(logContent, sizeof(char), 
        (size_t)maxCharactersToRead, pLog);
    if ((readCount < (size_t)maxCharactersToRead) && (0 != ferror(pLog))) 
    {

    }

    *log = logContent;
    if (pLog) (void)fclose(pLog);
    return 0;

fail:
    if (pLog) (void)fclose(pLog);
    return 1;
}

static int send_fetchlogs_job_complete(const char* sessionToken, 
    const char* jobId, const char* endpoint, int jobStatus, long auditId, 
    const char* message, const char* log, struct CommonCompleteResp** pComp)
{
    char* url = NULL;

    log_verbose("%s::%s(%d) : Sending complete request: %ld for session: %s", 
        LOG_INF, auditId, sessionToken);
    struct FetchLogsCompleteReq* req = FetchLogsCompleteReq_new();
    if (sessionToken)
    {
        req->SessionToken = strdup(sessionToken);
    }
    else
    {
        req->SessionToken = strdup("Error no session token");
    }
    if (jobId)
    {
        req->JobId = strdup(jobId);
    }
    else
    {
        req->JobId = strdup("Error no JobId");
    }
	
	req->Status = jobStatus;
	req->AuditId = auditId;
    if (message) 
    {
        req->Message = strdup(message);
    }
    else
    {
        req->Message = strdup("");
    }
	
    if (log)
    {
        req->Log = strdup(log);
    }
    else
    {
        req->Log = strdup("Log retrieval error!");
    }


    char* jsonReq = FetchLogsCompleteReq_toJson(req);

    char* jsonResp = NULL;

    url = config_build_url(endpoint, true);

    int res = http_post_json(url, ConfigData->Username, ConfigData->Password, 
        ConfigData->TrustStore, ConfigData->AgentCert, ConfigData->AgentKey, 
        ConfigData->AgentKeyPassword, jsonReq, &jsonResp, 
        ConfigData->httpRetries, ConfigData->retryInterval);

    if(res == 0)
    {
        *pComp = CommonCompleteResp_fromJson(jsonResp);
    }
    else
    {
        log_error("%s::%s(%d) : Job completion failed with error code %d", 
            LOG_INF, res);
    }

    free(jsonReq);
    free(jsonResp);
    free(url);
    FetchLogsCompleteReq_free(req);
    return res;
}

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
int cms_job_fetchLogs(struct SessionJob* jobInfo, char* sessionToken)
{
    int res = 0;
    int returnable = 0;
    struct FetchLogsConfigResp* fetchLogsConf = NULL;
    char* statusMessage = strdup("");
	enum AgentApiResultStatus status = STAT_UNK;

    log_info("%s::%s(%d) : Starting fetch logs job %s", 
        LOG_INF, jobInfo->JobId);

    res = get_fetchlogs_config(sessionToken, jobInfo->JobId, 
        jobInfo->ConfigurationEndpoint, &fetchLogsConf);

    if(res == 0 && fetchLogsConf && AgentApiResult_log(fetchLogsConf->Result, 
        &statusMessage, &status))
    {
        if(fetchLogsConf->JobCancelled)
        {
            returnable = 1;
            log_info("%s::%s(%d) : Job has been cancelled and will not be run", 
                LOG_INF);
        }
        else
        {
			log_verbose("%s::%s(%d) : Audit Id: %ld", LOG_INF, 
                fetchLogsConf->AuditId);
            char* log = NULL;
            struct CommonCompleteResp* compResponse = NULL;

            /* pull the last 4000 characters from the log file. */
            /* (trim beginning to the first \n if necessary).   */
            status = STAT_SUCCESS;
            if( 0 != get_logs(ConfigData->LogFile, 
                fetchLogsConf->MaxCharactersToReturn, &log) )
            {
                status = STAT_ERR;
            }

            /* Complete job. */
            res = send_fetchlogs_job_complete(sessionToken, jobInfo->JobId, 
                jobInfo->CompletionEndpoint, (status+1), 
                fetchLogsConf->AuditId, statusMessage, log, &compResponse);
            
            log_verbose("%s::%s : %s", __FILE__, __FUNCTION__, log);
            free(log); 
            CommonCompleteResp_free(compResponse);
        }
    }
    
    /* free memory */
    FetchLogsConfigResp_free(fetchLogsConf);
    free(statusMessage);

    return returnable;
}
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/