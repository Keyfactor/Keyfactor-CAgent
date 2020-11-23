/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file fetchlogs.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fetchlogs.h"
#include "logging.h"
#include "httpclient.h"

static int get_fetchlogs_config(const char* sessionToken, const char* jobId, \
                                const char* endpoint,struct ConfigData* config,\
                                struct FetchLogsConfigResp** pConf)
{
    char* url = NULL;

    log_verbose("%s::%s(%d) : Sending config request: %s", \
        __FILE__, __FUNCTION__, __LINE__, jobId);
    struct CommonConfigReq* req = NULL;
    req = CommonConfigReq_new();
    req->JobId = strdup(jobId);
    req->SessionToken = strdup(sessionToken);

    char* jsonReq = CommonConfigReq_toJson(req);
    char* jsonResp = NULL;

    url = config_build_url(config, endpoint, true);

    int res = http_post_json(url, config->Username, config->Password, \
                            config->TrustStore, config->AgentCert, \
                            config->AgentKey, config->AgentKeyPassword, \
                            jsonReq, &jsonResp, config->httpRetries, \
                            config->retryInterval);

    if(res == 0)
    {
        *pConf = FetchLogsConfigResp_fromJson(jsonResp);
    }
    else 
    {
        log_error("%s::%s(%d) : Config retrieval failed with error code %d", \
            __FILE__, __FUNCTION__, __LINE__, res);
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
        log_error("%s::%s(%d) : Failed to open log file.", \
            __FILE__, __FUNCTION__, __LINE__);
        return 1;
    }
    if(fseek(pLog, 0, SEEK_END) != 0)
    {
        log_error("%s::%s(%d) : End of file not found.", \
            __FILE__, __FUNCTION__, __LINE__);
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
        log_error("%s::%s(%d) : Out of memory", \
            __FILE__, __FUNCTION__, __LINE__);
        goto fail;
    }
    size_t readCount = fread(logContent, sizeof(char), \
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

static int send_fetchlogs_job_complete(const char* sessionToken, \
    const char* jobId, const char* endpoint, struct ConfigData* config, \
    int jobStatus, long auditId, const char* message, const char* log, \
    struct CommonCompleteResp** pComp)
{
    char* url = NULL;

    log_verbose("%s::%s(%d) : Sending complete request: %ld for session: %s", \
        __FILE__, __FUNCTION__, __LINE__, auditId, sessionToken);
    struct FetchLogsCompleteReq* req = FetchLogsCompleteReq_new();
    req->SessionToken = strdup(sessionToken);
	req->JobId = strdup(jobId);
	req->Status = jobStatus;
	req->AuditId = auditId;
	req->Message = strdup(message);
    req->Log = strdup(log);

    char* jsonReq = FetchLogsCompleteReq_toJson(req);

    char* jsonResp = NULL;

    url = config_build_url(config, endpoint, true);

    int res = http_post_json(url, config->Username, config->Password, \
        config->TrustStore, config->AgentCert, config->AgentKey, \
        config->AgentKeyPassword, jsonReq, &jsonResp, config->httpRetries, \
        config->retryInterval);

    if(res == 0)
    {
        *pComp = CommonCompleteResp_fromJson(jsonResp);
    }
    else
    {
        log_error("%s::%s(%d) : Job completion failed with error code %d",\
            __FILE__, __FUNCTION__, __LINE__, res);
    }

    free(jsonReq);
    free(jsonResp);
    free(url);
    FetchLogsCompleteReq_free(req);
    return res;
}

int cms_job_fetchLogs(struct SessionJob* jobInfo, struct ConfigData* config, \
    char* sessionToken)
{
    int res = 0;
    int returnable = 0;
    struct FetchLogsConfigResp* fetchLogsConf = NULL;
    char* statusMessage = strdup("");
	enum AgentApiResultStatus status = STAT_UNK;

    log_info("%s::%s(%d) : Starting fetch logs job %s", \
        __FILE__, __FUNCTION__, __LINE__, jobInfo->JobId);

    res = get_fetchlogs_config(sessionToken, jobInfo->JobId, \
        jobInfo->ConfigurationEndpoint, config, &fetchLogsConf);

    if(res == 0 && fetchLogsConf && AgentApiResult_log(fetchLogsConf->Result, \
        &statusMessage, &status))
    {
        if(fetchLogsConf->JobCancelled)
        {
            returnable = 1;
            log_info("%s::%s(%d) : Job has been cancelled and will not be run",\
             __FILE__, __FUNCTION__, __LINE__);
        }
        else
        {
			log_verbose("%s::%s(%d) : Audit Id: %ld", \
                __FILE__, __FUNCTION__, __LINE__,fetchLogsConf->AuditId);
            char* log = NULL;
            struct CommonCompleteResp* compResponse = NULL;

            // pull the last 4000 characters from the log file. 
            // (trim beginning to the first \n if necessary).
            status = STAT_SUCCESS;
            if( \
                get_logs(config->LogFile, fetchLogsConf->MaxCharactersToReturn,\
                    &log) != 0)
            {
                status = STAT_ERR;
            }

            // Complete job.
            res = send_fetchlogs_job_complete(sessionToken, jobInfo->JobId, \
                jobInfo->CompletionEndpoint, config, (status+1), \
                fetchLogsConf->AuditId, statusMessage, log, &compResponse);
            
            log_verbose("%s::%s : %s", __FILE__, __FUNCTION__, log);
            free(log);  // seg fault here because log is a const char* not char*
            CommonCompleteResp_free(compResponse);
        }
    }
    
    // free memory
    FetchLogsConfigResp_free(fetchLogsConf);
    free(statusMessage);

    return returnable;
}