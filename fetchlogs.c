/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fetchlogs.h"

static int get_fetchlogs_config(const char* sessionToken, const char* jobId, const char* endpoint, struct ConfigData* config, struct FetchLogsConfigResp** pConf)
{
    char* url = NULL;

    log_verbose("fetchlogs-get_fetchlogs_config-Sending config request: %s", jobId);
    struct CommonConfigReq* req = CommonConfigReq_new();
    req->JobId = strdup(jobId);
    req->SessionToken = strdup(sessionToken);

    char* jsonReq = CommonConfigReq_toJson(req);
    char* jsonResp = NULL;

    url = config_build_url(config, endpoint, true);
    int res = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, config->ClientKey, config->ClientKeyPassword, jsonReq, &jsonResp);

    if(res == 0)
    {
        *pConf = FetchLogsConfigResp_fromJson(jsonResp);
    }
    else 
    {
        log_error("fetchlogs-get_fetchlogs_config-Config retrieval failed with error code %d", res);
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
        log_error("fetchlogs-get_logs-Failed to open log file.");
        return 1;
    }
    if(fseek(pLog, 0, SEEK_END) != 0)
    {
        log_error("fetchlogs-get_logs-End of file not found.");
        return 1;
    }
    int fileSize = ftell(pLog);
    if(fseek(pLog, -1 * maxCharactersToRead, SEEK_END) != 0)
    {
        rewind(pLog);
    }

    if(fileSize - ftell(pLog) == maxCharactersToRead)
    {
        while(1)
        {
            if (fgetc(pLog) == '\n')
            {
                fseek(pLog, 1, SEEK_CUR);
                break;
            }
            else if(fgetc(pLog) == EOF)
            {
                if(fseek(pLog, -1 * maxCharactersToRead, SEEK_END) != 0)
                {
                    rewind(pLog);
                }
                break;
            }
            else 
            {
                fseek(pLog, 1, SEEK_CUR);
            }
        }
    }

    logContent = calloc(maxCharactersToRead, sizeof(char));
    fread(logContent, sizeof(char), maxCharactersToRead, pLog);

    *log = logContent;
    fclose(pLog);
    return 0;
}

static int send_fetchlogs_job_complete(const char* sessionToken, const char* jobId, const char* endpoint, \
		struct ConfigData* config, int jobStatus, long auditId, const char* message, const char* log, struct CommonCompleteResp** pComp)
{
    char* url = NULL;

    log_verbose("fetchlogs-send_fetchlogs_job_complete-Sending complete request: %ld for session: %s", auditId, sessionToken);
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
    int res = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, config->ClientKey, config->ClientKeyPassword, jsonReq, &jsonResp);

    if(res == 0)
    {
        *pComp = CommonCompleteResp_fromJson(jsonResp);
    }
    else
    {
        log_error("fetchlogs-send_fetchlogs_job_complete-Job completion failed with error code %d", res);
    }

    free(jsonReq);
    free(jsonResp);
    free(url);
    FetchLogsCompleteReq_free(req);
    return res;
}

int cms_job_fetchLogs(struct SessionJob* jobInfo, struct ConfigData* config, char* sessionToken)
{
    int res = 0;
    int returnable = 0;
    struct FetchLogsConfigResp* fetchLogsConf = NULL;
    char* statusMessage = strdup("");
	enum AgentApiResultStatus status = STAT_UNK;

    log_info("fetchlogs-cms_job_fetchlogs-Starting fetch logs job %s", jobInfo->JobId);

    res = get_fetchlogs_config(sessionToken, jobInfo->JobId, jobInfo->ConfigurationEndpoint, config, &fetchLogsConf);

    if(res == 0 && fetchLogsConf && AgentApiResult_log(fetchLogsConf->Result, &statusMessage, &status))
    {
        if(fetchLogsConf->JobCancelled)
        {
            returnable = 1;
            log_info("fetchlogs-cms_job_fetchlogs-Job has been cancelled and will not be run\n");
        }
        else
        {
			log_verbose("fetchlogs-cms_job_fetchlogs-Audit Id: %ld", fetchLogsConf->AuditId);
            char* log = NULL;
            struct CommonCompleteResp* compResponse = NULL;

            // pull the last 4000 characters from the log file. (trim beginning to the first \n if necessary).
            status = STAT_SUCCESS;
            if(get_logs(config->LogFile, fetchLogsConf->MaxCharactersToReturn, &log) != 0)
            {
                status = STAT_ERR;
            }

            // Complete job.
            res = send_fetchlogs_job_complete(sessionToken, jobInfo->JobId, jobInfo->CompletionEndpoint, config, (status+1), fetchLogsConf->AuditId, statusMessage, log, &compResponse);
            
            log_verbose("%s", log);
            free(log);  // seg fault here because log is a const char* not char*
            CommonCompleteResp_free(compResponse);
        }
    }
    
    // free memory
    FetchLogsConfigResp_free(fetchLogsConf);
    free(statusMessage);

    return returnable;
}