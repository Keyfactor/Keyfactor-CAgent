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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <time.h> 

#include "logging.h"
#include "httpclient.h"
#include "global.h"
#include "utils.h"
#include "config.h"

#if defined(__TPM__)
  #include "agent.h"
  #include <tss2/tss2_mu.h>
  #include <tss2/tss2_esys.h>
  #include <tpm2-tss-engine.h>
#endif

/******************************************************************************/
/***************************** GLOBAL VARIABLES *******************************/
/******************************************************************************/
bool add_client_cert_to_header = false;

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/
static const size_t MAX_CERT_SIZE = 4096;

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/
/**                                                                           */
/* The memory structure used by curl in its callback function                 */
/* memory holds the curl response data (callback NULL terminates this data)   */
/* size holds the size of the data                                            */
/*                                                                            */
struct MemoryStruct {
  char *memory;
  size_t size;
};

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
/* This handles curl_easy_setopt returned error code logging                  */
/* @param  - [Input] curl = a pointer to our CURL handle                      */
/* @param  - [I/O]   errNum = the curl error number                           */
/*                                                                            */
static int handle_curl_error(CURL *curl, int errNum) {
    /* When tracing, dump the error buffer to stderr */
    if ( is_log_trace() ) {
        size_t len = strlen( errBuff );
        log_error( "%s::%s-libcurl: (%d) ", LOG_INF, errNum );
        if ( len ) {
            log_error( "%s::%s(%d) : %s%s", LOG_INF, errBuff,
              ((errBuff[len-1] != '\n') ? "\n" : ""));
        } else {
            log_error("%s::%s(%d) : %s", LOG_INF, curl_easy_strerror(errNum) );
        }
    }
    log_error("%s::%s(%d) : %s", LOG_INF, curl_easy_strerror(errNum));

    curl_easy_cleanup(curl);
    return errNum;
}

/**                                                                           */
/* The memory callback function curl uses -- the default is fwrite, so we     */
/* want to change that behaviour.                                             */
/*                                                                            */
/* to send data to this function, execute:                                    */
/*  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback) */
/*                                                                            */
/* to pass our 'chunk' structure we need this code:                           */
/*  struct MemoryStruct chunk;                                                */
/*  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);         */
/*                                                                            */
/* This function gets called by libcurl as soon as there is data received     */
/* that needs to be saved.  For most transfers, this callback gets called many*/
/* times and each invoke delivers another chunk of data.                      */
/*                                                                            */
/* @param  - [Output] contents = The delivered data (NOT NULL TERMINATED)     */
/* @param  - [N/A] size = 1.  This is always one (refers to a byte)           */
/* @param  - [Input] nmemb = The size of the delivered contents               */
/* @param  - [Output] userp =                                                 */
/* @return - success = the number of bytes taken care of                      */
/*           failure = the number of bytes taken care of                      */
/*                                                                            */
static size_t WriteMemoryCallback(const void *contents, const size_t size, const size_t nmemb, const void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = realloc( mem->memory, (mem->size + realsize + 1) );
  if( NULL == mem->memory )  {
    log_error("%s::%s(%d): out of memory", LOG_INF);
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = '\0';

  return realsize;
} /* WriteMemoryCallback */

/**                                                                           */
/*   Check if a file exists                                                   */
/*   @param fileName = the filename to look on the filesystem for             */
/*   @retval true = file exists                                               */
/*   @retval false = file isn't there or other error                          */
/*                                                                            */
static bool check_file_exists( const char *fileName )
{
  FILE *fp;
  if ( (fp = fopen( fileName, "r")) )
  {
    (void)fclose(fp);
    return true;
  }
  else
  {
    return false;
  }
} /* file_exists */

static void stripCR(char string[])
{
    static const char CR = '\n';
    size_t x, y;
    x = 0;
    y = 0;
    while (('\0' != string[x]) && (MAX_CERT_SIZE > x)) {
        if (CR != string[x]) {
            string[y] = string[x];
            x++;
            y++;
        } else {
            x++;
        }
    } /* while */
    string[y] = '\0';
    return;
}

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/*  Issue an HTTP POST command stating that the content is JSON and that a    */
/*   JSON response is accepted.                                               */
/*                                                                            */
/*   @param url = a string with the URL address to contact                    */
/*   @param username = a string with the username to log into the URL address */
/*   @param password = a string with password to log into the URL address     */
/*   @param trustStore = a string with a filename containing additional       */
/*                       trusted certificates                                 */
/*   @param clientCert = a string with a filename containing a CA signed      */
/*                       cert for this platform (for TLS communication)       */
/*   @param clientKey = a string with a filename containing the private key   */
/*                      associated with the clientCert                        */
/*   @param clientKeyPass = a string with the password associated with the    */
/*                          clientKey                                         */
/*   @param postData = a JSON string                                          */
/*   @param pRespData = a pointer to a string where the HTTP response         */
/*                      data gets set.  NOTE: This memory gets DYNAMICALLY    */
/*                      allocated here!  You need to properly dispose of it in*/
/*                      the calling function.                                 */
/*   @param retryCount = The number of times to try the http session          */
/*   @param retryInterval = The time (in seconds) between retries             */
/*   @return 0 on successfull completion                                      */
/*           1-99 corresponding to the failed cURL response code              */
/*           255 if the dynamic memory allocation for pRespData fails         */
/*           300-511 The HTTP response error (e.g. 404 Not Found)             */
/*                                                                            */
int http_post_json(const char* url, const char* username,
                   const char* password, const char* trustStore,
                   const char* clientCert, const char* clientKey,
                   const char* clientKeyPass, char* postData,
                   char** pRespData, int retryCount, int retryInterval) 
{
    log_info("%s::%s(%d) : Preparing to POST to Platform at %s", LOG_INF, url);
    bool client_cert_present = false;
    unsigned char* client_cert_compressed = NULL;
    size_t dummySize = 0;
	int toReturn = -1;
    log_trace("%s::%s(%d) : Initializing cURL", LOG_INF);
	CURL* curl = curl_easy_init();
	char errBuff[CURL_ERROR_SIZE];
	if(curl) {
        log_trace("%s::%s(%d) : Curl initialized ok", LOG_INF);
            struct MemoryStruct chunk;
            chunk.size = 0;
        chunk.memory = calloc(1,sizeof(*chunk.memory));
        if ( !chunk.memory ) {
          log_error("%s::%s(%d): Out of memory when allocating chunk", LOG_INF);
          curl_easy_cleanup(curl);
          return CURLE_FAILED_INIT;
        }

    #if  defined(__TPM__)
        if (ConfigData->EnrollOnStartup)
        {
          log_info("%s::%s(%d) : Skipping TPM - enroll on startup is turned on.",
            LOG_INF);
          goto skipTPM;
        }
        /**************************************************************************/
        /*  When a TPM is used, the clientKey is an encrypted BLOB.  The BLOB can */
        /*  only be decoded inside the TPM.  Tell cURL that this is the case &    */
        /*  use the engine_id global variable.  This is usually the tpm2tss engine*/
        /**************************************************************************/
        log_verbose("%s::%s(%d) : Setting cURL to use TPM as SSL Engine %s",
          LOG_INF, engine_id);
        int errNum = curl_easy_setopt(curl, CURLOPT_SSLENGINE, engine_id);
        if ( CURLE_OK != errNum ) {
          return handle_curl_error(curl, errNum);
        }

        log_verbose("%s::%s(%d) : Setting cURL to use TPM as the default "
          "SSL Engine %s", LOG_INF, engine_id);
        errNum = curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
	    if ( CURLE_OK != errNum ) {
	        return handle_curl_error(curl, errNum);
	    }

        log_verbose("%s::%s(%d) : Setting cURL to have keytype as engine", LOG_INF);
        errNum = curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "ENG");
	    if ( CURLE_OK != errNum ) {
	        return handle_curl_error(curl, errNum);
	    }

        log_verbose("%s::%s(%d) : Setting cURL to use default TPM keyphrase", LOG_INF);
        errNum = curl_easy_setopt(curl, CURLOPT_KEYPASSWD, "");
	    if ( CURLE_OK != errNum ) {
	        return handle_curl_error(curl, errNum);
	    }
	}

    skipTPM:
    #endif

        /**************************************************************************/
        /*  Set up curl to POST to a url using the username and Password          */
        /*  passed to the function                                                */
        /**************************************************************************/
        log_trace("%s::%s(%d) : Configuring cURL options", LOG_INF);
        errNum = curl_easy_setopt(curl, CURLOPT_URL, url);
        if ( CURLE_OK != errNum ) {
            return handle_curl_error(curl, errNum);
        }
        errNum = curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if ( CURLE_OK != errNum ) {
            return handle_curl_error(curl, errNum);
        }
        if (username && password) {
          log_trace("%s::%s(%d) Configuring username and password", LOG_INF);
          errNum = curl_easy_setopt(curl, CURLOPT_USERNAME, username);
          if ( CURLE_OK != errNum ) {
            return handle_curl_error(curl, errNum);
          }
          errNum = curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
          if ( CURLE_OK != errNum ) {
            return handle_curl_error(curl, errNum);
          }
        } else {
          log_trace("%s::%s(%d) : Username and password not supplied - skipping",
            LOG_INF);
        }
        errNum = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);
        if ( CURLE_OK != errNum ) {
            return handle_curl_error(curl, errNum);
        }
    #ifdef __HTTP_1_1__
        /* Some versions of openSSL default to v2.0.  If the platform is set for */
        /* v1.1, curl will not failover to v1.1.  So, force V1.1 */
        errNum = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        if ( CURLE_OK != errNum ) {
            return handle_curl_error(curl, errNum);
        }
    #endif

        /**************************************************************************/
        /*  If the passed files exist in the system, then use them for additional */
        /*  trusted certificates, and certs to create the TLS connection.         */
        /**************************************************************************/
        if( 1 == file_exists(trustStore) ) {
            log_trace("%s::%s(%d) : Setting trustStore to %s", LOG_INF, trustStore);
            errNum = curl_easy_setopt(curl, CURLOPT_CAINFO, trustStore);
            if ( CURLE_OK != errNum ) {
                return handle_curl_error(curl, errNum);
            }
        } else {
          log_trace("%s::%s(%d) : Trust store does not exist", LOG_INF);
        }

        /* Set the cert based on enroll on startup and UseBootStrapCert */
        if( ConfigData->EnrollOnStartup ) {
            if ( ConfigData->UseBootstrapCert ) {
                log_trace("%s::%s(%d) : Attempting to use the BOOTSTRAP cert and key", LOG_INF);
                if( 1 == file_exists(ConfigData->BootstrapCert) ) {
                    log_trace("%s::%s(%d) : Setting clientCert to %s", LOG_INF, ConfigData->BootstrapCert);
                    errNum = curl_easy_setopt(curl, CURLOPT_SSLCERT, ConfigData->BootstrapCert);
                    if ( CURLE_OK != errNum ) {
                        return handle_curl_error(curl, errNum);
                    }
                    read_file_bytes(ConfigData->BootstrapCert, &client_cert_compressed, &dummySize);
                    if (NULL == client_cert_compressed) {
                        log_error("%s::%s(%d) : Out of memory copying client certificate", LOG_INF);
                        goto exit;
                    }
                } else {
                    log_warn("%s::%s(%d) : The BOOTSTRAP cert was not found at %s", LOG_INF,
                             ConfigData->BootstrapCert);
                }
                if( 1 == file_exists(ConfigData->BootstrapKey) ) {
                    log_trace("%s::%s(%d) : Setting clientKey to %s", LOG_INF, ConfigData->BootstrapKey);
                    errNum = curl_easy_setopt(curl, CURLOPT_SSLKEY, ConfigData->BootstrapKey);
                    if ( CURLE_OK != errNum ) {
                        return handle_curl_error(curl, errNum);
                    }
                } else {
                    log_warn("%s::%s(%d) : The BOOTSTRAP key was not found at %s", LOG_INF,
                                ConfigData->BootstrapKey);
                }
                if( (1 == file_exists(ConfigData->BootstrapKey)) && ConfigData->BootstrapKeyPassword ) {
                    log_trace("%s::%s(%d) : Setting clientPassword to %s", LOG_INF,
                              ConfigData->BootstrapKeyPassword);
                    errNum = curl_easy_setopt(curl, CURLOPT_KEYPASSWD, ConfigData->BootstrapKeyPassword);
                    if ( CURLE_OK != errNum ) {
                        return handle_curl_error(curl, errNum);
                    }
                }
            } else {
                log_info("%s::%s(%d) : Bypassing client certificates on initial startup", LOG_INF);
            }
        } else {
          log_trace("%s::%s(%d) : Use the Agent cert and key", LOG_INF);
          if( 1 == file_exists(clientCert) ) {
            log_trace("%s::%s(%d) : Setting clientCert to %s", LOG_INF, clientCert);
            errNum = curl_easy_setopt(curl, CURLOPT_SSLCERT, clientCert);
            if ( CURLE_OK != errNum ) {
              return handle_curl_error(curl, errNum);
            }
            read_file_bytes(clientCert, &client_cert_compressed, &dummySize);
            if (NULL == client_cert_compressed) {
              log_error("%s::%s(%d) : Out of memory copying client certificate", LOG_INF);
              goto exit;
            }
          } else {
              log_warn("%s::%s(%d) : The clientCert does not exist at %s", LOG_INF, clientCert);
          }
          if( 1 == file_exists(clientKey) ) {
            log_trace("%s::%s(%d) : Setting clientKey to %s", LOG_INF, clientKey);
            errNum = curl_easy_setopt(curl, CURLOPT_SSLKEY, clientKey);
            if ( CURLE_OK != errNum ) {
                return handle_curl_error(curl, errNum);
            }
          } else {
              log_warn("%s::%s(%d) : The clientKey does not exist at %s", LOG_INF, clientKey);
          }
          if( (1 == file_exists(clientKey)) && clientKeyPass ) {
            log_trace("%s::%s(%d) : Setting clientPassword to %s", LOG_INF,clientKeyPass);
            errNum = curl_easy_setopt(curl, CURLOPT_KEYPASSWD, clientKeyPass);
            if ( CURLE_OK != errNum ) {
                return handle_curl_error(curl, errNum);
            }
          }
        }

        /* Turn on verbose output for tracing */
        if ( is_log_trace() ) {
          log_trace("%s::%s(%d) : Turning on cURL verbose output", LOG_INF);
          errNum = curl_easy_setopt( curl, CURLOPT_VERBOSE, 1 );
          if ( CURLE_OK != errNum ) {
              return handle_curl_error(curl, errNum);
          }
          errNum = curl_easy_setopt( curl, CURLOPT_ERRORBUFFER, errBuff );
          if ( CURLE_OK != errNum ) {
              return handle_curl_error(curl, errNum);
          }
          errBuff[0] = 0; /* empty the error buffer */
        }

        /* send all data to this function  */
        errNum = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        if ( CURLE_OK != errNum ) {
            return handle_curl_error(curl, errNum);
        }
        /* we pass our 'chunk' struct to the callback function */
        errNum = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        if ( CURLE_OK != errNum ) {
            return handle_curl_error(curl, errNum);
        }

        log_trace("%s::%s(%d) : cURL options set correctly", LOG_INF);

        struct curl_slist* list = NULL;
        /**************************************************************************/
        /*    Set up the HTTP header to tell the API this is standard JSON.       */
        /*    NOTE: Some versions of Internet Explorer have a problem using       */
        /*          these headers.                                                */
        /*    Also, set the content length header option to the data size.        */
        /*    TODO: Error checking, as this is a dynamic memory allocation and any*/
        /*            on-demand memory allocation needs a verification step.      */
        /**************************************************************************/
        list = curl_slist_append(NULL, "Content-Type: application/json");
        list = curl_slist_append(list, "Accept: application/json");
        char clBuf[30];
        (void)snprintf(clBuf, 30, "Content-Length: %d", (int)strlen(postData));
        list = curl_slist_append(list, clBuf);
        if ((add_client_cert_to_header) && (NULL != client_cert_compressed)) {
            log_debug("%s::%s(%d) : Adding client certificate to %s header", LOG_INF, CLIENT_CERT_HEADER);
            char certBuf[MAX_CERT_SIZE];
            stripCR(client_cert_compressed);
            (void)snprintf(certBuf, MAX_CERT_SIZE, "%s: %s",CLIENT_CERT_HEADER, client_cert_compressed);
            list = curl_slist_append(list, certBuf);
        } else {
            log_debug("%s::%s(%d) : Skipping adding header = %s", LOG_INF, CLIENT_CERT_HEADER);
        }

        /**************************************************************************/
        /*  Now add the header & data to the HTTP POST request.                   */
        /**************************************************************************/
        errNum = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
        if ( CURLE_OK != errNum ) {
            return handle_curl_error(curl, errNum);
        }
        errNum = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData);
        if ( CURLE_OK != errNum ) {
            return handle_curl_error(curl, errNum);
        }
        errNum = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (int)strlen(postData));
        if ( CURLE_OK != errNum ) {
            return handle_curl_error(curl, errNum);
        }
        log_trace("%s::%s(%d): postData = %s", LOG_INF, postData);


        /**************************************************************************/
        /*  Make sure the cURL operation succeeded and the HTTP response code     */
        /*  indicates success. If we are successfull, place the response message  */
        /*  If the cURL operation fails, return the cURL error code.              */
        /*  If the HTTP response is an error, return the HTTP failure code.       */
        /**************************************************************************/
        long httpCode = 0;
        int res = CURLE_FAILED_INIT;
        int tries = retryCount;

        while (0 < tries) {
          res = curl_easy_perform(curl);
          (void)curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &httpCode);
          /* if there was an error & we still have tries left to do */
          tries--;
          log_verbose("%s::%s(%d): curl resp = %d, httpCode = %ld, tries left = %d",
            LOG_INF,res, httpCode, tries);
          if(((CURLE_OK != res) || (httpCode >= 300)) && (0 < tries)) {
            log_verbose("%s::%s(%d): Failed curl post. Sleeping %d seconds before retry", LOG_INF,retryInterval);
            if ( 0 < retryInterval ) {
              (void)sleep((unsigned int)retryInterval);
            }
          } else {
            tries = 0; /* exit the loop */
          }
        } /* while */

        if(res != CURLE_OK) {
            /* When tracing, dump the error buffer to stderr */
            if ( is_log_trace() ) {
                size_t len = strlen( errBuff );
                log_error( "%s::%s(%d): libcurl: (%d) ", LOG_INF, res );
                if ( 0 != len ) {
                    log_error( "%s::%s(%d): %s%s", LOG_INF,	errBuff,((errBuff[len-1] != '\n') ? "\n" : ""));
                } else {
                    log_error("%s::%s(%d): %s\n", LOG_INF, curl_easy_strerror(res) );
                }
            }
            log_error("%s::%s(%d): %s", LOG_INF, curl_easy_strerror(res));
            toReturn = res;
        } else if(httpCode >= 300) {
            log_error("%s::%s(%d): HTTP Response: %ld", LOG_INF, httpCode);
            toReturn = (int)httpCode;
        } else {
            log_verbose("%s::%s(%d): %lu bytes retrieved -- allocating memory for response",
                        LOG_INF, (unsigned long)chunk.size);
            *pRespData = strdup(chunk.memory);
            log_trace("%s::%s(%d): Response is:\n%s", LOG_INF, *pRespData);
            if ( NULL == *pRespData ) {
                log_error("%s::%s(%d): Out of memory", LOG_INF);
                toReturn = 255;
            } else {
                toReturn = 0;
            }
        }

exit:
        /* Cleanup, de-allocate, etc. */
        if (list) {
            curl_slist_free_all(list);
        }
        if (curl) {
            curl_easy_cleanup(curl);
        }
        if (chunk.memory) {
            free(chunk.memory);
        }
    } /* if curl */

	return toReturn;
} /* http_post_json */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/