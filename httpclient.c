/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file httpclient.c */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <time.h> // BL-20654

#include "logging.h"
#include "httpclient.h"
#include "global.h"

#if defined(__TPM__)
  #include "agent.h"
  #include <tss2/tss2_mu.h>
  #include <tss2/tss2_esys.h>
  #include <tpm2-tss-engine.h>
  const char* bootstrapCert = "certs/Boostrap.cer";
  const char* bootstrapKey = "certs/Bootstrap.pem";
  const char* bootstrapPW = "P@ssw0rd";
#endif

/**
 * The memory structure used by curl in its callback function
 * memory holds the curl response data (our callback NULL terminates this data)
 * size holds the size of the data
 */
struct MemoryStruct {
  char *memory;
  size_t size;
};

/**
 * The memory callback function curl uses -- the default is fwrite, so we
 * want to change that behaviour.
 *
 * to send data to this function, execute:
 *  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)
 *
 * to pass our 'chunk' structure we need this code:
 *  struct MemoryStruct chunk;
 *  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
 *
 * This function gets called by libcurl as soon as there is data received
 * that needs to be saved.  For most transfers, this callback gets called many
 * times and each invoke delivers another chunk of data. 
 *
 * @param  - [Output] contents = The delivered data (NOT NULL TERMINATED)
 * @param  - [N/A] size = 1.  This is always one (refers to a byte)
 * @param  - [Input] nmemb = The size of the delivered contents
 * @param  - [Output] userp = 
 * @return - success = the number of bytes taken care of
 *           failure = the number of bytes taken care of
 */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, \
  void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = realloc( mem->memory, (mem->size + realsize + 1) );
  if( NULL == mem->memory )  
  {
    log_error("%s::%s(%d): out of memory", __FILE__, __FUNCTION__, __LINE__);
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = '\0';

  return realsize;
} /* WriteMemoryCallback */

/**
 *   Check if a file exists
 *   @param fileName = the filename to look on the filesystem for
 *   @retval true = file exists
 *   @retval false = file isn't there or other error
 */
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

/**
 *  Issue an HTTP POST command stating that the content is JSON and that a
 *   JSON response is accepted.
 *
 *   @param url = a string with the URL address to contact
 *   @param username = a string with the username to log into the URL address
 *   @param password = a string with password to log into the URL address
 *   @param trustStore = a string with a filename containing additional
 *                       trusted certificates
 *   @param clientCert = a string with a filename containing a CA signed
 *                       cert for this platform (for TLS communication)
 *   @param clientKey = a string with a filename containing the private key
 *                      associated with the clientCert
 *   @param clientKeyPass = a string with the password associated with the
 *                          clientKey
 *   @param postData = a JSON string
 *   @param pRespData = a pointer to a string where the HTTP response
 *                      data gets set.  NOTE: This memory gets DYNAMICALLY
 *                      allocated here!  You need to properly dispose of it in
 *                      the calling function.
 *   @param retryCount = The number of times to try the http session
 *   @param retryInterval = The time (in seconds) between retries
 *   @return 0 on successfull completion
 *           1-99 corresponding to the failed cURL response code
 *           255 if the dynamic memory allocation for pRespData fails
 *           300-511 The HTTP response error (e.g. 404 Not Found)
 */
int http_post_json(const char* url, const char* username,
                   const char* password, const char* trustStore,
                   const char* clientCert, const char* clientKey,
                   const char* clientKeyPass, char* postData,
                   char** pRespData, int retryCount, int retryInterval) 
{
  log_trace("%s::%s(%d) : Preparing to POST to Platform", \
    __FILE__, __FUNCTION__, __LINE__);
	int toReturn = -1;
	CURL* curl = curl_easy_init();
	char errBuff[CURL_ERROR_SIZE];
	if(curl)
	{
		struct MemoryStruct chunk;
		chunk.size = 0;
    chunk.memory = calloc(1,sizeof(*chunk.memory));
    if ( !chunk.memory )
    {
      log_error("%s::%s(%d): Out of memory when allocating chunk", \
        __FILE__, __FUNCTION__, __LINE__);
      curl_easy_cleanup(curl);
      return CURLE_FAILED_INIT;
    }

#if  defined(__TPM__)
    if (ConfigData->EnrollOnStartup) {
      log_info("%s::%s(%d) : Skipping TPM - enroll on startup is turned on.", \
        __FILE__, __FUNCTION__, __LINE__);
      goto skipTPM;
    }
    /***************************************************************************
        When a TPM is used, the clientKey is an encrypted BLOB.  The BLOB can
        only be decoded inside the TPM.  Tell cURL that this is the case &
        use the engine_id global variable.  This is usually the tpm2tss engine.
    ***************************************************************************/
    log_verbose("%s::%s(%d) : Setting cURL to use TPM as SSL Engine %s", \
      __FILE__, __FUNCTION__, __LINE__, engine_id);
    int errNum = curl_easy_setopt(curl, CURLOPT_SSLENGINE, engine_id);
    if ( CURLE_OK != errNum ) {
      /* When tracing, dump the error buffer to stderr */
      if ( is_log_trace() ) {
        size_t len = strlen( errBuff );
        log_trace( "%s::%s-libcurl: (%d) ", \
          __FILE__, __FUNCTION__, __LINE__, errNum );
        if ( len ) {
          log_trace( "%s::%s(%d) : %s%s", __FILE__, __FUNCTION__, __LINE__,
                  errBuff, ((errBuff[len-1] != '\n') ? "\n" : ""));

        } else {
          log_trace("%s::%s(%d) : %s", \
            __FILE__, __FUNCTION__, __LINE__, curl_easy_strerror(errNum) );
        }
      }
      log_error("%s::%s(%d) : http-http_post_json-%s", \
        __FILE__, __FUNCTION__, __LINE__, curl_easy_strerror(errNum));

      curl_easy_cleanup(curl);
      return errNum;
    }

    log_verbose("%s::%s(%d) : Setting cURL to use TPM as the default SSL Engine %s", \
      __FILE__, __FUNCTION__, __LINE__, engine_id);
    errNum = curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
    if ( CURLE_OK != errNum ) {
      /* When tracing, dump the error buffer to stderr */
      if ( is_log_trace() ) {
        size_t len = strlen( errBuff );
        log_trace( "%s::%s-libcurl: (%d) ", \
          __FILE__, __FUNCTION__, __LINE__, errNum );
        if ( len )  {
          log_trace( "%s::%s(%d) : %s%s", __FILE__, __FUNCTION__, __LINE__,
                  errBuff, ((errBuff[len-1] != '\n') ? "\n" : ""));

        } else {
          log_trace("%s::%s(%d) : %s", \
            __FILE__, __FUNCTION__, __LINE__, curl_easy_strerror(errNum) );
        }
      }
      log_error("%s::%s(%d) : http-http_post_json-%s", \
        __FILE__, __FUNCTION__, __LINE__, curl_easy_strerror(errNum));

      curl_easy_cleanup(curl);
      return errNum;
    }

    log_verbose("%s::%s(%d) : Setting cURL to have keytype as engine",\
      __FILE__, __FUNCTION__, __LINE__);
    errNum = curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "ENG");
    if ( CURLE_OK != errNum ) {
      /* When tracing, dump the error buffer to stderr */
      if ( is_log_trace() ) {
        size_t len = strlen( errBuff );
        log_trace( "%s::%s-libcurl: (%d) ", \
          __FILE__, __FUNCTION__, __LINE__, errNum );
        if ( len )  {
          log_trace( "%s::%s(%d) : %s%s", __FILE__, __FUNCTION__, __LINE__,
                  errBuff, ((errBuff[len-1] != '\n') ? "\n" : ""));

        } else {
          log_trace("%s::%s(%d) : %s", \
            __FILE__, __FUNCTION__, __LINE__, curl_easy_strerror(errNum) );
        }
      }
      log_error("%s::%s(%d) : http-http_post_json-%s", \
        __FILE__, __FUNCTION__, __LINE__, curl_easy_strerror(errNum));

      curl_easy_cleanup(curl);
      return errNum;
    }
skipTPM:
#endif

    /***************************************************************************
        Set up curl to POST to a url using the username and Password
        passed to the function
    ***************************************************************************/
    (void)curl_easy_setopt(curl, CURLOPT_URL, url);
    (void)curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (username && password) {
    	(void)curl_easy_setopt(curl, CURLOPT_USERNAME, username);
    	(void)curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
    }
    (void)curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);
#ifdef __HTTP_1_1__
    /* Some version sof openSSL default to v2.0.  If the platform is set for */
    /* v1.1, curl will not failover to v1.1.  So, force V1.1 */
    (void)curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
#endif

    /***************************************************************************
        If the passed files exist in the system, then use them for additional
        trusted certificates, and certs to create the TLS connection.
    ***************************************************************************/
		if( check_file_exists(trustStore) )	{
      log_trace("%s::%s(%d) : Setting trustStore to %s",
                    __FILE__, __FUNCTION__, __LINE__,trustStore);
			(void)curl_easy_setopt(curl, CURLOPT_CAINFO, trustStore);
		}

#if defined(__TPM__)
    /* Set the cert based on enroll on startup */
    if( ConfigData->EnrollOnStartup ) {
      log_trace("%s::%s(%d) : Use the bootstrap cert and key", \
        __FILE__, __FUNCTION__, __LINE__);
      log_trace("%s::%s(%d) : Setting clientCert to %s",
        __FILE__, __FUNCTION__, __LINE__, bootstrapCert);
      (void)curl_easy_setopt(curl, CURLOPT_SSLCERT, bootstrapCert);
      log_trace("%s::%s(%d) : Setting bootstrapKey to %s",
        __FILE__, __FUNCTION__, __LINE__, bootstrapKey);
      (void)curl_easy_setopt(curl, CURLOPT_SSLKEY, bootstrapKey);
      if ( bootstrapPW ) {
        log_trace("%s::%s(%d) : Setting clientPassword to %s",
        __FILE__, __FUNCTION__, __LINE__,bootstrapPW);
        (void)curl_easy_setopt(curl, CURLOPT_KEYPASSWD, bootstrapPW);
      }
    } else {
      log_trace("%s::%s(%d) : Use the Agent cert and key", \
        __FILE__, __FUNCTION__, __LINE__);
      if( check_file_exists(clientCert) ) {
      log_trace("%s::%s(%d) : Setting clientCert to %s",
        __FILE__, __FUNCTION__, __LINE__,clientCert);
      (void)curl_easy_setopt(curl, CURLOPT_SSLCERT, clientCert);
      }
      if( check_file_exists(clientKey) ) {
        log_trace("%s::%s(%d) : Setting clientKey to %s",
          __FILE__, __FUNCTION__, __LINE__,clientKey);
        (void)curl_easy_setopt(curl, CURLOPT_SSLKEY, clientKey);
      }
      if( check_file_exists(clientKey) && clientKeyPass ) {
      log_trace("%s::%s(%d) : Setting clientPassword to %s",
        __FILE__, __FUNCTION__, __LINE__,clientKeyPass);
      (void)curl_easy_setopt(curl, CURLOPT_KEYPASSWD, clientKeyPass);
      }
    }   
#else
		if( check_file_exists(clientCert) )	{
      log_trace("%s::%s(%d) : Setting clientCert to %s",
        __FILE__, __FUNCTION__, __LINE__,clientCert);
			(void)curl_easy_setopt(curl, CURLOPT_SSLCERT, clientCert);
		}
		if( check_file_exists(clientKey) ) {
      log_trace("%s::%s(%d) : Setting clientKey to %s",
        __FILE__, __FUNCTION__, __LINE__,clientKey);
			(void)curl_easy_setopt(curl, CURLOPT_SSLKEY, clientKey);
		}
		if( check_file_exists(clientKey) && clientKeyPass )	{
      log_trace("%s::%s(%d) : Setting clientPassword to %s",
        __FILE__, __FUNCTION__, __LINE__,clientKeyPass);
			(void)curl_easy_setopt(curl, CURLOPT_KEYPASSWD, clientKeyPass);
		}
#endif

		/* Turn on verbose output for tracing */
		if ( is_log_trace() )	{
			(void)curl_easy_setopt( curl, CURLOPT_VERBOSE, 1 );
			(void)curl_easy_setopt( curl, CURLOPT_ERRORBUFFER, errBuff );
			errBuff[0] = 0; // empty the error buffer
		}

		/* send all data to this function  */
		(void)curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		/* we pass our 'chunk' struct to the callback function */
		(void)curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

		struct curl_slist* list = NULL;
    /**************************************************************************
        Set up the HTTP header to tell the API this is standard JSON.
        NOTE: Some versions of Internet Explorer have a problem using
              these headers.
        Also, set the content length header option to the data size.
        //TODO: Error checking, as this is a dynamic memory allocation and any
                on-demand memory allocation needs a verification step.
    ***************************************************************************/
		list = curl_slist_append(NULL, "Content-Type: application/json");
		list = curl_slist_append(list, "Accept: application/json");
		char clBuf[30];
		(void)snprintf(clBuf, 30, "Content-Length: %d", (int)strlen(postData));
		list = curl_slist_append(list, clBuf);

    /**************************************************************************
        Now add the header & data to the HTTP POST request.
    ***************************************************************************/
    (void)curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
		(void)curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData);
    log_trace("%s::%s(%d): postData = %s", \
      __FILE__, __FUNCTION__, __LINE__, postData);
    

    /***************************************************************************
        Make sure the cURL operation succeeded and the HTTP response code
        indicates success. If we are successfull, place the response messagee
        If the cURL operation fails, return the cURL error code.
        If the HTTP response is an error, return the HTTP failure code.
    ***************************************************************************/
		long httpCode = 0;
    int res = CURLE_FAILED_INIT;
    int tries = retryCount;
    /* Begin BL-20654 */
    while (0 < tries)
    {
      res = curl_easy_perform(curl);
      (void)curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &httpCode);
      // if there was an error & we still have tries left to do
      tries--;
      log_verbose("%s::%s(%d): curl resp = %d, httpCode = %ld, tries left = %d",
                  __FILE__, __FUNCTION__, __LINE__,res, httpCode, tries);
      if(((CURLE_OK != res) || (httpCode >= 300)) && (0 < tries))
      {
        log_verbose("%s::%s(%d): Failed curl post. Sleeping %d "
                    "seconds before retry",\
                   __FILE__, __FUNCTION__, __LINE__,retryInterval);
        if ( 0 < retryInterval )
        {
          (void)sleep((unsigned int)retryInterval);
        }
      }
      else
      {
        tries = 0; // exit the loop
      }
    }
    /* End BL-20654 */
		if(res != CURLE_OK)
		{
			/* When tracing, dump the error buffer to stderr */
			if ( is_log_trace() )
			{
				size_t len = strlen( errBuff );
				log_trace( "%s::%s(%d): libcurl: (%d) ", \
          __FILE__, __FUNCTION__, __LINE__, res );
				if ( 0 != len ) {
					log_trace( "%s::%s(%d): %s%s", __FILE__, __FUNCTION__, __LINE__,
									errBuff, ((errBuff[len-1] != '\n') ? "\n" : ""));

				}	else {
					log_trace("%s::%s(%d): %s\n", \
            __FILE__, __FUNCTION__, __LINE__, curl_easy_strerror(res) );
				}
			}
			log_error("%s::%s(%d): %s", \
        __FILE__, __FUNCTION__, __LINE__, curl_easy_strerror(res));
			toReturn = res;
		}	else if(httpCode >= 300) {
			log_error("%s::%s(%d): HTTP Response: %ld", \
        __FILE__, __FUNCTION__, __LINE__, httpCode);
			toReturn = (int)httpCode;
		}	else {
			log_verbose("%s::%s(%d): %lu bytes retrieved -- "
                  "allocating memory for response",\
                  __FILE__, __FUNCTION__, __LINE__, (unsigned long)chunk.size);
			*pRespData = strdup(chunk.memory);
      log_trace("%s::%s(%d): Response is:\n%s",
        __FILE__, __FUNCTION__, __LINE__, *pRespData);
      if ( NULL == *pRespData ) {
        log_error("%s::%s(%d): Out of memory", \
          __FILE__, __FUNCTION__, __LINE__);
        toReturn = 255;
      } else {
			  toReturn = 0;
      }
		}

		// Cleanup, de-allocate, etc.
		if (list) { curl_slist_free_all(list); }
		if (curl) { curl_easy_cleanup(curl); }
		if (chunk.memory) { free(chunk.memory); }
	}

	return toReturn;
} /* http_post_json */
