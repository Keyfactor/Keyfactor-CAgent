/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <unistd.h>
#include "logging.h"
#include "httpclient.h"
#include "global.h"

#define MODULE "httpclient-"

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	#undef FUNCTION
	#define FUNCTION "WriteMemoryCallback-"
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory! */
    log_error("%s%sout of memory", MODULE, FUNCTION);
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

/***************************************************************************//**
    Check if a file exists
    @param fileName = the filename to look on the filesystem for
    @retval 1 = file exists
    @retval 0 = file isn't there or other error
*/
/******************************************************************************/
int check_file_exists( const char *fileName )
{
  FILE *fp;
  if ( (fp = fopen( fileName, "r")) )
  {
    fclose(fp);
    return 1;
  }
  else
  {
    return 0;
  }
} // file_exists

/***************************************************************************//**
    Issue an HTTP POST command stating that the content is JSON and that a
    JSON response is accepted.
    @param url = a string with the URL address to contact
    @param username = a string with the username to log into the URL address
    @param password = a string with password to log into the URL address
    @param trustStore = a string with a filename containing additional
                        trusted certificates
    @param clientCert = a string with a filename containing a CA signed
                        cert for this platform (for TLS communication)
    @param clientKey = a string with a filename containing the private key
                       associated with the clientCert
    @param clientKeyPass = a string with the password associated with the
                           clientKey
    @param postData = a JSON string
    @param pRespData = a pointer to a string where the HTTP response
                       data gets set.  NOTE: This memory gets DYNAMICALLY
                       allocated here!  You need to properly dispose of it in
                       the calling function.
    @retval 0 on successfull completion
    @retval 1-99 corresponding to the failed cURL response code
    @retval 255 if the dynamic memory allocation for pRespData fails
    @retval 300-511 The HTTP response error (e.g. 404 Not Found)
*/
/******************************************************************************/
int http_post_json(const char* url, const char* username,
                   const char* password, const char* trustStore,
                   const char* clientCert, const char* clientKey,
                   const char* clientKeyPass,
                   char* postData,
                   char** pRespData)
{
	#undef FUNCTION
	#define FUNCTION "http_post_json-"
	int toReturn = -1;
	CURL* curl = curl_easy_init();
	char errBuff[CURL_ERROR_SIZE];
	if(curl)
	{
		struct MemoryStruct chunk;
		chunk.memory = malloc(1);
    if ( !chunk.memory )
    {
      log_error("%s%sOut of memory when allocating chunk",MODULE,FUNCTION);
      return CURLE_FAILED_INIT;
    }
		chunk.size = 0;

#ifdef __TPM__
    /***************************************************************************
        When a TPM is used, the clientKey is an encrypted BLOB.  The BLOB can
        only be decoded inside the TPM.  Tell cURL that this is the case &
        use the engine_id global variable.  This is usually the tpm2tss engine.
    ***************************************************************************/
    log_verbose("%s%s-Setting cURL to use TPM as SSL Engine %s",
                  MODULE,FUNCTION, engine_id);
    int errNum = curl_easy_setopt(curl, CURLOPT_SSLENGINE, engine_id);
    if ( CURLE_OK != errNum )
    {
      /* When tracing, dump the error buffer to stderr */
			if ( is_log_trace() )
			{
				size_t len = strlen( errBuff );
				log_trace( "%s%s-libcurl: (%d) ", MODULE, FUNCTION, errNum );
				if ( len )
				{
					log_trace( "%s%s-%s%s", MODULE, FUNCTION,
									errBuff, ((errBuff[len-1] != '\n') ? "\n" : ""));

				}
				else
				{
					log_trace("%s%s-%s\n", MODULE, FUNCTION, curl_easy_strerror(errNum) );
				}
			}
			log_error("%s%shttp-http_post_json-%s", MODULE, FUNCTION,
                                        curl_easy_strerror(errNum));

  		curl_easy_cleanup(curl);
      return errNum;
    }

    log_verbose("%s%s-Setting cURL to use TPM as the default SSL Engine %s",
                  MODULE,FUNCTION, engine_id);
    errNum = curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
    if ( CURLE_OK != errNum )
    {
      /* When tracing, dump the error buffer to stderr */
      if ( is_log_trace() )
      {
        size_t len = strlen( errBuff );
        log_trace( "%s%s-libcurl: (%d) ", MODULE, FUNCTION, errNum );
        if ( len )
        {
          log_trace( "%s%s-%s%s", MODULE, FUNCTION,
                  errBuff, ((errBuff[len-1] != '\n') ? "\n" : ""));

        }
        else
        {
          log_trace("%s%s-%s\n", MODULE, FUNCTION, curl_easy_strerror(errNum) );
        }
      }
      log_error("%s%shttp-http_post_json-%s", MODULE, FUNCTION,
                                        curl_easy_strerror(errNum));

      curl_easy_cleanup(curl);
      return errNum;
    }

    log_verbose("%s%s-Setting cURL to have keytype as engine",
                  MODULE,FUNCTION);
    errNum = curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "ENG");
    if ( CURLE_OK != errNum )
    {
      /* When tracing, dump the error buffer to stderr */
      if ( is_log_trace() )
      {
        size_t len = strlen( errBuff );
        log_trace( "%s%s-libcurl: (%d) ", MODULE, FUNCTION, errNum );
        if ( len )
        {
          log_trace( "%s%s-%s%s", MODULE, FUNCTION,
                  errBuff, ((errBuff[len-1] != '\n') ? "\n" : ""));

        }
        else
        {
          log_trace("%s%s-%s\n", MODULE, FUNCTION, curl_easy_strerror(errNum) );
        }
      }
      log_error("%s%shttp-http_post_json-%s", MODULE, FUNCTION,
                                        curl_easy_strerror(errNum));

      curl_easy_cleanup(curl);
      return errNum;
    }
#endif

    /***************************************************************************
        Set up curl to POST to a secure url using the username and Password
        passed to the function
    ***************************************************************************/
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_USERNAME, username);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);

    /***************************************************************************
        If the passed files exist in the system, then use them for additional
        trusted certificates, and certs to create the TLS connection.

        //TODO: Add error checking
    ***************************************************************************/
		if( check_file_exists(trustStore) )
		{
      log_trace("%s%sSetting trustStore to %s",
                    MODULE,FUNCTION,trustStore);
			curl_easy_setopt(curl, CURLOPT_CAINFO, trustStore);
		}
		if( check_file_exists(clientCert) )
		{
      log_trace("%s%sSetting clientCert to %s",
                    MODULE,FUNCTION,clientCert);
			curl_easy_setopt(curl, CURLOPT_SSLCERT, clientCert);
		}
		if( check_file_exists(clientKey) )
		{
      log_trace("%s%sSetting clientKey to %s",
                    MODULE,FUNCTION,clientKey);
			curl_easy_setopt(curl, CURLOPT_SSLKEY, clientKey);
		}
		if( check_file_exists(clientKey) && clientKeyPass )
		{
      log_trace("%s%sSetting clientPassword to %s",
                    MODULE,FUNCTION,clientKeyPass);
			curl_easy_setopt(curl, CURLOPT_KEYPASSWD, clientKeyPass);
		}

		/* Turn on verbose output for tracing */
		if ( is_log_trace() )
		{
			curl_easy_setopt( curl, CURLOPT_VERBOSE, 1 );
			curl_easy_setopt( curl, CURLOPT_ERRORBUFFER, errBuff );
			errBuff[0] = 0; // empty the error buffer
		}

		/* send all data to this function  */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		/* we pass our 'chunk' struct to the callback function */
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

		struct curl_slist* list = NULL;
    /**************************************************************************
        Set up the HTTP header to tell the API this is standard JSON.
        NOTE: Some versions of Internet Explorer have a problem using
              these headers.
        Also, set the content length header option to the data size.
        //TODO: Error checking, as this is a dynamic memory allocation and any
                on-demand memory allocation needs a verification step.
    ***************************************************************************/
		list = curl_slist_append(list, "Content-Type: application/json");
		list = curl_slist_append(list, "Accept: application/json");
		char clBuf[30];
		sprintf(clBuf, "Content-Length: %d", (int)strlen(postData));
		list = curl_slist_append(list, clBuf);

    /**************************************************************************
        Now add the header & data to the HTTP POST request & execute it.
    ***************************************************************************/
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData);
		int res = curl_easy_perform(curl);

    /***************************************************************************
        Make sure the cURL operation succeeded and the HTTP response code
        indicates success. If we are successfull, place the response messagee
        If the cURL operation fails, return the cURL error code.
        If the HTTP response is an error, return the HTTP failure code.
    ***************************************************************************/
		long httpCode = 0;
		curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &httpCode);
		if(res != CURLE_OK)
		{
			/* When tracing, dump the error buffer to stderr */
			if ( is_log_trace() )
			{
				size_t len = strlen( errBuff );
				log_trace( "%s%s-libcurl: (%d) ", MODULE, FUNCTION, res );
				if ( len )
				{
					log_trace( "%s%s-%s%s", MODULE, FUNCTION,
									errBuff, ((errBuff[len-1] != '\n') ? "\n" : ""));

				}
				else
				{
					log_trace("%s%s-%s\n", MODULE, FUNCTION, curl_easy_strerror(res) );
				}
			}
			log_error("%s%shttp-WriteMemoryCallback-%s", MODULE, FUNCTION,
                                                      curl_easy_strerror(res));
			toReturn = res;
		}
		else if(httpCode >= 300)
		{
			log_error("%s%sHTTP Response: %ld", MODULE, FUNCTION, httpCode);
			toReturn = httpCode;
		}
		else
		{
			log_verbose("%s%s%lu bytes retrieved -- allocating memory for response",
                        MODULE, FUNCTION, chunk.size);
      //TODO: - Following might not be portable, currently compiling with GNU99?
			*pRespData = strdup(chunk.memory);
      if ( NULL == *pRespData )
      {
        log_error("%s%sOut of memory",MODULE,FUNCTION);
        toReturn = 255;
      }
      else
      {
			  toReturn = 0;
      }
		}

		// Cleanup, de-allocate, etc.
		curl_slist_free_all(list);
		curl_easy_cleanup(curl);

		free(chunk.memory);
	}

	return toReturn;
} // http_post_json
