/******************************************************************************/
/* Copyright 2021 Keyfactor                                                   */
/* Licensed under the Apache License, Version 2.0 (the "License"); you may    */
/* not use this file except in compliance with the License.  You may obtain a */
/* copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless */
/* required by applicable law or agreed to in writing, software distributed   */
/* under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   */
/* OR CONDITIONS OF ANY KIND, either express or implied. See the License for  */
/* the specific language governing permissions and limitations under the      */
/* License.                                                                   */
/******************************************************************************/
/* @file httpclient.c                                                         */
/*                                                                            */
/* Provides http_post_json(), the single HTTP transport function used by the  */
/* agent to communicate with the Keyfactor platform.                          */
/*                                                                            */
/* Internal structure:                                                        */
/*   setup_curl_handle()    -- init, error buffer, timeouts, HTTP version     */
/*   apply_basic_auth()     -- optional username/password                     */
/*   apply_trust_store()    -- optional CA bundle                             */
/*   apply_client_cert()    -- bootstrap or agent mTLS cert + key             */
/*   build_request_headers()-- Content-Type/Accept/Content-Length slist       */
/*   attach_post_body()     -- POSTFIELDS + write callback                    */
/*   execute_with_retry()   -- perform loop, HTTP code check, response alloc  */
/******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include "constants.h"

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

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/*                                                                            */
/* Response accumulator passed as userdata to WriteMemoryCallback.           */
/* memory: heap buffer grown by realloc as chunks arrive.                    */
/* size:   total bytes written so far (excludes the null terminator).        */
/*                                                                            */
struct MemoryStruct {
    char  *memory;
    size_t size;
};

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/*                                                                            */
/* Log a cURL setup error, clean up the handle, and return the error code.  */
/*                                                                            */
/* errBuff must have been registered with CURLOPT_ERRORBUFFER before calling */
/* this function; if it has not yet been populated it will be empty and the  */
/* strerror fallback will be used instead.                                   */
/*                                                                            */
/* @param curl    - CURL handle to clean up (must not be NULL)               */
/* @param errNum  - CURLcode that triggered the error                        */
/* @param errBuff - buffer registered via CURLOPT_ERRORBUFFER                */
/* @return errNum (pass-through for single-expression callers)               */
/*                                                                            */
static int handle_curl_error(CURL *curl, int errNum, const char *errBuff)
{
    if (is_log_trace() && errBuff && errBuff[0] != '\0') {
        size_t len = strlen(errBuff);
        log_error("%s::%s(%d) : libcurl (%d): %s%s", LOG_INF, errNum,
                  errBuff, (errBuff[len - 1] != '\n') ? "\n" : "");
    } else {
        log_error("%s::%s(%d) : libcurl (%d): %s", LOG_INF, errNum,
                  curl_easy_strerror(errNum));
    }
    curl_easy_cleanup(curl);
    return errNum;
} /* handle_curl_error */

/*                                                                            */
/* curl write callback — appends each received chunk to a MemoryStruct.     */
/* Registered via CURLOPT_WRITEFUNCTION / CURLOPT_WRITEDATA.                */
/*                                                                            */
/* @return bytes consumed; returning 0 signals an error to libcurl           */
/*                                                                            */
static size_t WriteMemoryCallback(const void *contents, const size_t size,
                                   const size_t nmemb, const void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        log_error("%s::%s(%d) : Out of memory in write callback", LOG_INF);
        return 0;
    }
    mem->memory = ptr;
    memcpy(&mem->memory[mem->size], contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = '\0';
    return realsize;
} /* WriteMemoryCallback */

/*                                                                            */
/* Strip newline characters ('\n') from a cert string in-place.             */
/* Used before embedding a PEM cert in an HTTP header value.                */
/* Bounded by MAX_CERT_SIZE to guard against unterminated input.            */
/*                                                                            */
static void stripNewlines(char *string)
{
    size_t x = 0, y = 0;
    while (string[x] != '\0' && x < MAX_CERT_SIZE) {
        if (string[x] != '\n')
            string[y++] = string[x];
        x++;
    }
    string[y] = '\0';
} /* stripNewlines */

/*----------------------------------------------------------------------------*/
/* CURL SETUP HELPERS                                                         */
/*----------------------------------------------------------------------------*/

/*                                                                            */
/* Initialise the curl handle with core POST options: URL, error buffer,     */
/* connect timeout, HTTP version, and verbose tracing if enabled.            */
/*                                                                            */
/* @param curl    - freshly initialised CURL handle                          */
/* @param url     - target URL                                               */
/* @param errBuff - CURL_ERROR_SIZE buffer, zeroed by caller                 */
/* @return CURLE_OK or a CURLcode on failure (handle already cleaned up)     */
/*                                                                            */
static int setup_curl_handle(CURL *curl, const char *url, char *errBuff)
{
    int errNum;

    /* Register the error buffer first so every subsequent error captures it */
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errBuff);

    errNum = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

    errNum = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

    errNum = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);
    if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

#ifdef __HTTP_1_1__
    /* Some OpenSSL builds default to HTTP/2; force 1.1 when required */
    errNum = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);
#endif

    if (is_log_trace()) {
        log_trace("%s::%s(%d) : Enabling cURL verbose output", LOG_INF);
        errNum = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);
    }

    return CURLE_OK;
} /* setup_curl_handle */

/*                                                                            */
/* Apply HTTP basic auth credentials to the curl handle.                    */
/* Both username and password must be non-NULL; otherwise auth is skipped.  */
/*                                                                            */
static int apply_basic_auth(CURL *curl, const char *username,
                             const char *password, char *errBuff)
{
    if (!username || !password) {
        log_trace("%s::%s(%d) : No basic auth credentials supplied — skipping",
                  LOG_INF);
        return CURLE_OK;
    }

    int errNum;
    log_trace("%s::%s(%d) : Configuring basic auth", LOG_INF);

    errNum = curl_easy_setopt(curl, CURLOPT_USERNAME, username);
    if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

    errNum = curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
    if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

    return CURLE_OK;
} /* apply_basic_auth */

/*                                                                            */
/* Configure an additional CA bundle for peer certificate verification.     */
/* If the file does not exist the system default trust store is used.       */
/*                                                                            */
static int apply_trust_store(CURL *curl, const char *trustStore, char *errBuff)
{
    if (!file_exists(trustStore)) {
        log_trace("%s::%s(%d) : Trust store not found — using system default",
                  LOG_INF);
        return CURLE_OK;
    }

    log_trace("%s::%s(%d) : Setting trust store: %s", LOG_INF, trustStore);
    int errNum = curl_easy_setopt(curl, CURLOPT_CAINFO, trustStore);
    if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

    return CURLE_OK;
} /* apply_trust_store */

/*                                                                            */
/* Configure mTLS client certificate and key on the curl handle.            */
/*                                                                            */
/* Selects bootstrap credentials when EnrollOnStartup + UseBootstrapCert    */
/* are both set; otherwise uses the agent cert/key passed by the caller.    */
/* If the configuration indicates no cert should be used, returns CURLE_OK  */
/* immediately without modifying the handle.                                */
/*                                                                            */
/* @param curl          - curl handle to configure                           */
/* @param clientCert    - agent cert path (ignored during bootstrap)         */
/* @param clientKey     - agent key path (ignored during bootstrap)          */
/* @param clientKeyPass - agent key password, may be NULL                   */
/* @param pCertBytes    - out: heap copy of the cert PEM for header use,    */
/*                        or unchanged if not needed. Caller must free.     */
/* @param errBuff       - curl error buffer                                  */
/* @return CURLE_OK, a CURLcode, or CURLE_OUT_OF_MEMORY                    */
/*                                                                            */
static int apply_client_cert(CURL *curl, const char *clientCert,
                              const char *clientKey, const char *clientKeyPass,
                              unsigned char **pCertBytes, char *errBuff)
{
    const char *certPath = NULL;
    const char *keyPath  = NULL;
    const char *keyPass  = NULL;
    int errNum;

    if (ConfigData->EnrollOnStartup) {
        if (!ConfigData->UseBootstrapCert) {
            log_info("%s::%s(%d) : Bypassing client cert on initial enrollment",
                     LOG_INF);
            return CURLE_OK;
        }
        log_trace("%s::%s(%d) : Using bootstrap cert and key", LOG_INF);
        certPath = ConfigData->BootstrapCert;
        keyPath  = ConfigData->BootstrapKey;
        keyPass  = ConfigData->BootstrapKeyPassword;
    } else {
        if (!ConfigData->UseAgentCert) {
            log_verbose("%s::%s(%d) : Configured to not use agent cert", LOG_INF);
            return CURLE_OK;
        }
        log_trace("%s::%s(%d) : Using agent cert and key", LOG_INF);
        certPath = clientCert;
        keyPath  = clientKey;
        keyPass  = clientKeyPass;
    }

    /* Client certificate */
    if (file_exists(certPath)) {
        log_trace("%s::%s(%d) : Setting client cert: %s", LOG_INF, certPath);
        errNum = curl_easy_setopt(curl, CURLOPT_SSLCERT, certPath);
        if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

        size_t dummySize = 0;
        read_file_bytes(certPath, pCertBytes, &dummySize);
        if (!*pCertBytes) {
            log_error("%s::%s(%d) : Out of memory reading client certificate",
                      LOG_INF);
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        log_warn("%s::%s(%d) : Client cert not found at %s", LOG_INF, certPath);
    }

    /* Client private key */
    if (file_exists(keyPath)) {
        log_trace("%s::%s(%d) : Setting client key: %s", LOG_INF, keyPath);
        errNum = curl_easy_setopt(curl, CURLOPT_SSLKEY, keyPath);
        if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

        if (keyPass) {
            log_trace("%s::%s(%d) : Setting client key password", LOG_INF);
            errNum = curl_easy_setopt(curl, CURLOPT_KEYPASSWD, keyPass);
            if (CURLE_OK != errNum)
                return handle_curl_error(curl, errNum, errBuff);
        }
    } else {
        log_warn("%s::%s(%d) : Client key not found at %s", LOG_INF, keyPath);
    }

    return CURLE_OK;
} /* apply_client_cert */

#if defined(__TPM__)
/*                                                                            */
/* Configure the TPM2 SSL engine on the curl handle.                        */
/* Only called when __TPM__ is defined and EnrollOnStartup is false.        */
/*                                                                            */
static int apply_tpm_engine(CURL *curl, char *errBuff)
{
    int errNum;
    log_verbose("%s::%s(%d) : Configuring TPM2 SSL engine: %s",
                LOG_INF, engine_id);

    errNum = curl_easy_setopt(curl, CURLOPT_SSLENGINE, engine_id);
    if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

    errNum = curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
    if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

    errNum = curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "ENG");
    if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

    errNum = curl_easy_setopt(curl, CURLOPT_KEYPASSWD, "");
    if (CURLE_OK != errNum) return handle_curl_error(curl, errNum, errBuff);

    return CURLE_OK;
} /* apply_tpm_engine */
#endif /* __TPM__ */

/*                                                                            */
/* Build the HTTP request header slist: Content-Type, Accept,               */
/* Content-Length, and optionally the client cert header.                   */
/*                                                                            */
/* @param postData  - the JSON body (used only to compute Content-Length)   */
/* @param certBytes - PEM cert bytes to embed in header, or NULL to skip    */
/* @return allocated slist on success, NULL on failure                      */
/*                                                                            */
static struct curl_slist *build_request_headers(const char *postData,
                                                 const unsigned char *certBytes)
{
    struct curl_slist *list = NULL;

    list = curl_slist_append(NULL, "Content-Type: application/json");
    list = curl_slist_append(list, "Accept: application/json");

    char clBuf[30];
    (void)snprintf(clBuf, sizeof(clBuf), "Content-Length: %d",
                   (int)strlen(postData));
    list = curl_slist_append(list, clBuf);

    if (add_client_cert_to_header && certBytes) {
        log_debug("%s::%s(%d) : Adding client cert to %s header",
                  LOG_INF, CLIENT_CERT_HEADER);
        /* Copy into a local buffer so stripNewlines does not modify the    */
        /* original cert bytes, which may be needed for error reporting.    */
        char certBuf[MAX_CERT_SIZE];
        strncpy(certBuf, (const char *)certBytes, sizeof(certBuf) - 1);
        certBuf[sizeof(certBuf) - 1] = '\0';
        stripNewlines(certBuf);

        char headerBuf[MAX_CERT_SIZE + 32];
        (void)snprintf(headerBuf, sizeof(headerBuf), "%s: %s",
                       CLIENT_CERT_HEADER, certBuf);
        list = curl_slist_append(list, headerBuf);
    } else {
        log_debug("%s::%s(%d) : Skipping %s header", LOG_INF,
                  CLIENT_CERT_HEADER);
    }

    return list;
} /* build_request_headers */

/*                                                                            */
/* Attach the POST body and write callback to the curl handle, then set     */
/* the pre-built header slist.                                               */
/*                                                                            */
/* Takes ownership of list on success; on failure list is freed here and    */
/* the caller should not free it again.                                      */
/*                                                                            */
static int attach_post_body(CURL *curl, char *postData,
                             struct curl_slist *list,
                             struct MemoryStruct *chunk, char *errBuff)
{
    int errNum = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    if (CURLE_OK != errNum) goto fail;

    errNum = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)chunk);
    if (CURLE_OK != errNum) goto fail;

    errNum = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    if (CURLE_OK != errNum) goto fail;

    errNum = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData);
    if (CURLE_OK != errNum) goto fail;

    errNum = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (int)strlen(postData));
    if (CURLE_OK != errNum) goto fail;

#ifdef __QATESTING__
    log_qa("%s::%s(%d) : postData = %s", LOG_INF, postData);
#else
    log_trace("%s::%s(%d) : postData = %s", LOG_INF, postData);
#endif

    return CURLE_OK;

fail:
    curl_slist_free_all(list);
    return handle_curl_error(curl, errNum, errBuff);
} /* attach_post_body */

/*                                                                            */
/* Execute the curl request with retry logic, check the HTTP response code, */
/* and allocate the response string on success.                             */
/*                                                                            */
/* The retry sleep is applied before each attempt after the first, so a     */
/* retryCount of 1 makes exactly one attempt with no sleep.                 */
/* A retryCount <= 0 is treated as 1 (at least one attempt always occurs).  */
/*                                                                            */
/* @param curl          - fully configured curl handle                       */
/* @param retryCount    - total number of attempts                           */
/* @param retryInterval - seconds between attempts                           */
/* @param chunk         - response accumulator populated by the callback     */
/* @param pRespData     - out: heap-allocated response body on success       */
/* @param errBuff       - curl error buffer                                  */
/* @return 0            on success                                           */
/*         1-99         CURLcode on transport failure                        */
/*         255          out of memory allocating *pRespData                 */
/*         300-511      HTTP error response code                             */
/*                                                                            */
static int execute_with_retry(CURL *curl, int retryCount, int retryInterval,
                               struct MemoryStruct *chunk, char **pRespData,
                               char *errBuff)
{
    int res = CURLE_FAILED_INIT;
    long httpCode = 0;
    int attempts = (retryCount > 0) ? retryCount : 1;

    for (int i = 0; i < attempts; i++) {
        if (i > 0 && retryInterval > 0) {
            log_verbose("%s::%s(%d) : Retry %d/%d — sleeping %d seconds",
                        LOG_INF, i + 1, attempts, retryInterval);
            (void)sleep((unsigned int)retryInterval);
        }

        res = curl_easy_perform(curl);
        (void)curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &httpCode);
        log_verbose("%s::%s(%d) : Attempt %d/%d — curl=%d httpCode=%ld",
                    LOG_INF, i + 1, attempts, res, httpCode);

        if (CURLE_OK == res && httpCode < 300)
            break;
    }

    /* Evaluate final outcome */
    if (CURLE_OK != res) {
        if (is_log_trace() && errBuff[0] != '\0') {
            size_t len = strlen(errBuff);
            log_error("%s::%s(%d) : libcurl (%d): %s%s", LOG_INF, res,
                      errBuff, (errBuff[len - 1] != '\n') ? "\n" : "");
        } else {
            log_error("%s::%s(%d) : libcurl (%d): %s", LOG_INF, res,
                      curl_easy_strerror(res));
        }
        return res;
    }

    if (httpCode >= 300) {
        log_error("%s::%s(%d) : HTTP error: %ld", LOG_INF, httpCode);
        return (int)httpCode;
    }

    log_verbose("%s::%s(%d) : %lu bytes received", LOG_INF,
                (unsigned long)chunk->size);
    *pRespData = strdup(chunk->memory);
    if (!*pRespData) {
        log_error("%s::%s(%d) : Out of memory allocating response", LOG_INF);
        return 255;
    }

#ifdef __QATESTING__
    log_qa("%s::%s(%d) : Response:\n%s", LOG_INF, *pRespData);
#else
    log_trace("%s::%s(%d) : Response:\n%s", LOG_INF, *pRespData);
#endif

    return 0;
} /* execute_with_retry */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/*                                                                            */
/* Issue an HTTP POST with JSON content and accept headers, with optional    */
/* basic auth, trust store, and mTLS client certificate.                    */
/*                                                                            */
/* @param url           - URL to POST to                                     */
/* @param username      - basic auth username, or NULL to skip               */
/* @param password      - basic auth password, or NULL to skip               */
/* @param trustStore    - path to CA bundle file, or NULL to use system      */
/* @param clientCert    - path to client certificate file                    */
/* @param clientKey     - path to client private key file                    */
/* @param clientKeyPass - password for client key, or NULL                  */
/* @param postData      - null-terminated JSON string to POST               */
/* @param pRespData     - out: dynamically allocated response body;          */
/*                        caller must free on success                        */
/* @param retryCount    - total number of attempts (clamped to min 1)       */
/* @param retryInterval - seconds to wait between attempts                  */
/* @return 0            on success                                           */
/*         1-99         cURL error code                                      */
/*         255          response memory allocation failure                   */
/*         300-511      HTTP error response code                             */
/*                                                                            */
int http_post_json(const char *url, const char *username,
                   const char *password, const char *trustStore,
                   const char *clientCert, const char *clientKey,
                   const char *clientKeyPass, char *postData,
                   char **pRespData, int retryCount, int retryInterval)
{
    log_info("%s::%s(%d) : Preparing to POST to %s", LOG_INF, url);

    int toReturn = CURLE_FAILED_INIT;
    unsigned char *client_cert_bytes = NULL;
    char errBuff[CURL_ERROR_SIZE];
    errBuff[0] = '\0';

    struct MemoryStruct chunk = { .memory = calloc(1, 1), .size = 0 };
    if (!chunk.memory) {
        log_error("%s::%s(%d) : Out of memory allocating response buffer",
                  LOG_INF);
        return CURLE_FAILED_INIT;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        log_error("%s::%s(%d) : curl_easy_init() failed", LOG_INF);
        free(chunk.memory);
        return CURLE_FAILED_INIT;
    }

    /* ------------------------------------------------------------------ */
    /* Step 1: Core handle options (URL, timeout, HTTP version, verbose)  */
    /* ------------------------------------------------------------------ */
    toReturn = setup_curl_handle(curl, url, errBuff);
    if (CURLE_OK != toReturn) goto exit;

    /* ------------------------------------------------------------------ */
    /* Step 2: TPM engine (compiled out on non-TPM builds)                */
    /* ------------------------------------------------------------------ */
#if defined(__TPM__)
    if (!ConfigData->EnrollOnStartup) {
        toReturn = apply_tpm_engine(curl, errBuff);
        if (CURLE_OK != toReturn) goto exit;
    } else {
        log_info("%s::%s(%d) : Skipping TPM setup — enroll on startup active",
                 LOG_INF);
    }
#endif

    /* ------------------------------------------------------------------ */
    /* Step 3: Authentication and TLS material                            */
    /* ------------------------------------------------------------------ */
    toReturn = apply_basic_auth(curl, username, password, errBuff);
    if (CURLE_OK != toReturn) goto exit;

    toReturn = apply_trust_store(curl, trustStore, errBuff);
    if (CURLE_OK != toReturn) goto exit;

    toReturn = apply_client_cert(curl, clientCert, clientKey, clientKeyPass,
                                 &client_cert_bytes, errBuff);
    if (CURLE_OK != toReturn) goto exit;

    /* ------------------------------------------------------------------ */
    /* Step 4: Build headers and attach POST body                         */
    /* ------------------------------------------------------------------ */
    struct curl_slist *list = build_request_headers(postData, client_cert_bytes);
    if (!list) {
        log_error("%s::%s(%d) : Failed to build request headers", LOG_INF);
        toReturn = CURLE_OUT_OF_MEMORY;
        goto exit;
    }

    toReturn = attach_post_body(curl, postData, list, &chunk, errBuff);
    if (CURLE_OK != toReturn) goto exit;  /* list already freed by attach_post_body on failure */

    /* ------------------------------------------------------------------ */
    /* Step 5: Execute with retry and harvest response                    */
    /* ------------------------------------------------------------------ */
    toReturn = execute_with_retry(curl, retryCount, retryInterval,
                                  &chunk, pRespData, errBuff);

exit:
    curl_easy_cleanup(curl);
    free(chunk.memory);
    if (client_cert_bytes)
        free(client_cert_bytes);
    return toReturn;
} /* http_post_json */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
