/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file httpclient.h */
#ifndef __HTTPCLIENT_H__
#define __HTTPCLIENT_H__

#define CONNECTION_TIMEOUT 60

int http_post_json(const char* url, const char* username, const char* password, const char* trustStore, const char* clientCert, \
	const char* clientKey, const char* clientKeyPass, char* postData, char** pRespData, 
	// BL-20654
	int retryCount,
	int retryInterval);

#endif
