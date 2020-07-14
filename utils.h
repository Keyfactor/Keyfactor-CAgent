/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#ifndef UTILS_H_
#define UTILS_H_

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/x509.h>
#else
#include <openssl/x509.h>
#endif

#include <stdbool.h>

char* hex_encode(unsigned char* inBuf, int len);

char* compute_thumbprint(X509* cert);

bool is_cert_key_match(X509* cert, EVP_PKEY* key);

int append_line(char** msg, const char* line);

int append_linef(char** msg, const char* fmt, ...) __attribute__ ((format (printf, 2, 3)));

int backup_file(const char* file);

int restore_file(const char* file);

int read_file_bytes(const char* srcPath, unsigned char** pFileBytes, size_t* fileLen);

int replace_file(const char* file, const char* contents, long len, bool backup);

void to_lower_case( char s[], const int len );

int byte_to_hex_string( char hexStr[],
					 int stringSize,
					 unsigned char byteData[],
					 int byteSize );

void util_strip_string(char* fromString, const char* stripString);
#endif /* UTILS_H_ */
