/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file utils.h */
#ifndef UTILS_H_
#define UTILS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

char* hex_encode(unsigned char* inBuf, int len);

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

char* util_strip_string(const char* fromString, const char* stripString);

/**																*/
/* Better string concatenation vs the mess that is ANSI C 		*/
/* 																*/
/* @param  - [Input] s1 = null terminated string to pre-pend 	*/
/* @param  - [Input] s2 = null terminated string to append 		*/
/* @return - failure: NULL 										*/
/*           success: ptr to the new string 					*/
/** 															*/
char* bstrcat(const char* s1, const char* s2);

/* BEGIN GM Specific */
/**
 * GM Specific
 * Convert the numbers in the VIN or ECU into characters
 *
 * @param  - [Output] outString : The string to hold the destination
 *                    NOTE: The output string must be longer than the
 *                    length by 1 or more.  this is not validated here.
 * @param  - [Input] id : The VIN or ECU id
 * @param  - [Input] len : The length of the VIN or ID in bytes
 * @return - success : A string (null terminated) representing the ID
 *           failure : NULL
 */
char* convert_GMid(uint8_t* id, uint8_t len);
/* END GM Specific */

#endif /* UTILS_H_ */
