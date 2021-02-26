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

int file_exists( const char *file );

/******************************************************************************/
/** @fn is_directory( const char *file )
	@brief checks if a string is really a directory
	@param const char *file = path and filename of file to check
	@returns true if file is actually a directory
	         false if the file is actually a file
*/
/******************************************************************************/
bool is_directory( const char *file );

/**
 * Return a substring that is everything up to the last character to find
 * 
 * NOTE: Memory is allocated by this function & must be deallocated by the
 *       calling function.
 *
 * @param  - [Input] string = the null terminated string to search
 * @param  - [Input] find = the character to search within the string
 * @return - The substring of the string parameter up to the character to find
 *           NULL if the character is not found
 */
char* get_prefix_substring(const char* string, const char find);

#endif /* UTILS_H_ */
