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

#ifndef UTILS_H_
#define UTILS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

char* hex_encode(unsigned char* inBuf, int len);

int append_line(char** msg, const char* line);

int append_linef(char** msg, 
	const char* fmt, ...) __attribute__ ((format (printf, 2, 3)));

int backup_file(const char* file);

int restore_file(const char* file);

int read_file_bytes(const char* srcPath, unsigned char** pFileBytes, 
	size_t* fileLen);

int replace_file(const char* file, const char* contents, long len, bool backup);

void to_lower_case( char s[], const int len );

int byte_to_hex_string( char hexStr[], int stringSize, 
	unsigned char byteData[], int byteSize );

char* util_strip_string(const char* fromString, const char* stripString);
char* bstrcat(const char* s1, const char* s2);
int file_exists( const char *file );
bool is_directory( const char *file );
char* get_prefix_substring(const char* string, const char find);

#endif /* UTILS_H_ */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/