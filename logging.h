/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file logging.h */
#ifndef LOGGING_H_
#define LOGGING_H_

#include <stdbool.h>
	
void log_error(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

void log_info(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

void log_verbose(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

void log_debug(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

void log_trace(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

void log_set_trace(bool param);
void log_set_debug(bool param);
void log_set_verbosity(bool param);
void log_set_info(bool param);
void log_set_error(bool param);
void log_set_off(bool param);

bool is_log_off( void );
bool is_log_error( void );
bool is_log_info( void );
bool is_log_verbose( void );
bool is_log_debug( void );
bool is_log_trace( void );

#endif /* LOGGING_H_ */
