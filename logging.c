/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "logging.h"

#define LOG_HEAD_SIZE 50
#define LOG_LEVEL_SIZE 10

#define ERRORLVL   "[ERROR]  "
#define INFOLVL    "[INFO]   "
#define VERBOSELVL "[VERBOSE]"
#define DEBUGLVL   "[DEBUG]  "
#define TRACELVL   "[TRACE]  "

static bool _trace = false;
static bool _debug = false;
static bool _verbose = false;
static bool _info = false;
static bool _error = true; // default logging level

#define MODULE "logging-"

/******************************************************************************/
/** @fn is_log_verbose
	@brief check the current state of the verbose logging level
	@param none
	@returns true if verbose level is enabled, false otherwise
*/
/******************************************************************************/
bool is_log_verbose( void )
{
	return _verbose;
}

/******************************************************************************/
/** @fn is_log_trace
	@brief check the current state of the trace logging level
	@param none
	@returns true if trace level is enabled, false otherwise
*/
/******************************************************************************/
bool is_log_trace( void )
{
	return _trace;
}

/******************************************************************************/
/** @fn is_log_debug
	@brief check the current state of the debug logging level
	@param none
	@returns true if debug level is enabled, false otherwise
*/
/******************************************************************************/
bool is_log_debug( void )
{
	return _debug;
}

/******************************************************************************/
/** @fn is_log_info
	@brief check the current state of the info logging level
	@param none
	@returns true if info level is enabled, false otherwise
*/
/******************************************************************************/
bool is_log_info( void )
{
	return _info;
}

/******************************************************************************/
/** @fn is_log_error
	@brief check the current state of the error logging level
	@param none
	@returns true if error level is enabled, false otherwise
*/
/******************************************************************************/
bool is_log_error( void )
{
	return _error;
}

/******************************************************************************/
/** @fn is_log_off
	@brief check if logging is off
	@param none
	@returns true if the error level is off, false otherwise
*/
/******************************************************************************/
bool is_log_off( void )
{
	return !_error;
}

/******************************************************************************/
/** @fn get_log_format
	@brief locally defined function to format the log level with date & message
	@param char *buf = place to store the formatted message
	@param const char *msgFormat = message to print
	@param const char *logLevel = the log level of the message
	@returns none
*/
/******************************************************************************/
static inline void get_log_format(char* buf, const char* msgFormat,
								  const char* logLevel)
{
	char timeBuf[LOG_HEAD_SIZE];
	time_t t = time(NULL);
	struct tm* tm = gmtime(&t);
	strftime(timeBuf, LOG_HEAD_SIZE, "%Y-%m-%d %H:%M:%S", tm);

	sprintf(buf, "[%s] - %s - %s\n", timeBuf, logLevel, msgFormat);
}


/******************************************************************************/
/** @fn log_error
	@brief Print a message if the error logging level is enabled
	@returns none
*/
/******************************************************************************/
void log_error(const char* fmt, ...)
{
	if (_error)
	{
		char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
		get_log_format(logFormat, fmt, ERRORLVL);

		va_list args;
		va_start(args, fmt);
		vfprintf(stderr, logFormat, args);
		va_end(args);
	}
}

/******************************************************************************/
/** @fn log_info
	@brief Print a message if the info logging level is enabled
	@returns none
*/
/******************************************************************************/
void log_info(const char* fmt, ...)
{
	if(_info)
	{
		char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
		get_log_format(logFormat, fmt, INFOLVL);

		va_list args;
		va_start(args, fmt);
		vprintf(logFormat, args);
		va_end(args);
	}
}

/******************************************************************************/
/** @fn log_verbose
	@brief Print a message if the verbose logging level is enabled
	@returns none
*/
/******************************************************************************/
void log_verbose(const char* fmt, ...)
{
	if(_verbose)
	{
		char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
		get_log_format(logFormat, fmt, VERBOSELVL);

		va_list args;
		va_start(args, fmt);
		vprintf(logFormat, args);
		va_end(args);
	}
}

/******************************************************************************/
/** @fn log_debug
	@brief Print a message if the debug logging level is enabled
	@returns none
*/
/******************************************************************************/
void log_debug(const char* fmt, ...)
{
	if(_debug)
	{
		char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
		get_log_format(logFormat, fmt, DEBUGLVL);

		va_list args;
		va_start(args, fmt);
		vprintf(logFormat, args);
		va_end(args);
	}
}

/******************************************************************************/
/** @fn log_trace
	@brief Print a message if the trace logging level is enabled
	@returns none
*/
/******************************************************************************/
void log_trace(const char* fmt, ...)
{
	if(_trace)
	{
		char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
		get_log_format(logFormat, fmt, TRACELVL);

		va_list args;
		va_start(args, fmt);
		vprintf(logFormat, args);
		va_end(args);
	}
}

/******************************************************************************/
/** @fn log_me
	@brief local-only function to print a message
	@returns none
*/
/******************************************************************************/
static void log_me( const char* fmt, ... )
{
	char logFormat[LOG_HEAD_SIZE + strlen(fmt) + LOG_LEVEL_SIZE];
	get_log_format(logFormat, fmt, "[LOGGING]");

	va_list args;
	va_start(args, fmt);
	vprintf(logFormat, args);
	va_end(args);
}

/******************************************************************************/
/** @fn log_at_level
        @brief takes a logging level and logs at that level
        @returns none
*/
/******************************************************************************/
void log_at_level(enum LOG_LEVEL level, char* message)
{
	switch (level)
	{
		case ERROR:
			log_error("%s",message);
			break;
		case INFO:
			log_info("%s",message);
			break;
		case VERBOSE:
			log_verbose("%s",message);
			break;
		case DEBUG:
			log_debug("%s",message);
			break;
		case TRACE:
			log_trace("%s",message);
			break;
	}

}

/******************************************************************************/
/** @fn log_set_trace
	@brief Turn on the trace & all lower logging levels
	@returns none
*/
/******************************************************************************/
void log_set_trace(bool param)
{
	log_me( "%sSetting logging level to info.", MODULE );
	_trace = param;
	_debug = param;
	_verbose = param;
	_info = param;
	_error = param;
}

/******************************************************************************/
/** @fn log_set_debug
	@brief Turn on the debug & all lower logging levels
	@returns none
*/
/******************************************************************************/
void log_set_debug(bool param)
{
	log_me( "%sSetting logging level to info.", MODULE );
	_trace = !param;
	_debug = param;
	_verbose = param;
	_info = param;
	_error = param;
}

/******************************************************************************/
/** @fn log_set_verbosity
	@brief Turn on the verbose & all lower logging levels
	@returns none
*/
/******************************************************************************/
void log_set_verbosity(bool param)
{
	log_me( "%sSetting logging level to verbose.", MODULE );
	_trace = !param;
	_debug = !param;
	_verbose = param;
	_info = param;
	_error = param;
}

/******************************************************************************/
/** @fn log_set_info
	@brief Turn on the info & all lower logging levels
	@returns none
*/
/******************************************************************************/
void log_set_info(bool param)
{
	log_me( "%sSetting logging level to info.", MODULE );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = param;
	_error = param;
}

/******************************************************************************/
/** @fn log_set_error
	@brief Turn on the error logging level
	@returns none
*/
/******************************************************************************/
void log_set_error(bool param)
{
	log_me( "%sSetting logging level to error.", MODULE );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = !param;
	_error = param;
}

/******************************************************************************/
/** @fn log_set_off
	@brief Turn off all further logging
	@returns none
*/
/******************************************************************************/
void log_set_off(bool param)
{
	log_me( "%sTurning off all further logging.", MODULE );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = !param;
	_error = !param;
}
