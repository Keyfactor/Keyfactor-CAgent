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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "logging.h"
#include "config.h"
#include "utils.h"

#define LOG_HEAD_SIZE 50
#define LOG_LEVEL_SIZE 10
#define MAX_LOG_SIZE 1024 + LOG_HEAD_SIZE + LOG_LEVEL_SIZE

#define ERRORLVL   "[ERROR]  "
#define WARNLVL    "[WARNING]"
#define INFOLVL    "[INFO]   "
#define VERBOSELVL "[VERBOSE]"
#define DEBUGLVL   "[DEBUG]  "
#define TRACELVL   "[TRACE]  "

#define MAX_LOG_FILE	(5 * 1024) /* 5k of log messages on disk, 4k retrieve */
#define MAX_LOG_BUFFER  (2 * MAX_LOG_FILE)


/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/
static char LOG_BUFFER[MAX_LOG_BUFFER+1];
static bool log_is_dirty = false;
static int log_index = 0;

static bool _trace = false;
static bool _debug = false;
static bool _verbose = false;
static bool _info = true; /* default logging level */
static bool _warn = true;
static bool _error = true; 
static char logFormat[LOG_HEAD_SIZE + MAX_LOG_SIZE + LOG_LEVEL_SIZE];
static char timeBuf[LOG_HEAD_SIZE];

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/*	locally defined function to format the log level with date & message      */
/*	@param  char *buf = place to store the formatted message                  */
/*	@param  const char *msgFormat = message to print                          */
/*	@param  const char *logLevel = the log level of the message               */
/*	@return none                                                              */
/*                                                                            */
static inline void get_log_format(char* buf, const char* msgFormat, 
	const char* logLevel)
{
	time_t t = time(NULL);
	struct tm* tm = gmtime(&t);
	(void)strftime(timeBuf, LOG_HEAD_SIZE, "%Y-%m-%d %H:%M:%S", tm);
	(void)snprintf(buf, MAX_LOG_SIZE, "[%s] - %s - %s\n", timeBuf, 
		logLevel, msgFormat);
} /* get_log_format */

/**                                                                           */
/*  local-only function to print a message                                    */
/*	@returns none                                                             */
/*                                                                            */
static void log_me( const char* fmt, ... )
{
	get_log_format(logFormat, fmt, "[LOGGING]");

	va_list args;
	va_start(args, fmt);
	(void)vprintf(logFormat, args);
	va_end(args);
} /* log_me */

/**                                                                           */
/* Resize the log file once it has grown beyond 6k.                           */
/* shrink it to 3k by saving the newest 3k & resetting                        */
/* the index to 3k.                                                           */
/*                                                                            */
static void resize_log_file( void )
{
	log_me("%s::%s(%d) : Resizing log file", LOG_INF);
	size_t z = 0; /* Start at the beginning of the buffer for writes */
	size_t y = MAX_LOG_FILE; /* Need this to suppress gcc warning */
	char tempChar; /* Need this to suppress gcc warning */
	for (z = 0;z < MAX_LOG_FILE; z++) 
	{
		y = MAX_LOG_FILE + z;
		tempChar = LOG_BUFFER[y];
		LOG_BUFFER[z] = tempChar;
	}
	LOG_BUFFER[MAX_LOG_FILE] = '\0';
	log_index = MAX_LOG_FILE + 1;
	log_me("%s::%s(%d) : Leaving log file resize", LOG_INF);
	return;
} /* resize_log_file */

/******************************************************************************/
/************************ GLOBAL FUNCTION DEFINITIONS *************************/
/******************************************************************************/
/**                                                                           */
/*  @fn is_log_verbose                                                        */
/*	@brief check the current state of the verbose logging level               */
/*	@param none                                                               */
/*	@returns true if verbose level is enabled, false otherwise                */
/*                                                                            */
bool is_log_verbose( void )
{
	return _verbose;
} /* is_log_verbose */

/**                                                                           */
/*  @fn is_log_trace                                                          */
/*	@brief check the current state of the trace logging level                 */
/*	@param none                                                               */
/*	@returns true if trace level is enabled, false otherwise                  */
/*                                                                            */
bool is_log_trace( void )
{
	return _trace;
} /* is_log_trace */

/**                                                                           */
/*  @fn is_log_debug                                                          */
/*	@brief check the current state of the debug logging level                 */
/*	@param none                                                               */
/*	@returns true if debug level is enabled, false otherwise                  */
/*                                                                            */
bool is_log_debug( void )
{
	return _debug;
} /* is_log_debug */

/**                                                                           */
/*  @fn is_log_info                                                           */
/*	@brief check the current state of the info logging level                  */
/*	@param none                                                               */
/*	@returns true if info level is enabled, false otherwise                   */
/*                                                                            */
bool is_log_info( void )
{
	return _info;
} /* is_log_info */

/**                                                                           */
/* @fn is_log_warn                                                            */
/* @brief check the current state of the warning logging level                */
/* @param none                                                                */
/* @returns true if the warning level is enabled, false otherwise             */
/*                                                                            */
bool is_log_warn( void )
{
	return _warn;
} /* is_log_warn */

/**                                                                           */
/*  @fn is_log_error                                                          */
/*	@brief check the current state of the error logging level                 */
/*	@param none                                                               */
/*	@returns true if error level is enabled, false otherwise                  */
/*                                                                            */
bool is_log_error( void )
{
	return _error;
} /* is_log_error */

/**                                                                           */
/*  @fn is_log_off                                                            */
/*	@brief check if logging is off                                            */
/*	@param none                                                               */
/*	@returns true if the error level is off, false otherwise                  */
/*                                                                            */
bool is_log_off( void )
{
	return !_error;
} /* is_log_off */


/**                                                                           */
/*  @fn log_error                                                             */
/*	@brief Print a message if the error logging level is enabled              */
/*	@returns none                                                             */
/*                                                                            */
void log_error(const char* fmt, ...)
{
	if (_error)
	{
		get_log_format(logFormat, fmt, ERRORLVL);

		va_list args;
		va_start(args, fmt);
		size_t chars_to_write = vfprintf(stderr, logFormat, args);
		va_end(args);

		if (config_loaded) 
		{
			/* Write to the log buffer, too */			
			if (MAX_LOG_BUFFER <= (log_index + chars_to_write)) 
			{ 
				resize_log_file();		
			}
			char *log_ptr = &LOG_BUFFER[log_index];
			get_log_format(logFormat, fmt, ERRORLVL);
			va_list args;
			va_start(args, fmt);
			size_t char_write = vsprintf(log_ptr, logFormat, args);
			va_end(args);
			log_index += char_write;
			log_is_dirty = true;
			/* End write to the log buffer, too */
		}
	}
} /* log_error */

/**                                                                           */
/*  @fn log_warn                                                              */
/*	@brief Print a message if the info logging level is enabled               */
/*	@returns none                                                             */
/*                                                                            */
void log_warn(const char* fmt, ...)
{
	if(_warn)
	{
		get_log_format(logFormat, fmt, WARNLVL);

		va_list args;
		va_start(args, fmt);
		size_t chars_to_write = vfprintf(stderr, logFormat, args);
		va_end(args);

		if (config_loaded) 
		{
			/* Write to the log buffer, too */			
			if (MAX_LOG_BUFFER <= (log_index + chars_to_write)) 
			{ 
				resize_log_file();		
			}
			char *log_ptr = &LOG_BUFFER[log_index];
			get_log_format(logFormat, fmt, WARNLVL);
			va_list args;
			va_start(args, fmt);
			size_t char_write = vsprintf(log_ptr, logFormat, args);
			va_end(args);
			log_index += char_write;
			log_is_dirty = true;
			/* End write to the log buffer, too */
		}
	}
} /* log_warn */

/**                                                                           */
/*  @fn log_info                                                              */
/*	@brief Print a message if the info logging level is enabled               */
/*	@returns none                                                             */
/*                                                                            */
void log_info(const char* fmt, ...)
{
	if(_info)
	{
		get_log_format(logFormat, fmt, INFOLVL);

		va_list args;
		va_start(args, fmt);
		size_t chars_to_write = vfprintf(stderr, logFormat, args);
		va_end(args);

		if (config_loaded) 
		{
			/* Write to the log buffer, too */			
			if (MAX_LOG_BUFFER <= (log_index + chars_to_write)) 
			{ 
				resize_log_file();		
			}
			char *log_ptr = &LOG_BUFFER[log_index];
			get_log_format(logFormat, fmt, INFOLVL);
			va_list args;
			va_start(args, fmt);
			size_t char_write = vsprintf(log_ptr, logFormat, args);
			va_end(args);
			log_index += char_write;
			log_is_dirty = true;
			/* End write to the log buffer, too */
		}	
	}
} /* log_info */

/**                                                                           */
/*  @fn log_verbose                                                           */
/*	@brief Print a message if the verbose logging level is enabled            */
/*	@returns none                                                             */
/*                                                                            */
void log_verbose(const char* fmt, ...)
{
	if(_verbose)
	{
		get_log_format(logFormat, fmt, VERBOSELVL);

		va_list args;
		va_start(args, fmt);
		size_t chars_to_write = vfprintf(stderr, logFormat, args);
		va_end(args);
#ifdef __DONT_COMPILE_ME__
		if (config_loaded) {
			/* Write to the log buffer, too */			
			if (MAX_LOG_BUFFER <= (log_index + chars_to_write)) 
			{ 
				resize_log_file();		
			}
			char *log_ptr = &LOG_BUFFER[log_index];
			get_log_format(logFormat, fmt, VERBOSELVL);
			va_list args;
			va_start(args, fmt);
			size_t char_write = vsprintf(log_ptr, logFormat, args);
			va_end(args);
			log_index += char_write;
			log_is_dirty = true;
			/* End write to the log buffer, too */
		}
#endif
	}
} /* log_verbose */

/**                                                                           */
/*  @fn log_debug                                                             */
/*	@brief Print a message if the debug logging level is enabled              */
/*	@returns none                                                             */
/*                                                                            */
void log_debug(const char* fmt, ...)
{
	if(_debug)
	{
		get_log_format(logFormat, fmt, DEBUGLVL);

		va_list args;
		va_start(args, fmt);
		size_t chars_to_write = vfprintf(stderr, logFormat, args);
		va_end(args);
#ifdef __DONT_COMPILE_ME__
		if (config_loaded) {
			/* Write to the log buffer, too */			
			if (MAX_LOG_BUFFER <= (log_index + chars_to_write)) 
			{ 
				resize_log_file();		
			}
			char *log_ptr = &LOG_BUFFER[log_index];
			get_log_format(logFormat, fmt, DEBUGLVL);
			va_list args;
			va_start(args, fmt);
			size_t char_write = vsprintf(log_ptr, logFormat, args);
			va_end(args);
			log_index += char_write;
			log_is_dirty = true;
			/* End write to the log buffer, too */
		}
#endif
	}
} /* log_debug */

/**                                                                           */ 
/*  @fn log_trace                                                             */
/*	@brief Print a message if the trace logging level is enabled              */
/*	@returns none                                                             */
/*                                                                            */
void log_trace(const char* fmt, ...)
{
	if(_trace)
	{
		get_log_format(logFormat, fmt, TRACELVL);

		va_list args;
		va_start(args, fmt);
		size_t chars_to_write = vfprintf(stderr, logFormat, args);
		va_end(args);

#ifdef __DONT_COMPILE_ME__
		if (config_loaded) 
		{
			/* Write to the log buffer, too */			
			if (MAX_LOG_BUFFER <= (log_index + chars_to_write)) 
			{ 
				resize_log_file();		
			}
			char *log_ptr = &LOG_BUFFER[log_index];
			get_log_format(logFormat, fmt, TRACELVL);
			va_list args;
			va_start(args, fmt);
			size_t char_write = vsprintf(log_ptr, logFormat, args);
			va_end(args);
			log_index += char_write;
			log_is_dirty = true;
			/* End write to the log buffer, too */
		}
#endif
	}
} /* log_trace */

/**                                                                           */
/*  @fn log_set_trace                                                         */
/*	@brief Turn on the trace & all lower logging levels                       */
/*	@returns none                                                             */
/*                                                                            */
void log_set_trace(bool param)
{
	log_me( "%s::%s(%d) : Setting logging level to trace.", LOG_INF );
	_trace = param;
	_debug = param;
	_verbose = param;
	_info = param;
	_warn = param;
	_error = param;
} /* log_set_trace */

/**                                                                           */
/*  @fn log_set_debug                                                         */
/*	@brief Turn on the debug & all lower logging levels                       */
/*	@returns none                                                             */
/*                                                                            */
void log_set_debug(bool param)
{
	log_me( "%s::%s(%d) : Setting logging level to debug.", LOG_INF );
	_trace = !param;
	_debug = param;
	_verbose = param;
	_info = param;
	_warn = param;
	_error = param;
} /* log_set_debug */

/**                                                                           */ 
/*  @fn log_set_verbosity                                                     */
/*	@brief Turn on the verbose & all lower logging levels                     */
/*	@returns none                                                             */
/*                                                                            */
void log_set_verbosity(bool param)
{
	log_me( "%s::%s(%d) : Setting logging level to verbose.", LOG_INF );
	_trace = !param;
	_debug = !param;
	_verbose = param;
	_info = param;
	_warn = param;
	_error = param;
} /* log_set_verbosity */

/**                                                                           */
/*  @fn log_set_info                                                          */
/*	@brief Turn on the info & all lower logging levels                        */
/*	@returns none                                                             */
/*                                                                            */
void log_set_info(bool param)
{
	log_me( "%s::%s(%d) : Setting logging level to info.", LOG_INF );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = param;
	_warn = param;
	_error = param;
} /* log_set_info */

/**                                                                           */
/* @fn log_set_warn                                                           */
/* @breif Turn on the warning logging level & all lower logging levels        */
/* @returns none                                                              */
/*                                                                            */
void log_set_warn(bool param)
{
	log_me("%s::%s(%d) : Setting logging level to warning.", LOG_INF);
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = !param;
	_warn = param;
	_error = param;
} /* log_set_warn */

/**                                                                           */
/*  @fn log_set_error                                                         */
/*	@brief Turn on the error logging level                                    */
/*	@returns none                                                             */
/*                                                                            */
void log_set_error(bool param)
{
	log_me( "%s::%s(%d) : Setting logging level to error.", LOG_INF );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = !param;
	_warn = !param;
	_error = param;
} /* log_set_error */

/**                                                                           */
/*  @fn log_set_off                                                           */
/*	@brief Turn off all further logging                                       */
/*	@returns none                                                             */
/*                                                                            */
void log_set_off(bool param)
{
	log_me( "%s::%s(%d) : Turning off all logging.", LOG_INF );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = !param;
	_warn = !param;
	_error = !param;
} /* log_set_off */

/**                                                                           */
/*  @fn load_log_buffer                                                       */
/*  @breif Load the log buffer from the log file                              */
/*  @return none                                                              */
/*                                                                            */
void load_log_buffer( void )
{
	log_me("%s::%s(%d) : Attempting to load log buffer", LOG_INF);
	FILE *fp = NULL;
	if (ConfigData->LogFile) 
	{
		log_me("%s::%s(%d) : ConfigData->LogFile Exists", LOG_INF);
		if (file_exists(ConfigData->LogFile)) 
		{
			log_me("%s::%s(%d) : The file %s exists", LOG_INF, 
				ConfigData->LogFile);
			fp = fopen(ConfigData->LogFile, "r");
			if (NULL != fp) 
			{
				log_me("%s::%s(%d) : Opened %s for reading", 
					LOG_INF, ConfigData->LogFile);
				log_index = fread(LOG_BUFFER, sizeof(char), MAX_LOG_BUFFER, fp);
				if (0 != ferror(fp)) 
				{
					log_me("%s::%s(%d) : Error reading logfile %s", 
						LOG_INF, ConfigData->LogFile);
					LOG_BUFFER[0] = '\0';
					log_index = 0;
				} 
				else 
				{
					log_me("%s::%s(%d) : Read %d bytes from file %s", 
						LOG_INF, log_index, ConfigData->LogFile);
					if (MAX_LOG_FILE <= log_index )
					{
						LOG_BUFFER[log_index] = '\0';
					}
					else
					{
						LOG_BUFFER[log_index++] = '\0'; 
					}
				}
			} 
			else 
			{
				log_me("%s::%s(%d) : Failed to open log file %s", 
					LOG_INF, ConfigData->LogFile);
				LOG_BUFFER[0] = '\0';
				log_index = 0;
			}
		} 
		else 
		{
			log_me("%s::%s(%d) : File %s doesn't exist, creating empty buffer",	
				LOG_INF, ConfigData->LogFile);
			LOG_BUFFER[0] = '\0';
			log_index = 0;
		}
	}
	else 
	{
		log_me("%s::%s(%d) : Config file isn't defined, creating empty buffer",	
			LOG_INF);
		LOG_BUFFER[0] = '\0';
		log_index = 0;
	}
	log_is_dirty = false;
	if (fp)
	{
		fclose(fp);
	}
	return;
} /* load_log_buffer */

/**                                                                           */
/*  @fn write_log_file                                                        */
/*  @breif Write the log to disk if the buffer is dirty                       */
/*  @return none                                                              */
/*                                                                            */
void write_log_file( char* file )
{
	if ((ConfigData->LogFile) && log_is_dirty) 
	{
		if ( (MAX_LOG_FILE-1) >= log_index ) 
		{
			printf("******* log_index <= MAX_LOG_FILE ******** %d\n", 
				log_index);
			FILE* fp = fopen(file, "w");
			if (NULL != fp)
			{
				LOG_BUFFER[log_index] = '\0';
				size_t write_bytes = fwrite(LOG_BUFFER, 1, log_index, fp);
				printf("******* WROTE %lu bytes to log file ***********\n", 
					write_bytes);
				fclose(fp);
			} 
			else 
			{
				printf("******* Error opening file %s\n", file);
			}
		} 
		else 
		{
			printf("******* log_index > MAX_LOG_FILE ********\n");
			FILE* fp = fopen(file, "w");
			if (NULL != fp)
			{
				LOG_BUFFER[log_index] = '\0';
				size_t write_bytes = 
					fwrite(&LOG_BUFFER[log_index-MAX_LOG_FILE], 1, 
						MAX_LOG_FILE, fp);
				printf("******* WROTE %lu bytes to log file ***********\n", 
					write_bytes);
				fclose(fp);
			} 
			else 
			{
				printf("******* Error opening file %s\n", file);
			}
		}
	} 
	else 
	{
		printf("******* LOG NOT DEFINED or is not DIRTY *******\n");
	}
	return;
} /* write_log_file */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/