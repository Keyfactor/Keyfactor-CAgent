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
#include <stdlib.h>
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

#define MAX_FILE_SIZE   (5ul * 1024ul * 1024ul) /* 5MByte log file on disk */
#define MAX_HEAP_SIZE   (256 * 1024) /* 256k of memory */


/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/
static char* log_head = NULL;
static char* log_tail = NULL;
static bool log_is_dirty = false;

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
    if (!tm) {
        (void) snprintf(buf, MAX_LOG_SIZE, "[%s] - %s - %s\n", "0000-00-00 00:00:00", logLevel, msgFormat);
    } else {
        (void) strftime(timeBuf, LOG_HEAD_SIZE, "%Y-%m-%d %H:%M:%S", tm);
        (void) snprintf(buf, MAX_LOG_SIZE, "[%s] - %s - %s\n", timeBuf, logLevel, msgFormat);
    }
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
/* Write the heap data to disk & set the heap tail = heap start               */
/*                                                                            */
/* @param  : none                                                             */
/* @return : none                                                             */
/*                                                                            */
static void write_heap_to_disk( void )
{
	do 
	{
		if (!ConfigData->LogFile) 
		{
			printf("%s::%s(%d) : No Log file defined in config\n", LOG_INF);
			break;
		}

		FILE* fp = NULL;
		if (file_exists(ConfigData->LogFile)) {
			printf("%s::%s(%d) : Opening existing log file\n", LOG_INF);
			fp = fopen(ConfigData->LogFile, "r+");
		} else {
			printf("%s::%s(%d) : Creating new log file\n", LOG_INF);
			fp = fopen(ConfigData->LogFile, "w");
		}

		if (NULL != fp)	{
            fseek(fp, 0ul, SEEK_END);
            size_t actualLogSize = ftell(fp);
			printf("%s::%s(%d) : Opened log file with size %lu\n", LOG_INF, 	actualLogSize);
			fseek(fp, ConfigData->LogFileIndex, SEEK_SET);
			size_t writeLen = log_tail - log_head;
			size_t logFileTest = (ConfigData->LogFileIndex + writeLen);
			printf("%s::%s(%d) : writing %lu bytes to log at index of %lu\n", LOG_INF, writeLen, ConfigData->LogFileIndex);
			printf("%s::%s(%d) : MAX_FILE_SIZE = %lu\n", LOG_INF, MAX_FILE_SIZE);
			if ( MAX_FILE_SIZE > logFileTest )	{
				printf("%s::%s(%d) : Writing %lu bytes to disk\n", LOG_INF, writeLen);
				size_t chars_written = fwrite((void*)log_head, sizeof(*log_head), writeLen, fp);
				ConfigData->LogFileIndex += chars_written;
				log_tail = log_head;
			} else {
				printf("%s::%s(%d) : Log file write of %lu creates wrap of log file\n", LOG_INF, writeLen);
				size_t toEOF = MAX_FILE_SIZE - ConfigData->LogFileIndex;
				size_t chars_written = fwrite((void*)log_head, sizeof(*log_head), toEOF, fp);
				fseek(fp, 0, SEEK_SET); /* reset to beginning of file */
				size_t new_chars_written = fwrite((void*)(log_head+chars_written+1), sizeof(*log_head),(writeLen-chars_written), fp);
				ConfigData->LogFileIndex = new_chars_written;
				log_tail = log_head;
			}

			config_save();
			fclose(fp);
		} else {
			printf("******* Error opening log file %s\n **************", ConfigData->LogFile);
			break;
		}

	} while(false);
	return;
} /* write_heap_to_disk */

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
			size_t log_index = (log_tail - log_head); /* parasoft-suppress MISRAC2012-DIR_4_1-i "same array" */
			if (MAX_HEAP_SIZE <= (log_index + chars_to_write)) 
			{ 
				write_heap_to_disk();		
			}
			get_log_format(logFormat, fmt, ERRORLVL);
			va_list args;
			va_start(args, fmt);
			size_t chars_written = vsprintf(log_tail, logFormat, args);
			va_end(args);
			log_tail += chars_written;
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
			size_t log_index = (log_tail - log_head);	/* parasoft-suppress MISRAC2012-DIR_4_1-i "same array" */
			if (MAX_HEAP_SIZE <= (log_index + chars_to_write)) 
			{ 
				write_heap_to_disk();		
			}
			get_log_format(logFormat, fmt, WARNLVL);
			va_list args;
			va_start(args, fmt);
			size_t chars_written = vsprintf(log_tail, logFormat, args);
			va_end(args);
			log_tail += chars_written;
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
			size_t log_index = (log_tail - log_head);  /* parasoft-suppress MISRAC2012-DIR_4_1-i "same array" */
			if (MAX_HEAP_SIZE <= (log_index + chars_to_write)) 
			{ 
				write_heap_to_disk();		
			}
			get_log_format(logFormat, fmt, INFOLVL);
			va_list args;
			va_start(args, fmt);
			size_t chars_written = vsprintf(log_tail, logFormat, args);
			va_end(args);
			log_tail += chars_written;
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

		if (config_loaded) 
		{
			/* Write to the log buffer, too */	
			size_t log_index = (log_tail - log_head); /* parasoft-suppress MISRAC2012-DIR_4_1-i "same array" */
			if (MAX_HEAP_SIZE <= (log_index + chars_to_write)) 
			{ 
				write_heap_to_disk();		
			}
			get_log_format(logFormat, fmt, VERBOSELVL);
			va_list args;
			va_start(args, fmt);
			size_t chars_written = vsprintf(log_tail, logFormat, args);
			va_end(args);
			log_tail += chars_written;
			log_is_dirty = true;
			/* End write to the log buffer, too */
		}
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

		if (config_loaded) 
		{
			/* Write to the log buffer, too */	
			size_t log_index = (log_tail - log_head); /* parasoft-suppress MISRAC2012-DIR_4_1-i "same array" */
			if (MAX_HEAP_SIZE <= (log_index + chars_to_write)) 
			{ 
				write_heap_to_disk();		
			}
			get_log_format(logFormat, fmt, DEBUGLVL);
			va_list args;
			va_start(args, fmt);
			size_t chars_written = vsprintf(log_tail, logFormat, args);
			va_end(args);
			log_tail += chars_written;
			log_is_dirty = true;
			/* End write to the log buffer, too */
		}
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

		if (config_loaded) 
		{
			/* Write to the log buffer, too */	
			size_t log_index = (log_tail - log_head);	/* parasoft-suppress MISRAC2012-DIR_4_1-i "same array" */
			if (MAX_HEAP_SIZE <= (log_index + chars_to_write)) 
			{ 
				write_heap_to_disk();		
			}
			get_log_format(logFormat, fmt, TRACELVL);
			va_list args;
			va_start(args, fmt);
			size_t chars_written = vsprintf(log_tail, logFormat, args);
			va_end(args);
			log_tail += chars_written;
			log_is_dirty = true;
			/* End write to the log buffer, too */
		}
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
bool load_log_buffer( void )
{
	bool bResult = false;

	log_me("%s::%s(%d) : Creating log buffer", LOG_INF);
	log_head = (char*)calloc(MAX_HEAP_SIZE, sizeof(*log_head));

	if (log_head)
	{
		log_me("%s::%s(%d) : Successfully created buffer of size %lu",
			LOG_INF, MAX_HEAP_SIZE);
		log_tail = log_head;
		bResult = true;
	}
	else
	{
		log_me("%s::%s(%d) : Out of memory", LOG_INF);
	}

	return bResult;
} /* load_log_buffer */

/**                                                                           */
/*  @fn write_log_file                                                        */
/*  @breif Write the log to disk if the buffer is dirty                       */
/*  @return none                                                              */
/*                                                                            */
void write_log_file( void )
{
	if ( log_is_dirty ) 
	{
		write_heap_to_disk();
	} 
	else 
	{
		printf("%s::%s(%d) : LOG is not DIRTY\n", LOG_INF);
	}
	return;
} /* write_log_file */

/**                                                                           */
/* Free the heap data structure                                               */
/* @param  : none                                                             */
/* @return : none                                                             */
/*                                                                            */
void free_log_heap( void )
{
	printf("%s::%s(%d) : Freeing Logging Heap Memory\n", LOG_INF);
	if (log_head) free(log_head);
	log_head = NULL;
	log_tail = NULL;
	return;
} /* free_log_heap */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/