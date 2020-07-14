/** @file agent.c */
/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>
#include "constants.h"

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/rand.h>
#include <wolfssl/openssl/err.h>
#else
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

#include "inventory.h"
#include "management.h"
#include "enrollment.h"
#include "httpclient.h"
#include "logging.h"
#include "dto.h"
#include "schedule.h"
#include "config.h"
#include "session.h"
#include "global.h"
#include "serialize.h"

#include "utils.h"

/* Optional includes based on switches in global.h */
#ifdef __RPI__
#include "rpi_gpio.h"
#endif
#ifdef __TPM__
/* ### RAL 12-Nov-2019 */
/* ### Added the following includes for tpm2tss engine. */
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <tpm2-tss-engine.h>
#endif

/* Versioning Information */
/* 1.1.0.0 = Initial version */
/* 1.1.0.1 = Added engine support (e.g., tpm2tss) & updated logging & created global header file*/
/* 1.1.0.2 = Added auto UUID and Serialization support */
/* 1.1.0.3 = Added wolfSSL */
#define AGENT_VERSION 0x0001000100000003

#define MODULE "agent-"
#define JOB_CHECK_SECONDS 30
#define UUID_LEN 37 // 36 char per RFC4122 + 1 for \0

char *engine_id;
static struct SessionInfo SessionData;
static struct ScheduledJob* JobList;
static struct ConfigData* ConfigData;
static int curlLoaded = 0;
#ifdef __TPM__
ENGINE *e = NULL;
#endif

/***************************************************************************//**
  @fn fill_random_byte_array
	Fill a byte array with random data
	@param unsigned char byteArray = the array to fill
	@param int arraySize = the number of bytes in the array
	@retval 1 on success
	@retval 0 on failure
*/
/******************************************************************************/
static int fill_random_byte_array( unsigned char byteArray[], int arraySize )
{
#undef FUNCTION
#define FUNCTION "fill_random_byte_array"
	int i, err;
	for( i = 0; arraySize > i; i++ )
	{
		err = RAND_bytes( &byteArray[i], 1 );
		if ( 1 != err )
		{
			return 0;
		}
		log_trace("%s%s-Random byte = 0x%02x", MODULE, FUNCTION, byteArray[i]);
	}
	return 1;
} // FillRandomByteArray

/***************************************************************************//**
  @fn make_UUID( void )
	Create a properly formatted RFFC4122 UUID
	A UUID looks like this:  8-4-4-4-12:
	   XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	         ^  ^
	         |  |
	         |  Must be an 8, 9, A, or B (all have 10bb)
	         |
	         Must be a 4
	@param char[] uuid = where to place the uuid
	@retval 0 on failure
	@retval 1 on success
*/
/******************************************************************************/
static int make_UUID( char uuid[] )
{
#undef FUNCTION
#define FUNCTION "make_UUID"
	// This array holds the array without the uuid dashes
	char uuidArray[ UUID_LEN - 4 ];
	// (37 chars - 4 dashes - 1 end string) / 2 = 16 bytes
	unsigned char uuidBytes[(UUID_LEN - 5)/2];
	int err, i, offset;

	// get random byte data
	err = fill_random_byte_array( uuidBytes, sizeof(uuidBytes)
								/ sizeof(uuidBytes[0]) );
	if ( !err )
	{
		log_error("%s%s-Failed to fill random byte array", MODULE, FUNCTION);
		return 0;
	}

	// Adjust the bits per RFC 4122 section 4.4:
	//		(a) set the high nibble of the 7th byte to 4
	//		(b) set the two msb of the 9th byte to 10xx, this
	//			results in that nibble being 8,9,A,B only
	uuidBytes[ 6 ] = 0x40 | (uuidBytes[6] & 0x0f);
	uuidBytes[ 8 ] = 0x80 | (uuidBytes[8] & 0x3f);
	log_debug("%s%s-uuidBytes = 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					MODULE, FUNCTION,
					uuidBytes[0 ], uuidBytes[1 ], uuidBytes[2 ], uuidBytes[3 ],
					uuidBytes[4 ], uuidBytes[5 ], uuidBytes[6 ], uuidBytes[7 ],
					uuidBytes[8 ], uuidBytes[9 ], uuidBytes[10], uuidBytes[11],
					uuidBytes[12], uuidBytes[13], uuidBytes[14], uuidBytes[15]);

	// convert the data to a string
	err = byte_to_hex_string( uuidArray,
						   sizeof(uuidArray)/sizeof(uuidArray[0]),
						   uuidBytes,
						   sizeof(uuidBytes)/sizeof(uuidBytes[0]) );
	log_debug("%s%s-uuidArray = 0x%s", MODULE, FUNCTION, uuidArray);
	if ( err )
	{
		log_error("%s%s-Failed to convert random byte array to a string.",
								MODULE, FUNCTION);
		return 0;
	}

	// split the result apart and place it in the uuid passed to this function
	offset = 0;
	for ( i = 0; 8 > i; i++ )
	{
		uuid[i+offset] = uuidArray[i];		// characters 1..8 array 0..7
	}
	uuid[i] = '-';							// 1st dash = character 9 array 8
	offset = offset+i+1;					// Should be array 9 (0+8+1)
	for ( i = 0 ; 4 > i; i++ )
	{
		uuid[i+offset] = uuidArray[i+8];	// characters 10..13 array 9..12
	}
	uuid[i+offset] = '-';					// 2nd dash = character 14 array 13
	offset = offset+i+1;					// Should be array 14 (9+4+1)
	for ( i = 0; 4 > i; i++ )
	{
		uuid[i+offset] = uuidArray[i+12];	// characters 15..18 array 14..17
	}
	uuid[i+offset] = '-';					// 3rd dash = 19th character array 18
	offset = offset+i+1;					// Should be array 19 (14+4+1)
	for ( i = 0; 4 > i; i++ )
	{
		uuid[i+offset] = uuidArray[i+16];	// characters 20..23 array 19..22
	}
	uuid[i+offset] = '-';					// 4th dash = 24th char array is 23
	offset = offset+i+1;					// Should be array 24 (19+4+1)
	for ( i = 0; 12 > i; i++ )
	{
		uuid[i+offset] = uuidArray[i+20];	// characters 25..36
	}
	uuid[UUID_LEN] = '\0'; 				// remember to end the string with this!!

	return 1;
} // makeUUID

/***************************************************************************//**
  @fn void parse_parameters( int argc, const char *argv[] )
	Parse command line switches and set the global variables associated
	with the switches.
	@param int argc = # of arguments passed
	@param const char *argv[] = the array of passed arguments
	@retval 1 on success
	@retval 0 on failure
*/
/******************************************************************************/
static int parse_parameters( int argc, char *argv[] )
{
	#undef FUNCTION
	#define FUNCTION "parse_parameters"
#ifdef __TPM__
	int foundEngine = 0;
	const char* default_engine = "dynamic"; // the default engine to choose
#endif

	for(int i = 1; i < argc; ++i)
	{
		if(strcmp(argv[i], "-v") == 0)
		{
			log_set_verbosity(true);
		}
		else if (strcmp(argv[i], "-l") == 0)
		{
			if ( argc <= i )
			{
				fprintf(stderr,
					      "You must supply a switch variable with the -l command\n");
				return 0;
			} // if argc
			else
			{
				if (strcmp(argv[i+1], "v") == 0)
				{
					log_set_verbosity(true);
					i++;
				}
				else if (strcmp(argv[i+1], "i") == 0)
				{
					log_set_info(true);
					i++;
				}
				else if (strcmp(argv[i+1], "e") == 0)
				{
					log_set_error(true);
					i++;
				}
				else if (strcmp(argv[i+1], "o") == 0)
				{
					log_set_off(true);
					i++;
				}
				else if (strcmp(argv[i+1], "d") == 0)
				{
					log_set_debug(true);
					i++;
				}
				else if (strcmp(argv[i+1], "t") == 0)
				{
					log_set_trace(true);
					i++;
				}
				else
				{
					// default
					fprintf(stderr,"Unknown -l switch variable %s\n", argv[i+1]);
					return 0;
				}
			} // else argc
		} // else -l
#ifdef __TPM__
		else if ( strcmp(argv[i], "-e") == 0 )
		{
			if ( argc > i )
			{
				strcpy( engine_id, argv[++i] );
				foundEngine = 1;
			}
		}
#endif
		else
		{
			log_verbose( "%s%s-Unknown switch: %s", MODULE, FUNCTION, argv[i] );
		}
	}

#ifdef __TPM__
	if ( !foundEngine )
	{
		// no -e switch means use the default engine
		strcpy( engine_id, default_engine );
	}
#endif

	return 1;
} // parse_parameters

#ifdef __TPM__
/***************************************************************************//**
    @fn ENGINE* intitialize_engine( const char* engine_id )
    Tries to initialize and open the engine passed to it.
    It also sets the engine as the default engine for all functions
    @param engine_id The name of the engine to use e.g., default, tpm2tss
    @retval Pointer to the initialized engine ENGINE*
    @retval NULL on failure
*/
/******************************************************************************/
ENGINE* initialize_engine( const char *engine_id )
{
    ENGINE *e = NULL;
    ENGINE_load_builtin_engines();

    // Set the engine pointer to an instance of the engine
    if ( !( e = ENGINE_by_id( engine_id ) ) )
    {
        log_error("%s%sUnable to find Engine: %s",
											engine_id, MODULE, FUNCTION);
        return NULL;
    }
    log_verbose("%s%sFound engine: %s", MODULE, FUNCTION, engine_id);

    // Initialize the engine for use
    if ( !ENGINE_init(e) )
    {
        log_error("%s%sUnable to initialize engine: %s",
											engine_id, MODULE, FUNCTION);
        return NULL;
    }
    log_verbose("%s%sInitialized engine: %s", MODULE, FUNCTION, engine_id);

    // Register the engine for use with all algorithms
    if ( !ENGINE_set_default( e, ENGINE_METHOD_ALL ) )
    {
        log_error("%s%sUnable to set %s as the default engine.",
											engine_id, MODULE, FUNCTION);
        return NULL;
    }
    log_verbose("%s%sSuccessfully set the default engine to %s.",
											engine_id, MODULE, FUNCTION);

    ENGINE_register_complete( e );
    return e;
} // initialize_engine
#endif // __TPM__

static int run_job(struct SessionJob* job)
{
	#undef FUNCTION
	#define FUNCTION "run_job-"
	char* chainJobId = NULL;
	struct SessionJob* chainJob = NULL;
	int status = 0;
	if(strcasecmp(job->JobTypeId, CAP_PEM_INVENTORY) == 0)
	{
		status = cms_job_inventory(job, ConfigData, SessionData.Token);
	}
	else if(strcasecmp(job->JobTypeId, CAP_PEM_MANAGEMENT) == 0)
	{
		status = cms_job_manage(job, ConfigData, SessionData.Token, &chainJobId);
	}
	else if(strcasecmp(job->JobTypeId, CAP_PEM_ENROLL) == 0)
	{
		status = cms_job_enroll(job, ConfigData, SessionData.Token, &chainJobId);
	}

	if(chainJobId)
	{
		log_info("%s%sCompleted job indicates that job %s should be run immediately"
							, MODULE, FUNCTION, chainJobId);
		chainJob = get_job_by_id(&JobList, chainJobId);
		if(chainJob)
		{
			run_job(chainJob);
		}
		else
		{
			log_info("%s%sJob %s could not be found in the scheduled jobs list, and will not be run"
								, MODULE, FUNCTION, chainJobId);
		}
	}

	free(chainJobId);
	return status;
}

/***************************************************************************//**
  Serialize the AgentName and CSR Subject using a json file.  In practice this
  is a file that is held on a common data store (i.e. network drive)
	@param a reference to the ConfigData structure
	@retval 1 on success
	@retval 0 on failure
*******************************************************************************/
static int do_serialization( struct ConfigData* config )
{
	#undef FUNCTION
	#define FUNCTION "do_serialization"
	struct SerializeData* serial = serialize_load(config->SerialFile);
	if(!serial)
	{
		log_error("%s%sUnable to load Serialization file: %s",
			MODULE,FUNCTION,config->SerialFile);
		return 0;
	}
	log_trace("%s%sFreeing AgentName & CSRSubject",MODULE,FUNCTION);
	free(config->AgentName);
	free(config->CSRSubject);
	config->AgentName = (char *)malloc(50);
	config->CSRSubject = (char *)malloc(50);
	if (!config->AgentName || !config->CSRSubject)
	{
		log_error("%s%sOut of membory for Agent Name or CSR Subject",
					MODULE,FUNCTION);
		return 0;
	}
	sprintf(config->AgentName, "%s-%d", serial->ModelName, serial->NextNumber);
	log_trace("%s%sconfig->AgentName set to: %s",
		MODULE,FUNCTION,config->AgentName);
	sprintf(config->CSRSubject, "CN=%d", serial->NextNumber);
	log_trace("%s%sconfig->CSRSubject set to: %s",
		MODULE,FUNCTION,config->CSRSubject);
	serial->NextNumber++;
	config->Serialize = false;
	config_save(ConfigData);
	if ( !(serialize_save(serial, config->SerialFile)) )
	{
		log_error("%s%sFailed saving the serialization file",MODULE,FUNCTION);
		return 0;
	}
	return 1;
} // do_serialization


/***************************************************************************//**
  @fn int init_platform( int argc, char* argv[] )
	Initialize the data structures, openSSL, the configuration, etc.
	@param argc the # of command line arguments
	@param argv the array of command line argument strings
	@retval 1 on successful
	@retval 0 on failure
*******************************************************************************/
static int init_platform( int argc, char* argv[] )
{
	#undef FUNCTION
	#define FUNCTION "init_platform-"

	/***************************************************************************
	 * 0. Parse the command line parameters.
	 **************************************************************************/
	log_trace("%s%sParsing Parameters", MODULE, FUNCTION);
	if ( 0 == parse_parameters( argc, &argv[0] ) )
	{
		log_error("%s%sFailed to parse command line parameters",
					MODULE, FUNCTION);
		return 0;
	}

	/***************************************************************************
	 * 1. Initialize the RPI GPIO
	 *    If a a raspberry pi is defined, then setup the GPIO to blink an LED
	 *    and blink the LED.
	 **************************************************************************/
#ifdef __RPI__
	log_trace("%s%sInitialize RPI GPIO", MODULE, FUNCTION);
	if ( !setup_io() )
	{
		log_error("%s%s-Failed to setup GPIO! exiting", MODULE, FUNCTION);
		return 0;
	}
	turn_on_led();
	sleep(1);
	turn_off_led();
#endif

	/***************************************************************************
	  2. If we are using a TPM, then initialize it & set it to be the source for
	     all cryptographic calls to openSSL
	 **************************************************************************/
#ifdef __TPM__
  log_trace("%s%sInitializing TPM engine", MODULE, FUNCTION);
	e = initialize_engine( engine_id );
	if ( !e )
	{
		log_error( "%s%s-ERROR getting engine %s", MODULE, FUNCTION, engine_id);
		if ( engine_id ) free( engine_id );
		return 0;
	}
#endif

	/***************************************************************************
	 * 3. Initalize openSSL and curl
	 **************************************************************************/
	log_trace("%s%sAdding openSSL algorithms", MODULE, FUNCTION);
	OpenSSL_add_all_algorithms();
	log_trace("%s%sInitializing cURL", MODULE, FUNCTION);
	if ( 0 != curl_global_init(CURL_GLOBAL_DEFAULT) )
	{
		log_error("%s%sError initializing cURL", MODULE, FUNCTION);
		return 0;
	}
	curlLoaded = 1;
	log_trace("%s%sLoading Crypto error strings", MODULE, FUNCTION);
	ERR_load_crypto_strings();

	/***************************************************************************
	* 4. Load the configuration data
	***************************************************************************/
	log_trace("%s%sLoading configuration data from config.json",
					MODULE, FUNCTION);
	ConfigData = config_load();
	if(!ConfigData)
	{
		log_error("%s%sUnable to load configuration. Exiting", 
					MODULE, FUNCTION);
		return 0;
	}


	/***************************************************************************
	* 5. If required, create a uuid.
	***************************************************************************/
	if (ConfigData->AutoGenerateId)
	{
		log_trace("%s%sEnrollOnStartup -> true", MODULE, FUNCTION);
		char *uuid = (char *)malloc(37);
		if ( !uuid )
		{
			log_error("%s%s-Out of memory for uuid", MODULE, FUNCTION);
			return 0;
		}

		if ( !make_UUID( uuid ) )
		{
			log_error("%s%s-Unable to create random UUID. Exiting",
					MODULE, FUNCTION);
			return 0;
		}
		log_debug("%s%s-uuid calculated to %s", MODULE,FUNCTION, uuid);
		strcpy(ConfigData->AgentId, uuid);
		log_verbose("%s%s-Random UUID is set to %s",
									MODULE, FUNCTION, ConfigData->AgentId);
		ConfigData->AutoGenerateId = false;
		config_save(ConfigData);
	}

	/***************************************************************************
	 * 6. If required, serialize the agent
	 **************************************************************************/
	if (ConfigData->Serialize)
	{
		log_trace("%s%sSerialize -> true", MODULE, FUNCTION);
		int x = do_serialization( ConfigData );
		if ( !x )
		{
			log_error("%s%sSerialization failed", MODULE, FUNCTION);
			return 0;
		}
	}

	return 1;
} //init_platform

/***************************************************************************//**
	@fn int main(int argc, char* argv[])
	Main program entry point.  This controls all flow.
	@retval EXIT_SUCCESS if successful
	@retval EXIT_FAILURE if failure.
*/
/******************************************************************************/
int main( int argc, char* argv[] )
{
	#undef FUNCTION
	#define FUNCTION "main-"

	/***************************************************************************
	  Provide space for an engine pointer if we are using a TPM, otherwise don't
	 **************************************************************************/
	#ifdef __TPM__
		engine_id = (char *)malloc(21); // 20 characters should be fine
		if ( !engine_id )
		{
			log_error("%s%s-Out of memory for engine_id", MODULE, FUNCTION);
			goto error_exit;
		}
	#endif

	/***************************************************************************
	 * 0. Initialize items based on command line, config.json, and #defines
	 **************************************************************************/
 	if ( !init_platform( argc, &argv[0] ) )
	{
		log_error("%s%sFailed to initialize platform", MODULE, FUNCTION);
		goto error_exit;
	}

  /*****************************************************************************
	 * 1. Prepare for the first time through the while loop; force immediate
	 *    session generation.
	 **************************************************************************/
	SessionData.UnreachableCount = 0;
	SessionData.Interval = 30;
	SessionData.NextExecution = time(NULL);
	int firstPass = 1;

  /*****************************************************************************
	 * The main loop
	 **************************************************************************/
	while(1)
	{
		log_verbose("%s%sWaking up to look for work", MODULE, FUNCTION);

		time_t now = time(NULL);

		if( (SessionData.NextExecution <= now) ||
				( 1 == firstPass ) )
		{
			if(strcmp(SessionData.Token, "") == 0)
			{
				log_verbose("%s%sNeed a session", MODULE, FUNCTION);
				register_session(ConfigData, &SessionData, &JobList, AGENT_VERSION);
			}
			else
			{
				log_verbose("%s%sNeed to heartbeat", MODULE, FUNCTION);
				heartbeat_session(ConfigData, &SessionData, &JobList, AGENT_VERSION);
			}
			firstPass = 0;
		}

		// Get current time again to deal with immediate jobs
		now = time(NULL); // TODO - Incorporate clock-skew remediation

		struct SessionJob* job;
		while( NULL != (job = get_runnable_job(&JobList, now)) )
		{
			int status = run_job(job);
			if(status == 1)
			{
				strcpy(SessionData.Token, "");
				register_session(ConfigData, &SessionData, &JobList, AGENT_VERSION);
			}
			else
			{
				schedule_job(&JobList, job, now);
			}
		}

		sleep(JOB_CHECK_SECONDS);
	} // while 1

  /*****************************************************************************
	 * Finalize & exit -- successful
	 **************************************************************************/
	if ( curlLoaded ) curl_global_cleanup();
	if ( engine_id ) free( engine_id );
#ifdef __TPM__
	if ( e ) ENGINE_free( e );
#endif
#ifdef __RPI__
	cleanup_io();
#endif
	exit(EXIT_SUCCESS);

	/***************************************************************************
	 * Finalize & exit -- error
	 **************************************************************************/
error_exit:
	 if ( curlLoaded ) curl_global_cleanup();
	 if ( engine_id ) free( engine_id );
#ifdef __TPM__
 	if ( e ) ENGINE_free( e );
#endif
#ifdef __RPI__
 	cleanup_io();
#endif
  exit(EXIT_FAILURE);

} // main
