/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file agent.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>
#include "constants.h"

#ifdef __WOLF_SSL__
	#include "wolfssl_wrapper/wolfssl_wrapper.h"
#else
	#ifdef __OPEN_SSL__
		#include <openssl/engine.h>
		#include "openssl_wrapper/openssl_wrapper.h"
	#else
		#ifdef __TPM__
			#include <tss2/tss2_mu.h>
			#include <tss2/tss2_esys.h>
			#include <tpm2-tss-engine.h>
		#else
		#endif
	#endif
#endif

#include "agent.h"
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
#include "fetchlogs.h"
#include "utils.h"

#define JOB_CHECK_SECONDS 10

/******************************************************************************/
/***************************** GLOBAL VARIABLES *******************************/
/******************************************************************************/
struct SessionInfo SessionData;
struct ScheduledJob* JobList;
struct ConfigData* ConfigData;
#if defined(__OPEN_SSL__)
char engine_id[21]; // 20 Characters should be enough
#endif
#if defined(__TPM__)
ENGINE* e = NULL;
#endif

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/
static bool curlLoaded = false;
static bool exit_if_inventory_only = false;
static bool inventory_ran = false;

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**
 *	Parse command line switches and set the global variables associated
 *	with the switches.
 *
 *	@param  - [Input] argc = # of arguments passed
 *	@param  - [Input] const char *argv[] = the array of passed arguments
 *	@return - success : 1
 *			  failure : 0
 */
static int parse_parameters( int argc, char *argv[] )
{
	#ifdef __TPM__
		int foundEngine = 0;
		const char* default_engine = "dynamic"; // the default engine to choose
	#endif
	for(int i = 1; i < argc; ++i) {
		if(strcmp(argv[i], "-v") == 0) {
			log_set_verbosity(true);
		}
		else if (strcmp(argv[i], "-l") == 0) {
			if ( argc <= i ) {
				fprintf(stderr,
					 "You must supply a switch variable with the -l command\n");
				return 0;
			} // if argc
			else {
				if (strcmp(argv[i+1], "v") == 0) {
					log_set_verbosity(true);
					i++;
				}
				else if (strcmp(argv[i+1], "i") == 0) {
					log_set_info(true);
					i++;
				}
				else if (strcmp(argv[i+1], "e") == 0) {
					log_set_error(true);
					i++;
				}
				else if (strcmp(argv[i+1], "o") == 0) {
					log_set_off(true);
					i++;
				}
				else if (strcmp(argv[i+1], "d") == 0) {
					log_set_debug(true);
					i++;
				}
				else if (strcmp(argv[i+1], "t") == 0) {
					log_set_trace(true);
					i++;
				}
				else {
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
				char* eng = &engine_id[0];
				eng = strncpy( eng, argv[++i], 20 );
				foundEngine = 1;
			}
		}
#endif
		else if (strcmp(argv[i], "-d") == 0) {
			/* Use this for debugging memory leaks */
			exit_if_inventory_only = true;
		} // else -d
		else {
			log_verbose( "%s::%s(%d) : Unknown switch: %s", \
				__FILE__, __FUNCTION__, __LINE__, argv[i] );
		}
	}

#ifdef __TPM__
	if ( !foundEngine )
	{
		// no -e switch means use the default engine
		char* eng = &engine_id[0];
		eng = strncpy( eng, default_engine, 20 );
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
static ENGINE* initialize_engine( const char *engine_id )
{
    ENGINE *e = NULL;
    ENGINE_load_builtin_engines();

    // Set the engine pointer to an instance of the engine
    if ( !( e = ENGINE_by_id( engine_id ) ) )
    {
        log_error("%s::%s(%d) : Unable to find Engine: %s", \
        	__FILE__, __FUNCTION__, __LINE__, engine_id);
        return NULL;
    }
    log_verbose("%s::%s(%d) : Found Engine: %s", \
        __FILE__, __FUNCTION__, __LINE__, engine_id);

    // Initialize the engine for use
    if ( !ENGINE_init(e) )
    {
        log_error("%s::%s(%d) : Unable to initialize Engine: %s", \
        	__FILE__, __FUNCTION__, __LINE__, engine_id);
        return NULL;
    }
    log_verbose("%s::%s(%d) : Initialized Engine: %s", \
        __FILE__, __FUNCTION__, __LINE__, engine_id);

    // Register the engine for use with all algorithms
    if ( !ENGINE_set_default( e, ENGINE_METHOD_ALL ) )
    {
        log_error("%s::%s(%d) : Unable to set %s as the default engine", \
        	__FILE__, __FUNCTION__, __LINE__, engine_id);
        return NULL;
    }
    log_verbose("%s::%s(%d) : Sucessfully set %s as the default engine", \
        __FILE__, __FUNCTION__, __LINE__, engine_id);

    ENGINE_register_complete( e );
    return e;
} // initialize_engine
#endif // __TPM__

/**
 * Serialize the AgentName and CSR Subject using a json file.  In practice this
 * is a file that is held on a common data store (i.e. network drive)
 *	@param  - [Input] config = a reference to the ConfigData structure
 *	@return - success = 1
 *		      failure = 0
 */
static int do_serialization( struct ConfigData* config )
{
	struct SerializeData* serial = serialize_load(config->SerialFile);
	if(!serial)
	{
		log_error("%s::%s(%d) : Unable to load Serialization file: %s",
			__FILE__, __FUNCTION__, __LINE__,config->SerialFile);
		return 0;
	}
	log_trace("%s::%s(%d) : Freeing AgentName & CSRSubject",\
		__FILE__, __FUNCTION__, __LINE__);
	free(config->AgentName);
	free(config->CSRSubject);
	config->AgentName = (char *)malloc(50);
	config->CSRSubject = (char *)malloc(50);
	if (!config->AgentName || !config->CSRSubject) {
		log_error("%s::%s(%d) : Out of memory for",
			__FILE__, __FUNCTION__, __LINE__);
		return 0;
	}
	sprintf(config->AgentName, "%s-%d", serial->ModelName, serial->NextNumber);
	log_trace("%s::%s(%d) : config->AgentName set to: %s",
		__FILE__, __FUNCTION__, __LINE__,config->AgentName);
	sprintf(config->CSRSubject, "CN=%d", serial->NextNumber);
	log_trace("%s::%s(%d) : config->CSRSubject set to: %s",
		__FILE__, __FUNCTION__, __LINE__,config->CSRSubject);
	serial->NextNumber++;
	config->Serialize = false;
	config_save(ConfigData);
	if ( !(serialize_save(serial, config->SerialFile)) ) {
		log_error("%s::%s(%d) : Failed saving the serialization file", \
			__FILE__, __FUNCTION__, __LINE__);
		return 0;
	}
	return 1;
} /* do_serialization */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**
 * Transfer the job to the appropriate function based on the job type.
 *
 * @param  [Input] : job = pointer to a job structure containing the Job type,
 *                         job guid, where to ask for configuration, etc.
 * @return job results as an integer
 */ 
int run_job(struct SessionJob* job)
{
	char* chainJobId = NULL;
	struct SessionJob* chainJob = NULL;
	int status = 0;

	if( 0 == strcasecmp(job->JobTypeId, CAP_PEM_INVENTORY) ) {
		status = cms_job_inventory(job, ConfigData, SessionData.Token);
		inventory_ran = true;
	}
	else if( 0 == strcasecmp(job->JobTypeId, CAP_PEM_MANAGEMENT) ) {
		status = cms_job_manage(job, ConfigData, SessionData.Token,&chainJobId);
	}
	else if( 0 == strcasecmp(job->JobTypeId, CAP_PEM_REENROLLMENT) ) {
		status = cms_job_enroll(job, ConfigData, SessionData.Token,&chainJobId);
	}
	else if( 0 == strcasecmp(job->JobTypeId, CAP_FETCH_LOGS) ) {
		status = cms_job_fetchLogs(job, ConfigData, SessionData.Token);
	}
	else {
		log_error("%s::%s(%d) : Unimplemented support for job type %s" \
			      ".  Ignoring job request", \
			__FILE__, __FUNCTION__, __LINE__, job->JobTypeId);
	}

	if(chainJobId) {
		log_info("%s::%s(%d) : Completed job indicates that job %s should "
			    "be run immediately", \
				__FILE__, __FUNCTION__, __LINE__, chainJobId);
		chainJob = get_job_by_id(&JobList, chainJobId);
		if(chainJob) {
			(void)run_job(chainJob);
		}
		else {
			log_info("%s::%s(%d) : Job %s could not be found in the scheduled "
				     "jobs list, and will not be run",\
				      __FILE__, __FUNCTION__, __LINE__, chainJobId);
		}
	}

	free(chainJobId);
	return status;
} /* run_job */

/**
 *	Initialize the data structures, ssl, the configuration, etc.
 *
 *	@param  - [Input] argc the # of command line arguments
 *	@param  - [Input] argv the array of command line argument strings
 *	@return - success 1
 *			  failure 0
 */
int init_platform( int argc, char* argv[] )
{
	/***************************************************************************
	 * 0. Parse the command line parameters.
	 **************************************************************************/
	log_trace("%s::%s(%d) : Parsing Parameters", \
		__FILE__, __FUNCTION__, __LINE__);
	if ( 0 == parse_parameters( argc, &argv[0] ) ) {
		log_error("%s::%s(%d) : Failed to parse command line parameters",
					__FILE__, __FUNCTION__, __LINE__);
		return 0;
	}

	/***************************************************************************
	  1. If we are using a TPM, then initialize it & set it to be the source for
	     all cryptographic calls to openSSL
	 **************************************************************************/
#ifdef __TPM__
  log_trace("%s::%s(%d) : Initializing TPM engine", \
  	__FILE__, __FUNCTION__, __LINE__);
	e = initialize_engine( engine_id );
	if ( !e )
	{
		log_error( "%s::%s(%d) : ERROR getting engine %s", \
			__FILE__, __FUNCTION__, __LINE__, engine_id);
		return 0;
	}
#endif

	/***************************************************************************
	 * 2. Initalize the SSL wrapper and curl
	 **************************************************************************/
	ssl_init();

	log_trace("%s::%s(%d) : Initializing cURL", \
		__FILE__, __FUNCTION__, __LINE__);
	if ( 0 != curl_global_init(CURL_GLOBAL_DEFAULT) ) {
		log_error("%s::%s(%d) : Error initializing cURL", 
			       __FILE__, __FUNCTION__, __LINE__);
		return 0;
	}
	curlLoaded = true;

	/***************************************************************************
	* 3. Load the configuration data
	***************************************************************************/
	log_trace("%s::%s(%d) : Loading configuration data",
		__FILE__, __FUNCTION__, __LINE__);
	ConfigData = config_load();
	if(!ConfigData)	{
		log_error("%s::%s(%d) : Unable to load configuration. Exiting", \
			__FILE__, __FUNCTION__, __LINE__);
		return 0;
	}

	/***************************************************************************
	 * 4. If required, serialize the agent
	 **************************************************************************/
	if (ConfigData->Serialize) {
		log_trace("%s::%s(%d) : Serialize -> true",  \
			__FILE__,  __FUNCTION__, __LINE__);
		int x = do_serialization( ConfigData );
		if ( !x ) {
			log_error("%s::%s(%d) : Serialization failed", \
				__FILE__,  __FUNCTION__, __LINE__);
			return 0;
		}
	}

	return 1;
} /* init_platform */

/**
 * Free any dynamic memory that was allocated and not released yet.
 * Clean up the curl, ssl, and crypto layers.
 *
 * @param  - none
 * @return - success : true
 *           failure : false
 */
bool release_platform(void)
{
	bool bResult = false;

	if (NULL != ConfigData)	{
		log_trace("%s::%s(%d) : Free config data", \
			__FILE__, __FUNCTION__, __LINE__);
		ConfigData_free( ConfigData );
	}

	if ( true == curlLoaded ) {
		log_trace("%s::%s(%d) : Cleaning up curl before exiting",
			       __FILE__, __FUNCTION__, __LINE__);
		curl_global_cleanup();
		curlLoaded = false;
	}

#ifdef __TPM__
	if ( e ) ENGINE_free( e );
#endif

	ssl_cleanup(); 

	bResult = true;
	return bResult;
} /* release_platform */

/**
 *	@fn int main(int argc, char* argv[])
 *	Main program entry point.  This controls all flow.
 *	@retval EXIT_SUCCESS if successful
 *	@retval EXIT_FAILURE if failure.
 */
int main( int argc, char* argv[] )
{
	/***************************************************************************
	 * 0. Initialize items based on command line, config.json, and #defines
	 **************************************************************************/
 	if ( !init_platform( argc, &argv[0] ) )	{
		log_error("%s::%s(%d) : Failed to initialize platform",  \
			__FILE__, __FUNCTION__, __LINE__);
		goto error_exit;
	}

    /***************************************************************************
	 * 1. Prepare for the first time through the while loop; force immediate
	 *    session generation.
	 **************************************************************************/
	SessionData.UnreachableCount = 0;
	SessionData.Interval = 30;
	SessionData.NextExecution = time(NULL);
	int firstPass = 1;

    /***************************************************************************
	 * The main loop
	 **************************************************************************/
	while(true)	{
		log_verbose("%s::%s(%d) : Waking up to look for work",  \
			__FILE__, __FUNCTION__, __LINE__);

		time_t now = time(NULL);

		if( (SessionData.NextExecution <= now) ||
				( 1 == firstPass ) ) {
			if(strcmp(SessionData.Token, "") == 0) {
				log_verbose("%s::%s(%d) : Need a session",  \
					__FILE__, __FUNCTION__, __LINE__);
				register_session(ConfigData, &SessionData, &JobList, \
					AGENT_VERSION);
			}
			else {
				log_verbose("%s::%s(%d) : Need to heartbeat",  \
					__FILE__, __FUNCTION__, __LINE__);
				heartbeat_session(ConfigData, &SessionData, &JobList, \
					AGENT_VERSION);
			}
			firstPass = 0;
		}

		// Get current time again to deal with immediate jobs
		now = time(NULL); 

		struct SessionJob* job;
		while( NULL != (job = get_runnable_job(&JobList, now)) ) {
			int status = run_job(job);
			if(status == 1)	{
				strcpy(SessionData.Token, "");
				register_session(ConfigData, &SessionData, &JobList, \
					AGENT_VERSION);
			}
			else {
				schedule_job(&JobList, job, now);
			}
		}

		/* If the -d flag was used, then exit after the first inventory job
		 * runs
		 */
		if ( (exit_if_inventory_only) && \
			 ((inventory_ran) || (NULL == JobList)) ) {
			if (JobList) {
				clear_job_schedules(&JobList);
			}
			goto good_exit;
		}

		sleep(JOB_CHECK_SECONDS);
	} 

    /***************************************************************************
	 * Finalize & exit -- successful
	 **************************************************************************/
good_exit:
	release_platform();
	exit(EXIT_SUCCESS);

	/***************************************************************************
	 * Finalize & exit -- error
	 **************************************************************************/
error_exit:
	release_platform();
  	exit(EXIT_FAILURE);
} // main

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/