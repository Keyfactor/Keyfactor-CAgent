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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

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

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/
#define JOB_CHECK_SECONDS 10

/******************************************************************************/
/***************************** GLOBAL VARIABLES *******************************/
/******************************************************************************/
struct SessionInfo SessionData;
struct ScheduledJob* JobList;

#if defined(__OPEN_SSL__)
	char engine_id[21]; /* 20 Characters should be enough */
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
/**                                                                           */
/* Print out program command line switches to the stderr                      */
/* @param  - argv[0]                                                          */
/* @return - none                                                             */
/*                                                                            */
static void usage(char *program)
{
    uint16_t major = (uint16_t)((AGENT_VERSION) >> (16*3));
    uint16_t minor = (uint16_t)((AGENT_VERSION & 0x0000FFFFF00000000) >> (16*2));
    uint16_t build = (uint16_t)((AGENT_VERSION & 0x00000000FFFFF0000) >> 16);
    uint16_t revision = (uint16_t)(AGENT_VERSION & 0x000000000000FFFF);
    fprintf( stderr,
             "\nKeyfactor reference Linux-Agent v%hu.%hu.%hu.%hu",
             major, minor, build, revision
            );
    fprintf(stderr, "\n\n"
                    "Usage: %s [-a] [-c config_file] [-e engine_name] [-h] [-v] [-l loglevel]\n\n"
                    "\t-a, --addheader\t\t\tAdd the agent certificate to the HTTP header X-ARR-ClientCert\n"
                    "\t-c, --config\tconfig_file\tUse config_file instead of config.json for agent configuration\n"
                    "\t                         \t  where config_file is the path and filename of a properly formatted\n"
                    "\t                         \t  JSON configuration file for a Keyfactor Linux-Agent\n"
                    "\t-e, --engine\tengine_name\tUse the TPM engine engine_name for openSSL commands\n"
                    "\t                         \t  where engine_name is the name of a compatible tpm2tss engine\n"
                    "\t                         \t  build for use with the tpm2tss stack\n"
                    "\t-h, --hostname           \tUse the $HOSTNAME_$DATETIME for the agent's name and CN in the agent's certificate\n"
                    "\t-v, --verbose            \tTurn on verbose logging [for agent v1.x.x.x compatibility]\n"
                    "\t-l, --loglevel\tloglevel \tSet the logging level as follows:\n"
                    "\t                         \t  o = turn off logging\n"
                    "\t                         \t  e = error messages only\n"
                    "\t                         \t  i = information and error messages\n"
                    "\t                         \t  w = warning, information, and error messages\n"
                    "\t                         \t  v = verbose, warning, information, and error messages\n"
                    "\t                         \t  d = debug, verbose, warning, information, and error messages\n"
                    "\t                         \t  t = trace, debug, verbose, warning, information, and error messages\n"
                    , program
             );
    fprintf(stderr,
            "Examples:\n"
            "\t%s -ahl e \t Add the agent certificate to the header, set agent-name to $HOSTNAME, set error logging level\n"
            "\t%s -l t \t Set trace logging level\n"
            "\t%s -hl o \t Set agent-name to $HOSTNAME, turn off logging\n"
            "\t%s --help \t print out usage information\n"
            "\t%s -? \t print out usage information\n\n\n"
            ,program, program, program, program, program
            "%s -ahl e\n"
            "%s -l t\n"
            "%s -hl o\n",
            program, program, program
            );
} /* usage */

/**                                                                           */
/*	Parse command line switches and set the global variables associated       */
/*	with the switches.                                                        */
/*                                                                            */
/*	@param  - [Input] argc = # of arguments passed                            */
/*	@param  - [Input] const char *argv[] = the array of passed arguments      */
/*	@return - success : 1                                                     */
/*			  failure : 0                                                     */
/*                                                                            */
static int parse_parameters( int argc, char *argv[] )
{
    struct option long_options[] = {
            {"addheader", no_argument, 0, 'a'},
            {"config", required_argument, 0, 'c'},
            {"engine", required_argument, 0, 'e'},
            {"loglevel", required_argument, 0, 'l'},
            {"verbose", no_argument, 0, 'v'},
            {"help", no_argument, 0, '?'},
            {"hostname", no_argument, 0, 'h'},
            {0,0,0,0}
    };
    int option_index = 0;

	bool foundConfig = false;
    int opt;
	#ifdef __TPM__
		int foundEngine = 0;
		const char* default_engine = "dynamic"; /* default engine to choose */
    #endif

    while (-1 != (opt = getopt_long(argc, argv, "ac:e:hvl:?", long_options, &option_index))) {
        switch (opt) {
            case 'a':
                /* Tell the system to add the client certificate in the header */
                add_client_cert_to_header = true;
                printf("%s::%s(%d) : Turning on add client cert to HTTP header flag\n", LOG_INF);
                break;
            case 'c':
                if (0 < strlen(optarg)) {
                    config_location = calloc(strlen(optarg) + 1, sizeof(*config_location));
                    if (NULL == config_location) {
                        printf("%s::%s(%d) : Out of memory", LOG_INF);
                        printf("%s::%s(%d) : Aborting...", LOG_INF);
#ifdef __MAKE_LIBRARY__
                        return(EXIT_FAILURE);
#else
                        exit(EXIT_FAILURE);
#endif
                    }
                    config_location = strncpy(config_location, optarg, strlen(optarg));
                    foundConfig = true;
                }
                break;
            case 'e':
#ifdef __TPM__
                printf("%s::%s(%d) :  TPM switch is enabled, setting the engine to %s\n", LOG_INF, optarg);
                char* eng = &engine_id[0];
                eng = strncpy( eng, optarg, 20 );
                foundEngine = 1;
#else
                printf("%s::%s(%d) : TPM switch not enabled, bypassing setting the openssl engine\n", LOG_INF);
#endif
                break;
            case 'h':
                /* Tell the system to use the host as the agent name if */
                /* Enroll on startup = true */
                use_host_as_agent_name = true;
                printf("%s::%s(%d) : Turning on use hostname as client name flag\n", LOG_INF);
                break;
            case 'v':
                printf("%s::%s(%d) : Setting Verbosity to Verbose\n", LOG_INF);
                log_set_verbosity(true);
                break;
            case 'l':
                printf("%s::%s(%d) : Setting logging level to ", LOG_INF);
                switch (optarg[0]) {
                    case 'v':
                        printf("verbose\n");
                        log_set_verbosity(true);
                        break;
                    case 'i':
                        printf("info\n");
                        log_set_info(true);
                        break;
                    case 'e':
                        printf("error\n");
                        log_set_error(true);
                        break;
                    case 'o':
                        printf("TURNING OFF LOGGING\n");
                        log_set_off(true);
                        break;
                    case 'd':
                        printf("debug\n");
                        log_set_debug(true);
                        break;
                    case 't':
                        printf("trace\n");
                        log_set_trace(true);
                        break;
                    case 'w':
                        printf("warning\n");
                        log_set_warn(true);
                        break;
                    case '?':
                        printf("Unknown logging level - setting log level to info\n");
                        log_set_info(true);
                        break;
                    default:
                        printf("Default level = info\n");
                        log_set_info(true);
                        break;
                }
                break;
            case '?':
                usage(argv[0]);
                return 0;
                break;
            default:
                usage(argv[0]);
                return 0;
                break;
        } /* switch */
    } /* while */

#ifdef __TPM__
	if ( !foundEngine )	{
		/* no -e switch means use the default engine */
		char* eng = &engine_id[0];
		eng = strncpy( eng, default_engine, 20 );
	}
#endif

	if ( !foundConfig )	{
		config_location = strdup( "config.json" );
	}

	return 1;
} /* parse_parameters */

#ifdef __TPM__
/**                                                                           */
/*  Try to initialize and open the engine passed to the function.             */
/*  Also set the engine as the default engine for all crypto functions        */
/*  @param  [Input] : engine_id The name of the engine to use e.g., tpm2tss   */
/*  @return success : Pointer to the initialized engine ENGINE*               */
/*          failure : NULL                                                    */
/*                                                                            */
static ENGINE* initialize_engine( const char *engine_id )
{
    ENGINE *e = NULL;
    ENGINE_load_builtin_engines();

    /* Set the engine pointer to an instance of the engine */
    if ( !( e = ENGINE_by_id( engine_id ) ) ) {
        log_error("%s::%s(%d) : Unable to find Engine: %s", LOG_INF, engine_id);
        return NULL;
    }
    log_verbose("%s::%s(%d) : Found Engine: %s", LOG_INF, engine_id);

    /* Initialize the engine for use */
    if ( !ENGINE_init(e) ) {
        log_error("%s::%s(%d) : Unable to initialize Engine: %s", LOG_INF, engine_id);
        return NULL;
    }
    log_verbose("%s::%s(%d) : Initialized Engine: %s", LOG_INF, engine_id);

    /* Register the engine for use with all algorithms */
    if ( !ENGINE_set_default( e, ENGINE_METHOD_ALL ) ) {
        log_error("%s::%s(%d) : Unable to set %s as the default engine", LOG_INF, engine_id);
        return NULL;
    }
    log_verbose("%s::%s(%d) : Sucessfully set %s as the default engine", LOG_INF, engine_id);

    ENGINE_register_complete( e );
    return e;
} /* initialize_engine */
#endif /* __TPM__ */

/**                                                                           */
/* Serialize the AgentName and CSR Subject using a json file.  In practice    */
/* this is a file that is held on a common data store (i.e. network drive)    */
/*  @param  : none                                                            */
/*	@return : success = 1                                                     */
/*		    : failure = 0                                                     */
/*                                                                            */
static int do_serialization( void )
{
	struct SerializeData* serial = serialize_load(ConfigData->SerialFile);
	if(!serial) {
		log_error("%s::%s(%d) : Unable to load Serialization file: %s",	
			LOG_INF,ConfigData->SerialFile);
		return 0;
	}
	log_trace("%s::%s(%d) : Freeing AgentName & CSRSubject", LOG_INF);
	free(ConfigData->AgentName);
	free(ConfigData->CSRSubject);
	ConfigData->AgentName = (char *)malloc(50);
	ConfigData->CSRSubject = (char *)malloc(50);
	if (!ConfigData->AgentName || !ConfigData->CSRSubject) {
		log_error("%s::%s(%d) : Out of memory",	LOG_INF);
		return 0;
	}
	sprintf(ConfigData->AgentName, "%s-%d", serial->ModelName,	serial->NextNumber);
	log_trace("%s::%s(%d) : ConfigData->AgentName set to: %s", LOG_INF,ConfigData->AgentName);
	sprintf(ConfigData->CSRSubject, "CN=%d", serial->NextNumber);
	log_trace("%s::%s(%d) : ConfigData->CSRSubject set to: %s", LOG_INF,ConfigData->CSRSubject);
	serial->NextNumber++;
	ConfigData->Serialize = false;
	config_save();
	if ( !(serialize_save(serial, ConfigData->SerialFile)) ) {
		log_error("%s::%s(%d) : Failed saving the serialization file", LOG_INF);
		return 0;
	}
	return 1;
} /* do_serialization */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**                                                                           */
/* Transfer the job to the appropriate function based on the job type.        */
/*                                                                            */
/* @param  [Input] : job = pointer to a job structure containing the Job type,*/
/*                         job guid, where to ask for configuration, etc.     */
/* @return job results as an integer                                          */
/*                                                                            */ 
int run_job(struct SessionJob* job)
{
	char* chainJobId = NULL;
	struct SessionJob* chainJob = NULL;
	int status = 0;

	if( 0 == strcasecmp(job->JobTypeId, CAP_PEM_INVENTORY) ) {
		status = cms_job_inventory(job, SessionData.Token);
		inventory_ran = true;
	} else if( 0 == strcasecmp(job->JobTypeId, CAP_PEM_MANAGEMENT) ) {
		status = cms_job_manage(job, SessionData.Token,&chainJobId);
	} else if( 0 == strcasecmp(job->JobTypeId, CAP_PEM_REENROLLMENT) ) {
		status = cms_job_enroll(job, SessionData.Token,&chainJobId);
	} else if( 0 == strcasecmp(job->JobTypeId, CAP_FETCH_LOGS) ) {
		status = cms_job_fetchLogs(job, SessionData.Token);
	} else {
		log_error("%s::%s(%d) : Unimplemented support for job type %s. Ignoring job request", LOG_INF, job->JobTypeId);
	}

#if defined (__RUN_CHAIN_JOBS__)
	if(chainJobId) {
		log_info("%s::%s(%d) : Completed job indicates that job %s should be run immediately", LOG_INF, chainJobId);
		chainJob = get_job_by_id(&JobList, chainJobId);
		if(chainJob) {
			(void)run_job(chainJob);
		} else {
			log_info("%s::%s(%d) : Job %s could not be found in the scheduled jobs list, and will not be run", LOG_INF, chainJobId);
		}
	}
#endif
	if (chainJobId) {
		free(chainJobId);
	}
	return status;
} /* run_job */

/**                                                                           */
/*	Initialize the data structures, ssl, the configuration, etc.              */
/*                                                                            */
/*	@param  - [Input] argc the # of command line arguments                    */
/*	@param  - [Input] argv the array of command line argument strings         */
/*	@return - success 1                                                       */
/*			  failure 0                                                       */
/*                                                                            */
int init_platform( int argc, char* argv[] )
{
	/**************************************************************************/
	/* 1. Parse the command line parameters.                                  */
	/**************************************************************************/
	log_trace("%s::%s(%d) : Parsing Parameters", LOG_INF);
	if ( 0 == parse_parameters( argc, &argv[0] ) )	{
		printf("%s::%s(%d) : Failed to parse command line parameters\n",	LOG_INF);
		return 0;
	}

	/**************************************************************************/
	/* 2. Load the configuration data                                         */
	/**************************************************************************/
	printf("%s::%s(%d) : Loading configuration data", LOG_INF);
	ConfigData = config_load();
	if(!ConfigData)	{
		printf("%s::%s(%d) : Unable to load configuration. Exiting\n", LOG_INF);
		return 0;
	}

	/**************************************************************************/
	/* 3. Initialize logging                                                  */
	/**************************************************************************/
	if ( !load_log_buffer() ) {
		printf("%s::%s(%d) : Failed to create a log buffer. Exiting\n", LOG_INF);
		return 0;
	}

	/**************************************************************************/
	/* 4. Validate configuration data is acceptable                           */
	/**************************************************************************/
	if (!validate_configuration()) {
		log_error("%s::%s(%d) : Configuration file has errors!", LOG_INF);
		return 0;
	}

	/**************************************************************************/
	/* 5. If we are using a TPM, then initialize it & set it to be the source */
	/*    for all cryptographic calls to openSSL                              */
	/**************************************************************************/
#ifdef __TPM__
  log_trace("%s::%s(%d) : Initializing TPM engine", LOG_INF);
	e = initialize_engine( engine_id );
	if ( !e ) {
		log_error( "%s::%s(%d) : ERROR getting engine %s", LOG_INF, engine_id);
		return 0;
	}
#endif

	/**************************************************************************/
	/* 6. Initalize the SSL wrapper and curl                                  */
	/**************************************************************************/
	ssl_init();

	log_trace("%s::%s(%d) : Initializing cURL", LOG_INF);
	if ( 0 != curl_global_init(CURL_GLOBAL_DEFAULT) ) {
		log_error("%s::%s(%d) : Error initializing cURL", LOG_INF);
		return 0;
	}
	curlLoaded = true;

	/**************************************************************************/
	/* 7. If required, serialize the agent                                    */
	/**************************************************************************/
	if (ConfigData->Serialize) {
		log_trace("%s::%s(%d) : Serialize -> true", LOG_INF);
		int x = do_serialization();
		if ( !x ) 
		{
			log_error("%s::%s(%d) : Serialization failed", LOG_INF);
			return 0;
		}
	}

	return 1;
} /* init_platform */

/**                                                                           */
/* Free any dynamic memory that was allocated and not released yet.           */
/* Clean up the curl, ssl, and crypto layers.                                 */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success : true                                                   */
/*           failure : false                                                  */
/*                                                                            */
bool release_platform(void)
{
	bool bResult = false;

	if (NULL == JobList) {
		log_debug("%s::%s(%d) : Job list is NULL", LOG_INF);
	} else {
		log_trace("%s::%s(%d) : Freeing the jobs", LOG_INF);
		clear_job_schedules(&JobList); /* Clean up any jobs in the queue */
	}

	if ( true == curlLoaded ) {
		log_trace("%s::%s(%d) : Cleaning up curl before exiting", LOG_INF);
		curl_global_cleanup();
		curlLoaded = false;
	}

#ifdef __TPM__
	if ( e ) ENGINE_free( e );
#endif

	ssl_cleanup(); 

	write_log_file();

	if (NULL != ConfigData)	{
		log_trace("%s::%s(%d) : Free config data\n", LOG_INF);
		ConfigData_free();
		if ( config_location ) {
			free( config_location );
		}
	}

	free_log_heap();

	bResult = true;
	return bResult;
} /* release_platform */

#if defined(__INFINITE_AGENT__)
/**                                                                           */
/* @fn _loop                                                                  */
/* Runs the infinite loop agent (OFF by default)                              */
/* @param  - none                                                             */
/* @return - none                                                             */
/*                                                                            */
static void main_loop( void )
{
	time_t now = 0;
	/**************************************************************************/
	/* 1. Prepare for the first time through the while loop; force immediate  */
	/*    session generation.                                                 */
	/**************************************************************************/
	SessionData.UnreachableCount = 0;
	SessionData.Interval = 30;
	SessionData.NextExecution = time(NULL);
	int firstPass = 1;

    /**************************************************************************/
	/* The main loop                                                          */
	/**************************************************************************/
	while(true)	{
		log_verbose("%s::%s(%d) : Waking up to look for work",  LOG_INF);
		now = time(NULL);

		if( (SessionData.NextExecution <= now) || ( 1 == firstPass ) ) {
			if(0 == strcmp(SessionData.Token, "")) {
				log_verbose("%s::%s(%d) : Need a session",  LOG_INF);
				register_session(&SessionData, &JobList, AGENT_VERSION);
			} else {
				log_verbose("%s::%s(%d) : Need to heartbeat",  LOG_INF);
				heartbeat_session(&SessionData, &JobList, AGENT_VERSION);
				write_log_file();
			}
			firstPass = 0;
		}

		/* Get current time again to deal with immediate jobs */
		now = time(NULL); 

		struct SessionJob* job;
		while( NULL != (job = get_runnable_job(&JobList, now)) ) {
			int status = run_job(job);
			if(1 == status)	{
				strcpy(SessionData.Token, "");
				clear_job_schedules(&JobList);
				register_session(&SessionData, &JobList, AGENT_VERSION);
			} else {
				schedule_job(&JobList, job, now);
			}
		}

		sleep(JOB_CHECK_SECONDS);
	}

	return;
} /* main_loop */
#else
/**                                                                           */
/* Runs a single loop agent (ON by default)                                   */
/* @param  - none                                                             */
/* @return - none                                                             */
/*                                                                            */
static void main_loop( void )
{
	time_t now = 0;
	/* First establish a session with the platform; the session registration */
	/* gets all of the jobs from the platform.  (Unless EnrollOnStartup is */
	//*true in the config file.  If EnrollOnStartup is true, the agent */
	/* makes a keypair & a CSR to send up to the platform for the agent)	*/
	log_verbose("%s::%s(%d) : Connecting to platform for session & job list", LOG_INF);
	register_session(&SessionData, &JobList, AGENT_VERSION);
	currentJob = JobList;

    /**************************************************************************/
	/*    The main loop, run all the jobs in the list, one at a time          */
	/*    based on the priority defined in session.c                          */
	/**************************************************************************/
	while(NULL != currentJob) {
		// Run the jobs based on the time queue
		now = time(NULL); 
		int status = run_job(currentJob->Job);
	    log_info("%s::%s(%d) : Advancing to job number %s", LOG_INF,
		NULL == currentJob->NextJob ? "NULL" : currentJob->NextJob->Job->JobId);
		currentJob = currentJob->NextJob;
	}

	log_info("%s::%s(%d) : No jobs to run -- Begin Agent Shutdown & Memory Release", LOG_INF);

	return;
} /* main_loop */
#endif

/**                                                                           */
/*	Main program entry point.  This controls all flow.                        */
/*  @param   [Input] argc = the number of command line arguments passed       */
/*  @param   [Input] argv = string array containing argc # of passed commands */
/*	@return  success : EXIT_SUCCESS                                           */
/*           failure : EXIT_FAILURE                                           */
/*                                                                            */
#ifdef __MAKE_LIBRARY__
int KF_main( int argc, char* argv[])
#else
int main( int argc, char* argv[] )
#endif
{
	time_t now = 0;
	/**************************************************************************/
	/* 1. Initialize items based on command line, config.json, and #defines   */
	/**************************************************************************/
 	if ( !init_platform( argc, &argv[0] ) ) {
		log_error("%s::%s(%d) : Failed to initialize platform", LOG_INF);
		goto error_exit;
	}

	/**************************************************************************/
	/* 2. Run the main loop (selected based on the defines in the makefile)   */
	/**************************************************************************/
	main_loop();

    /**************************************************************************/
	/* Finalize & exit -- successful                                          */
	/**************************************************************************/
good_exit:
	release_platform();
    printf("\n\n");
#ifdef __MAKE_LIBRARY__
    return(EXIT_SUCCESS);
#else
	exit(EXIT_SUCCESS);
#endif

	/**************************************************************************/
	/* Finalize & exit -- error                                               */
	/**************************************************************************/
error_exit:
	release_platform();
    printf("\n\n");
#ifdef __MAKE_LIBRARY__
    return(EXIT_FAILURE);
#else
  	exit(EXIT_FAILURE);
#endif
} /* main */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
