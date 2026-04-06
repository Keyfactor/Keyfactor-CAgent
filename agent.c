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
#include <strings.h>
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
#include "utils.h"

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/
#define JOB_CHECK_SECONDS 10

/******************************************************************************/
/***************************** GLOBAL VARIABLES *******************************/
/******************************************************************************/
SessionInfo_t   SessionData;
ScheduledJob_t *JobList;

/* KF v9 Adds in text capabilities                                            */
const char     *cap_pem_inventory    = "CertStores.PEM.Inventory";
const char     *cap_pem_management   = "CertStores.PEM.Management";
const char     *cap_pem_reenrollment = "CertStores.PEM.Reenrollment";

#if defined(__OPEN_SSL__)
char            engine_id[21];  /* 20 characters should be enough */
#endif

#if defined(__TPM__)
ENGINE         *e = NULL;
#endif

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/
static bool     curlLoaded             = false;
static bool     exit_if_inventory_only = false;
static bool     inventory_ran          = false;

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * @brief Prints usage information and version to stderr.
 *
 * @param[in] program  argv[0] — the name of the running executable.
 */
static void usage(char *program)
{
    uint16_t major    = (uint16_t)((AGENT_VERSION) >> (16 * 3));
    uint16_t minor    = (uint16_t)((AGENT_VERSION & 0x0000FFFFF00000000) >> (16 * 2));
    uint16_t build    = (uint16_t)((AGENT_VERSION & 0x00000000FFFFF0000) >> 16);
    uint16_t revision = (uint16_t)(AGENT_VERSION & 0x000000000000FFFF);

    fprintf(stderr,
            "\nKeyfactor reference Linux-Agent v%hu.%hu.%hu.%hu",
            major, minor, build, revision);
    fprintf(stderr, "\n\n"
            "Usage: %s [-a] [-c config_file] [-e engine_name] [-h] [-v] [-l loglevel]\n\n"
            "\t-a, --addheader\t\t\tAdd the agent certificate to the HTTP header X-ARR-ClientCert\n"
            "\t-c, --config\tconfig_file\tUse config_file instead of config.json for agent configuration\n"
            "\t                         \t  where config_file is the path and filename of a properly formatted\n"
            "\t                         \t  JSON configuration file for a Keyfactor Linux-Agent\n"
            "\t-e, --engine\tengine_name\tUse the TPM engine engine_name for openSSL commands\n"
            "\t                         \t  where engine_name is the name of a compatible tpm2tss engine\n"
            "\t                         \t  build for use with the tpm2tss stack\n"
            "\t-h, --hostname           \tUse the $HOSTNAME_$DATETIME for the agent name and CN\n"
            "\t-v, --verbose            \tTurn on verbose logging [for agent v1.x.x.x compatibility]\n"
            "\t-l, --loglevel\tloglevel \tSet the logging level as follows:\n"
            "\t                         \t  o = turn off logging\n"
            "\t                         \t  e = error messages only\n"
            "\t                         \t  i = information and error messages\n"
            "\t                         \t  w = warning, information, and error messages\n"
            "\t                         \t  v = verbose, warning, information, and error messages\n"
            "\t                         \t  d = debug, verbose, warning, information, and error messages\n"
            "\t                         \t  t = trace, debug, verbose, warning, information, and error messages\n"
            , program);
    fprintf(stderr,
            "Examples:\n"
            "\t%s -ahl e \t Add the agent certificate to the header, set agent-name to $HOSTNAME, set error logging level\n"
            "\t%s -l t \t Set trace logging level\n"
            "\t%s -hl o \t Set agent-name to $HOSTNAME, turn off logging\n"
            "\t%s --help \t print out usage information\n"
            "\t%s -? \t print out usage information\n\n\n"
            , program, program, program, program, program);
} /* usage */


/**
 * @brief Sets the active logging level from a single character code.
 *
 * Accepted codes: 'v' verbose, 'i' info, 'e' error, 'o' off,
 * 'd' debug, 't' trace, 'w' warning. Any unrecognised code defaults to info.
 *
 * @param[in] level  Single character identifying the desired log level.
 */
static void set_log_level(char level)
{
    printf("%s::%s(%d) : Setting logging level to ", LOG_INF);
    switch (level) {
        case 'v': printf("verbose\n");               log_set_verbosity(true); break;
        case 'i': printf("info\n");                  log_set_info(true);      break;
        case 'e': printf("error\n");                 log_set_error(true);     break;
        case 'o': printf("TURNING OFF LOGGING\n");   log_set_off(true);       break;
        case 'd': printf("debug\n");                 log_set_debug(true);     break;
        case 't': printf("trace\n");                 log_set_trace(true);     break;
        case 'w': printf("warning\n");               log_set_warn(true);      break;
        default:  printf("unknown — defaulting to info\n"); log_set_info(true); break;
    }
} /* set_log_level */


/**
 * @brief Allocates and stores the configuration file path from a CLI argument.
 *
 * Exits the process on allocation failure. Sets the global config_location.
 *
 * @param[in] path  Path string from the -c / --config command line option.
 * @return true on success, false if path is NULL or empty.
 */
static bool allocate_config_location(const char *path)
{
    if (!path || 0 == strlen(path)) {
        printf("%s::%s(%d) : Null or empty config path argument\n", LOG_INF);
        return false;
    }

    config_location = strdup(path);
    if (!config_location) {
        printf("%s::%s(%d) : Out of memory allocating config path\n", LOG_INF);
        printf("%s::%s(%d) : Aborting...\n", LOG_INF);
#ifdef __MAKE_LIBRARY__
        return false;
#else
        exit(EXIT_FAILURE);
#endif
    }
    return true;
} /* allocate_config_location */


/**
 * @brief Parses all command line arguments and sets corresponding global state.
 *
 * Sets add_client_cert_to_header, config_location, use_host_as_agent_name,
 * log level, and (on TPM builds) the engine_id. Defaults config_location to
 * "config.json" if -c is not provided.
 *
 * @param[in] argc  Argument count from main.
 * @param[in] argv  Argument vector from main.
 * @return 1 on success, 0 if usage was printed or a fatal error occurred.
 */
static int parse_parameters(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"addheader", no_argument,       0, 'a'},
        {"config",    required_argument, 0, 'c'},
        {"engine",    required_argument, 0, 'e'},
        {"loglevel",  required_argument, 0, 'l'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, '?'},
        {"hostname",  no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int  option_index = 0;
    bool foundConfig  = false;
    int  opt;

#ifdef __TPM__
    bool        foundEngine    = false;
    const char *default_engine = "dynamic";
#endif

    while (-1 != (opt = getopt_long(argc, argv, "ac:e:hvl:?",
                                    long_options, &option_index))) {
        switch (opt) {
            case 'a':
                add_client_cert_to_header = true;
                printf("%s::%s(%d) : Turning on add client cert to HTTP header flag\n",
                       LOG_INF);
                break;

            case 'c':
                if (allocate_config_location(optarg))
                    foundConfig = true;
                break;

            case 'e':
#ifdef __TPM__
                printf("%s::%s(%d) : TPM switch is enabled, setting the engine to %s\n",
                       LOG_INF, optarg);
                strncpy(engine_id, optarg, sizeof(engine_id) - 1);
                engine_id[sizeof(engine_id) - 1] = '\0';
                foundEngine = true;
#else
                printf("%s::%s(%d) : TPM switch not enabled, bypassing setting "
                       "the openssl engine\n", LOG_INF);
#endif
                break;

            case 'h':
                use_host_as_agent_name = true;
                printf("%s::%s(%d) : Turning on use hostname as client name flag\n",
                       LOG_INF);
                break;

            case 'v':
                printf("%s::%s(%d) : Setting Verbosity to Verbose\n", LOG_INF);
                log_set_verbosity(true);
                break;

            case 'l':
                set_log_level(optarg[0]);
                break;

            case '?':
            default:
                usage(argv[0]);
                return 0;
        }
    }

#ifdef __TPM__
    if (!foundEngine) {
        strncpy(engine_id, default_engine, sizeof(engine_id) - 1);
        engine_id[sizeof(engine_id) - 1] = '\0';
    }
#endif

    if (!foundConfig)
        config_location = strdup("config.json");

    return 1;
} /* parse_parameters */


#ifdef __TPM__
/**
 * @brief Loads, initialises, and registers an OpenSSL engine by name.
 *
 * Sets the engine as the default for all cryptographic operations and
 * registers it for all algorithms.
 *
 * @param[in] engine_id  Name of the engine to load (e.g. "tpm2tss").
 * @return Pointer to the initialised ENGINE on success, NULL on failure.
 */
static ENGINE *initialize_engine(const char *engine_id)
{
    ENGINE *e = NULL;
    ENGINE_load_builtin_engines();

    if (!(e = ENGINE_by_id(engine_id))) {
        log_error("%s::%s(%d) : Unable to find Engine: %s", LOG_INF, engine_id);
        return NULL;
    }
    log_verbose("%s::%s(%d) : Found Engine: %s", LOG_INF, engine_id);

    if (!ENGINE_init(e)) {
        log_error("%s::%s(%d) : Unable to initialize Engine: %s",
                  LOG_INF, engine_id);
        return NULL;
    }
    log_verbose("%s::%s(%d) : Initialized Engine: %s", LOG_INF, engine_id);

    if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
        log_error("%s::%s(%d) : Unable to set %s as the default engine",
                  LOG_INF, engine_id);
        return NULL;
    }
    log_verbose("%s::%s(%d) : Successfully set %s as the default engine",
                LOG_INF, engine_id);

    ENGINE_register_complete(e);
    return e;
} /* initialize_engine */
#endif /* __TPM__ */


/**
 * @brief Initialises the logging subsystem.
 *
 * @return true if the log buffer was created successfully, false otherwise.
 */
static bool init_logging(void)
{
    if (!load_log_buffer()) {
        printf("%s::%s(%d) : Failed to create a log buffer. Exiting\n", LOG_INF);
        return false;
    }
    return true;
} /* init_logging */


/**
 * @brief Initialises the TPM engine and registers it with OpenSSL.
 *
 * No-op on non-TPM builds. On TPM builds, calls initialize_engine with
 * the globally configured engine_id.
 *
 * @return true on success, false if engine initialisation fails.
 */
static bool init_tpm_engine(void)
{
#ifdef __TPM__
    log_trace("%s::%s(%d) : Initializing TPM engine", LOG_INF);
    e = initialize_engine(engine_id);
    if (!e) {
        log_error("%s::%s(%d) : ERROR getting engine %s", LOG_INF, engine_id);
        return false;
    }
#endif
    return true;
} /* init_tpm_engine */


/**
 * @brief Initialises the SSL wrapper and the libcurl global state.
 *
 * @return true on success, false if curl initialisation fails.
 */
static bool init_ssl_and_curl(void)
{
    ssl_init();

    log_trace("%s::%s(%d) : Initializing cURL", LOG_INF);
    if (0 != curl_global_init(CURL_GLOBAL_DEFAULT)) {
        log_error("%s::%s(%d) : Error initializing cURL", LOG_INF);
        return false;
    }
    curlLoaded = true;
    return true;
} /* init_ssl_and_curl */


/**
 * @brief Frees the scheduled job list if it is populated.
 */
static void cleanup_jobs(void)
{
    if (!JobList) {
        log_debug("%s::%s(%d) : Job list is NULL", LOG_INF);
        return;
    }
    log_trace("%s::%s(%d) : Freeing the jobs", LOG_INF);
    clear_job_schedules(&JobList);
} /* cleanup_jobs */


/**
 * @brief Cleans up the libcurl global state if curl was successfully loaded.
 */
static void cleanup_curl(void)
{
    if (!curlLoaded)
        return;
    log_trace("%s::%s(%d) : Cleaning up curl before exiting", LOG_INF);
    curl_global_cleanup();
    curlLoaded = false;
} /* cleanup_curl */


/**
 * @brief Frees the ConfigData structure and the config_location path string.
 */
static void cleanup_config(void)
{
    if (!ConfigData)
        return;
    log_trace("%s::%s(%d) : Free config data", LOG_INF);
    ConfigData_free();
    if (config_location) {
        free(config_location);
        config_location = NULL;
    }
} /* cleanup_config */


/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * @brief Dispatches a single job to the appropriate handler by job type.
 *
 * Sets inventory_ran to true when an inventory job completes. Logs an error
 * for any unrecognised job type.
 *
 * @param[in]  job         Job to execute.
 * @param[out] chainJobId  Receives a follow-on job ID if the handler provides one.
 * @return Job handler return code, or 0 for an unrecognised job type.
 */
static int dispatch_job_by_type(SessionJob_t *job, char **chainJobId)
{
    if (0 == strcasecmp(job->JobTypeId, CAP_PEM_INVENTORY)) {
        int status = cms_job_inventory(job, SessionData.Token);
        inventory_ran = true;
        return status;
    }
    if (0 == strcasecmp(job->JobTypeId, CAP_PEM_MANAGEMENT))
        return cms_job_manage(job, SessionData.Token, chainJobId);

    if (0 == strcasecmp(job->JobTypeId, CAP_PEM_REENROLLMENT))
        return cms_job_enroll(job, SessionData.Token, chainJobId);

    log_error("%s::%s(%d) : Unimplemented support for job type %s. "
              "Ignoring job request", LOG_INF, job->JobTypeId);
    return 0;
} /* dispatch_job_by_type */


/**
 * @brief Looks up and executes a chained follow-on job if one was provided.
 *
 * Only active when __RUN_CHAIN_JOBS__ is defined. Logs a warning if the
 * chained job ID cannot be found in the current schedule.
 *
 * @param[in] chainJobId  Job ID string returned by the preceding job handler.
 */
static void run_chain_job_if_needed(const char *chainJobId)
{
#if defined(__RUN_CHAIN_JOBS__)
    if (!chainJobId)
        return;

    log_info("%s::%s(%d) : Completed job indicates that job %s should be "
             "run immediately", LOG_INF, chainJobId);

    SessionJob_t *chainJob = get_job_by_id(&JobList, chainJobId);
    if (chainJob) {
        (void)run_job(chainJob);
    } else {
        log_info("%s::%s(%d) : Job %s could not be found in the scheduled "
                 "jobs list, and will not be run", LOG_INF, chainJobId);
    }
#else
    (void)chainJobId;
#endif
} /* run_chain_job_if_needed */


/**
 * @brief Dispatches a job by type and runs any chained follow-on job.
 *
 * @param[in] job  Pointer to the job structure containing the job type,
 *                 GUID, and endpoint configuration.
 * @return Return code from the job handler.
 */
int run_job(SessionJob_t *job)
{
    char *chainJobId = NULL;

    int status = dispatch_job_by_type(job, &chainJobId);

    if (0 == status)
        run_chain_job_if_needed(chainJobId);

    if (chainJobId)
        free(chainJobId);

    return status;
} /* run_job */


/**
 * @brief Initialises all platform components required before the main loop.
 *
 * Sequentially: parses CLI arguments, loads configuration, initialises
 * logging, validates configuration, initialises the TPM engine (if enabled),
 * then initialises SSL and curl.
 *
 * @param[in] argc  Argument count from main.
 * @param[in] argv  Argument vector from main.
 * @return 1 on success, 0 on any initialisation failure.
 */
int init_platform(int argc, char *argv[])
{
    log_trace("%s::%s(%d) : Parsing Parameters", LOG_INF);
    if (0 == parse_parameters(argc, argv)) {
        printf("%s::%s(%d) : Failed to parse command line arguments\n", LOG_INF);
        return 0;
    }

    printf("%s::%s(%d) : Loading configuration data\n", LOG_INF);
    ConfigData = config_load();
    if (!ConfigData) {
        printf("%s::%s(%d) : Unable to load configuration. Exiting\n", LOG_INF);
        return 0;
    }

    if (!init_logging())
        return 0;

    if (!validate_configuration()) {
        log_error("%s::%s(%d) : Configuration file has errors!", LOG_INF);
        return 0;
    }

    if (!init_tpm_engine())
        return 0;

    if (!init_ssl_and_curl())
        return 0;

    return 1;
} /* init_platform */


/**
 * @brief Releases all platform resources and resets global state.
 *
 * Frees the job list, shuts down curl, releases the TPM engine (if enabled),
 * cleans up the SSL layer, flushes the log buffer to disk, frees the
 * configuration, and releases the log heap.
 *
 * @return Always returns true.
 */
bool release_platform(void)
{
    cleanup_jobs();
    cleanup_curl();

#ifdef __TPM__
    if (e) {
        ENGINE_free(e);
        e = NULL;
    }
#endif

    ssl_cleanup();
    write_log_file();
    cleanup_config();
    free_log_heap();

    return true;
} /* release_platform */


/**
 * @brief Iterates through all scheduled jobs and executes each in order.
 *
 * Jobs are run in the priority order established by register_session.
 *
 * @return true if all jobs succeeded, false if any job returned non-zero.
 */
static bool execute_all_jobs(void)
{
    bool success = true;

    while (currentJob) {
        if (0 != run_job(currentJob->Job))
            success = false;

        log_info("%s::%s(%d) : Advancing to job number %s", LOG_INF,
                 currentJob->NextJob ? currentJob->NextJob->Job->JobId : "NULL");
        currentJob = currentJob->NextJob;
    }

    return success;
} /* execute_all_jobs */


/**
 * @brief Registers a session with the platform and runs all scheduled jobs.
 *
 * Establishes the session (which retrieves the job list), then delegates
 * to execute_all_jobs to run them in priority order.
 *
 * @return true if the session was established and all jobs succeeded,
 *         false otherwise.
 */
static bool main_loop(void)
{
    log_verbose("%s::%s(%d) : Connecting to platform for session & job list",
                LOG_INF);
    if (0 != register_session(&SessionData, &JobList, AGENT_VERSION)) {
        log_error("%s::%s(%d) : Failed to register session with platform",
                  LOG_INF);
        return false;
    }
    currentJob = JobList;

    bool success = execute_all_jobs();
    log_info("%s::%s(%d) : No jobs to run -- Begin Agent Shutdown & Memory Release",
             LOG_INF);
    return success;
} /* main_loop */


/**
 * @brief Main program entry point.
 *
 * Initialises the platform, runs the main job loop, releases all resources,
 * and exits with the appropriate status code.
 *
 * @param[in] argc  Number of command line arguments.
 * @param[in] argv  Array of command line argument strings.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on any error.
 */
#ifdef __MAKE_LIBRARY__
int KF_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    bool success = true;

    if (!init_platform(argc, argv)) {
        log_error("%s::%s(%d) : Failed to initialize platform", LOG_INF);
        success = false;
    }

    if (success && !main_loop())
        success = false;

    release_platform();
    printf("\n\n");

#ifdef __MAKE_LIBRARY__
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
#else
    exit(success ? EXIT_SUCCESS : EXIT_FAILURE);
#endif
} /* main */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
