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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include "config.h"
#include "logging.h"
#include "lib/json.h"
#include "utils.h"
#include "global.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/
#define DATE_TIME_LEN 14        /* YYYYMMDDHHMMSS */
#define STR_OR_NOT_SET(s) ((s) ? (s) : "(not set)")

/******************************************************************************/
/*************************** GLOBAL VARIABLES *********************************/
/******************************************************************************/
bool            config_loaded          = false;
ConfigData_t   *ConfigData;
char           *config_location        = NULL;
bool            use_host_as_agent_name = false;

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * @brief Prints all configuration parameters to stdout.
 *
 * @param[in] data  Pointer to the configuration structure to display.
 */
static void print_config(const ConfigData_t *data)
{
    if (!data) {
        log_error("%s::%s(%d) : Null pointer dereference - data is NULL", LOG_INF);
        return;
    }
    printf("\n\n          AgentId = %s\n",            STR_OR_NOT_SET(data->AgentId));
    printf("          AgentName = %s\n",              STR_OR_NOT_SET(data->AgentName));
    printf("          ClientParameterPath = %s\n",    STR_OR_NOT_SET(data->ClientParameterPath));
    printf("          Hostname = %s\n",               STR_OR_NOT_SET(data->Hostname));
    printf("          Password = %s\n",               data->Password        ? "********" : "(not set)");
    printf("          Username = %s\n",               STR_OR_NOT_SET(data->Username));
    printf("          VirtualDirectory = %s\n",       STR_OR_NOT_SET(data->VirtualDirectory));
    printf("          TrustStore = %s\n",             STR_OR_NOT_SET(data->TrustStore));
    printf("          UseAgentCert = %s\n",           data->UseAgentCert    ? "true" : "false");
    printf("          AgentCert = %s\n",              STR_OR_NOT_SET(data->AgentCert));
    printf("          AgentKey = %s\n",               STR_OR_NOT_SET(data->AgentKey));
    printf("          AgentKeyPassword = %s\n",       data->AgentKeyPassword ? "********" : "(not set)");
    printf("          UseSsl = %s\n",                 data->UseSsl          ? "true" : "false");
    printf("          CSRKeyType = %s\n",             STR_OR_NOT_SET(data->CSRKeyType));
    printf("          CSRKeySize = %d\n",             data->CSRKeySize);
    printf("          CSRSubject = %s\n",             STR_OR_NOT_SET(data->CSRSubject));
    printf("          EnrollOnStartup = %s\n",        data->EnrollOnStartup ? "true" : "false");
    printf("          UseBootstrapCert = %s\n",       data->UseBootstrapCert ? "true" : "false");
    printf("          BootstrapCert = %s\n",          STR_OR_NOT_SET(data->BootstrapCert));
    printf("          BootstrapKey = %s\n",           STR_OR_NOT_SET(data->BootstrapKey));
    printf("          LogFile = %s\n",                STR_OR_NOT_SET(data->LogFile));
    printf("          httpRetries = %d\n",            data->httpRetries);
    printf("          retryInterval = %d\n",          data->retryInterval);
    printf("\n\n");
} /* print_config */


/**
 * @brief Validates the fields required when UseAgentCert is true.
 *
 * Checks that CSRSubject, AgentCert, and AgentKey are present and that the
 * subject DN is at least four characters (minimum: "CN=x").
 *
 * @return true if all agent certificate fields are valid, false otherwise.
 */
static bool validate_agent_cert_config(void)
{
    if (!ConfigData->CSRSubject) {
        log_error("%s::%s(%d) : Agent CSR subject must exist", LOG_INF);
        return false;
    }
    if (4 > strlen(ConfigData->CSRSubject)) {
        log_error("%s::%s(%d) : Agent CSR subject must minimally be CN=x "
                  "where x is a single character", LOG_INF);
        return false;
    }
    if (!ConfigData->AgentCert) {
        log_error("%s::%s(%d) : Agent Cert file must be in the config.json file",
                  LOG_INF);
        return false;
    }
    if (!ConfigData->AgentKey) {
        log_error("%s::%s(%d) : Agent Key file must be in the config.json file",
                  LOG_INF);
        return false;
    }
    return true;
} /* validate_agent_cert_config */


/**
 * @brief Validates the fields required when UseBootstrapCert is true.
 *
 * @return true if BootstrapCert and BootstrapKey are present, false otherwise.
 */
static bool validate_bootstrap_cert_config(void)
{
    if (!ConfigData->BootstrapCert) {
        log_error("%s::%s(%d) : BootstrapCert filename is required if "
                  "UseBootstrapCert is true", LOG_INF);
        return false;
    }
    if (!ConfigData->BootstrapKey) {
        log_error("%s::%s(%d) : BootstrapKey filename is required if "
                  "UseBootstrapCert is true", LOG_INF);
        return false;
    }
    return true;
} /* validate_bootstrap_cert_config */


/**
 * @brief Checks that all required configuration fields are populated.
 *
 * Validates AgentName, AgentId, Hostname, and any fields conditional on
 * UseAgentCert or UseBootstrapCert being enabled.
 *
 * @return true if all minimum requirements are met, false otherwise.
 */
static bool minimum_config_requirements(void)
{
    if (!ConfigData) {
        log_error("%s::%s(%d) : Null pointer dereference - ConfigData is NULL",
                  LOG_INF);
        return false;
    }
    if (!ConfigData->AgentName) {
        log_error("%s::%s(%d) : Agent name is required in config file", LOG_INF);
        return false;
    }
    if (1 > strlen(ConfigData->AgentName)) {
        log_error("%s::%s(%d) : Agent name must be at least one character long",
                  LOG_INF);
        return false;
    }
    if (!ConfigData->AgentId) {
        log_error("%s::%s(%d) : AgentId field must exist", LOG_INF);
        return false;
    }
    if (ConfigData->UseAgentCert && !validate_agent_cert_config())
        return false;

    if (!ConfigData->Hostname) {
        log_error("%s::%s(%d) : Hostname must be in the config.json file",
                  LOG_INF);
        return false;
    }
    if (7 > strlen(ConfigData->Hostname)) {
        log_error("%s::%s(%d) : Minimal hostname is 7 characters long x.x.x.x",
                  LOG_INF);
        return false;
    }
    if (ConfigData->UseBootstrapCert && !validate_bootstrap_cert_config())
        return false;

    return true;
} /* minimum_config_requirements */


/**
 * @brief Validates that a single cert or key path is a file in an existing directory.
 *
 * Checks that the path itself is not a directory, then extracts the parent
 * directory component and verifies it exists.
 *
 * @param[in] path  Filesystem path to validate.
 * @return true if the path is a valid file location, false otherwise.
 */
static bool validate_cert_file_path(const char *path)
{
    if (is_directory(path)) {
        log_error("%s::%s(%d) : %s is a directory. "
                  "It must be a <path>/<filename>.", LOG_INF, path);
        return false;
    }

    char *parentDir = get_prefix_substring(path, '/');
    if (!parentDir)
        return true;    /* Relative path with no directory component — OK */

    bool exists = is_directory(parentDir);
    if (!exists)
        log_error("%s::%s(%d) : Directory %s does not exist",
                  LOG_INF, parentDir);

    free(parentDir);
    return exists;
} /* validate_cert_file_path */


/**
 * @brief Verifies that the agent certificate and key paths are valid file locations.
 *
 * Only runs when UseAgentCert is true. Delegates each path to
 * validate_cert_file_path.
 *
 * @return true if both paths are valid, false otherwise.
 */
static bool agent_directory_exists(void)
{
    if (!ConfigData->UseAgentCert) {
        log_debug("%s::%s(%d) : Skipping agent directory check for certs and such",
                  LOG_INF);
        return true;
    }

    if (!validate_cert_file_path(ConfigData->AgentCert))
        return false;

    if (!validate_cert_file_path(ConfigData->AgentKey))
        return false;

    return true;
} /* agent_directory_exists */


/**
 * @brief Validates the configured key type and, for ECC, the key size.
 *
 * Accepts RSA (any reasonable size) and ECC/ECDSA (256, 384, or 521 bits only).
 *
 * @return true if the key type and size are valid, false otherwise.
 */
static bool keypair_sanity_check(void)
{
    if (!ConfigData || !ConfigData->CSRKeyType) {
        log_error("%s::%s(%d) : Null pointer dereference - ConfigData or "
                  "CSRKeyType is NULL", LOG_INF);
        return false;
    }

    if (0 == strcasecmp("ecc", ConfigData->CSRKeyType) ||
        0 == strcasecmp("ecdsa", ConfigData->CSRKeyType)) {
        switch (ConfigData->CSRKeySize) {
            case 256:
            case 384:
            case 521:
                return true;
            default:
                log_error("%s::%s(%d) : %d is not an implemented ECC keysize",
                          LOG_INF, ConfigData->CSRKeySize);
                return false;
        }
    }

    if (0 == strcasecmp("rsa", ConfigData->CSRKeyType))
        return true;    /* RSA key sizes can be of any reasonable length */

    log_error("%s::%s(%d) : Error %s is an unknown key type",
              LOG_INF, ConfigData->CSRKeyType);
    return false;
} /* keypair_sanity_check */


/**
 * @brief Retrieves the OS hostname into the provided buffer.
 *
 * @param[out] buf     Buffer to receive the null-terminated hostname.
 * @param[in]  bufLen  Size of the buffer in bytes.
 * @return true on success, false if gethostname fails.
 */
static bool get_os_hostname(char *buf, size_t bufLen)
{
    log_verbose("%s::%s(%d) : Retrieving hostname", LOG_INF);
    if (-1 == gethostname(buf, bufLen)) {
        log_error("%s::%s(%d) : Failed to retrieve hostname from host OS",
                  LOG_INF);
        return false;
    }
    log_info("%s::%s(%d) : Hostname found as %s", LOG_INF, buf);
    return true;
} /* get_os_hostname */


/**
 * @brief Retrieves the current UTC time formatted as YYYYMMDDHHMMSS.
 *
 * @param[out] buf     Buffer to receive the null-terminated datetime string.
 * @param[in]  bufLen  Size of the buffer in bytes (must be >= DATE_TIME_LEN + 1).
 * @return true on success, false if time() fails.
 */
static bool get_formatted_datetime(char *buf, size_t bufLen)
{
    time_t t;
    log_verbose("%s::%s(%d) : Retrieving time from OS", LOG_INF);
    if (!time(&t)) {
        log_error("%s::%s(%d) : Error getting time from OS", LOG_INF);
        return false;
    }
    struct tm *tm = gmtime(&t);
    (void)strftime(buf, bufLen, "%Y%m%d%H%M%S", tm);
    log_verbose("%s::%s(%d) : Date time is %s", LOG_INF, buf);
    return true;
} /* get_formatted_datetime */


/**
 * @brief Allocates and returns a "{hostname}_{datetime}" agent name string.
 *
 * @param[in] hostname  Null-terminated hostname string.
 * @param[in] datetime  Null-terminated YYYYMMDDHHMMSS datetime string.
 * @return Heap-allocated name string on success, NULL on allocation failure.
 *         Caller is responsible for freeing the returned string.
 */
static char *build_agent_name_string(const char *hostname, const char *datetime)
{
    size_t len = strlen(hostname) + 1 + strlen(datetime) + 1; /* host + _ + dt + \0 */
    char *name = calloc(len, sizeof(*name));
    if (!name) {
        log_error("%s::%s(%d) : Out of memory!", LOG_INF);
        return NULL;
    }
    (void)snprintf(name, len, "%s_%s", hostname, datetime);
    return name;
} /* build_agent_name_string */


/**
 * @brief Allocates and returns a "CN={hostname}_{datetime}" CSR subject string.
 *
 * @param[in] hostname  Null-terminated hostname string.
 * @param[in] datetime  Null-terminated YYYYMMDDHHMMSS datetime string.
 * @return Heap-allocated subject string on success, NULL on allocation failure.
 *         Caller is responsible for freeing the returned string.
 */
static char *build_csr_subject_string(const char *hostname, const char *datetime)
{
    size_t len = 3 + strlen(hostname) + 1 + strlen(datetime) + 1; /* "CN=" + host + _ + dt + \0 */
    char *subject = calloc(len, sizeof(*subject));
    if (!subject) {
        log_error("%s::%s(%d) : Out of memory!", LOG_INF);
        return NULL;
    }
    (void)snprintf(subject, len, "CN=%s_%s", hostname, datetime);
    return subject;
} /* build_csr_subject_string */


/**
 * @brief Assigns the computed agent name and CSR subject to the configuration.
 *
 * Takes ownership of both strings. Frees either string that has no corresponding
 * target field to assign to, preventing leaks when the config was not fully
 * initialised.
 *
 * @param[in] config   Configuration structure to update.
 * @param[in] name     Heap-allocated agent name string (ownership transferred).
 * @param[in] subject  Heap-allocated CSR subject string, or NULL (ownership transferred).
 */
static void assign_agent_name_to_config(ConfigData_t *config,
                                        char *name,
                                        char *subject)
{
    if (config->AgentName) {
        free(config->AgentName);
        config->AgentName = name;
        log_info("%s::%s(%d) : Agent name set to %s", LOG_INF, config->AgentName);
    } else {
        free(name);
    }

    if (config->UseAgentCert && config->CSRSubject) {
        free(config->CSRSubject);
        config->CSRSubject = subject;
        log_info("%s::%s(%d) : Agent subject set to %s", LOG_INF,
                 config->CSRSubject);
    } else {
        free(subject);
    }
} /* assign_agent_name_to_config */


/**
 * @brief Derives the agent name and CSR subject from the OS hostname and current time.
 *
 * Leaves AgentName and CSRSubject unmodified if any step fails. Builds the
 * name as "{hostname}_{YYYYMMDDHHMMSS}" and the subject as
 * "CN={hostname}_{YYYYMMDDHHMMSS}".
 *
 * @param[in,out] config  Configuration structure to update on success.
 */
static void set_agent_name(ConfigData_t *config)
{
    char hostbuffer[256];
    char tBuf[DATE_TIME_LEN + 1];

    if (!get_os_hostname(hostbuffer, sizeof(hostbuffer)))
        return;

    if (!get_formatted_datetime(tBuf, sizeof(tBuf)))
        return;

    char *name = build_agent_name_string(hostbuffer, tBuf);
    if (!name)
        return;

    char *subject = NULL;
    if (config->UseAgentCert) {
        subject = build_csr_subject_string(hostbuffer, tBuf);
        if (!subject) {
            free(name);
            return;
        }
    }

    assign_agent_name_to_config(config, name, subject);
} /* set_agent_name */


/**
 * @brief Resizes a malformed AgentId field to the correct UUID length.
 *
 * The platform occasionally returns a UUID shorter than UUID_LEN. This
 * function reallocates the field to the correct size so that downstream
 * code can safely write a full GUID if needed.
 *
 * @param[in,out] config  Configuration structure whose AgentId may be resized.
 */
static void validate_and_fix_agent_id(ConfigData_t *config)
{
    if (!config->AgentId)
        return;
    if ((UUID_LEN - 1) > strlen(config->AgentId)) {
        log_trace("%s::%s(%d) : Resizing agent id to %lu bytes",
                  LOG_INF, UUID_LEN * sizeof(*(config->AgentId)));
        char *tmp = realloc(config->AgentId,
                            UUID_LEN * sizeof(*(config->AgentId)));
        if (!tmp) {
            log_error("%s::%s(%d) : Out of memory resizing AgentId", LOG_INF);
            return;
        }
        config->AgentId = tmp;
    }
} /* validate_and_fix_agent_id */


/**
 * @brief Parses the agent certificate fields from a JSON node.
 *
 * Only called when UseAgentCert is true. Reads AgentCert, AgentKey,
 * AgentKeyPassword, CSRKeyType, CSRKeySize, and CSRSubject.
 *
 * @param[in,out] config  Configuration structure to populate.
 * @param[in]     root    Parsed JSON root node.
 */
static void parse_agent_cert_fields(ConfigData_t *config, JsonNode *root)
{
    config->AgentCert        = json_get_member_string(root, "AgentCert");
    config->AgentKey         = json_get_member_string(root, "AgentKey");
    config->AgentKeyPassword = json_get_member_string(root, "AgentKeyPassword");
    config->CSRKeyType       = json_get_member_string(root, "CSRKeyType");
    config->CSRKeySize       = json_get_member_number(root, "CSRKeySize", 0);
    config->CSRSubject       = json_get_member_string(root, "CSRSubject");
} /* parse_agent_cert_fields */


/**
 * @brief Parses all configuration fields from a JSON root node into a config structure.
 *
 * Delegates agent certificate fields to parse_agent_cert_fields when
 * UseAgentCert is true. Enforces a minimum httpRetries value of 1.
 *
 * @param[in,out] config  Configuration structure to populate.
 * @param[in]     root    Parsed JSON root node.
 */
static void parse_config_fields(ConfigData_t *config, JsonNode *root)
{
    config->AgentId = json_get_member_string(root, "AgentId");
    validate_and_fix_agent_id(config);

    config->AgentName           = json_get_member_string(root, "AgentName");
    config->ClientParameterPath = json_get_member_string(root, "ClientParameterPath");
    config->Hostname            = json_get_member_string(root, "Hostname");
    config->Password            = json_get_member_string(root, "Password");
    config->Username            = json_get_member_string(root, "Username");
    config->VirtualDirectory    = json_get_member_string(root, "VirtualDirectory");
    config->TrustStore          = json_get_member_string(root, "TrustStore");
    config->UseAgentCert        = json_get_member_bool(root, "UseAgentCert", true);

    if (config->UseAgentCert)
        parse_agent_cert_fields(config, root);

    config->UseSsl               = json_get_member_bool(root, "UseSsl", true);
    config->EnrollOnStartup      = json_get_member_bool(root, "EnrollOnStartup", false);
    config->UseBootstrapCert     = json_get_member_bool(root, "UseBootstrapCert", false);
    config->BootstrapCert        = json_get_member_string(root, "BootstrapCert");
    config->BootstrapKey         = json_get_member_string(root, "BootstrapKey");
    config->BootstrapKeyPassword = json_get_member_string(root, "BootstrapKeyPassword");
    config->LogFile              = json_get_member_string(root, "LogFile");
    /* NOTE: LogFileIndex is NOT stored in config — managed by logging.c
     * in a separate <LogFile>.index file for robustness */

    config->httpRetries  = json_get_member_number(root, "httpRetries", 1);
    if (1 > config->httpRetries)
        config->httpRetries = 1;

    config->retryInterval = json_get_member_number(root, "retryInterval", 1);
} /* parse_config_fields */


/**
 * @brief Reads the configuration file at config_location into the provided buffer.
 *
 * @param[out] buf     Buffer to receive the null-terminated file contents.
 * @param[in]  bufLen  Size of the buffer in bytes.
 * @return true on success, false if the file does not exist or cannot be opened.
 */
static bool read_config_file(char *buf, size_t bufLen)
{
    if (!file_exists(config_location)) {
        log_error("%s::%s(%d) : Either %s does not exist or is a directory",
                  LOG_INF, config_location);
        return false;
    }

    FILE *fp = fopen(config_location, "r");
    if (!fp) {
        log_error("%s::%s(%d) : Unable to open config file %s: %s",
                  LOG_INF, config_location, strerror(errno));
        return false;
    }

    size_t len = fread(buf, 1, bufLen - 1, fp);
    buf[len]   = '\0';
    fclose(fp);
    return true;
} /* read_config_file */


/**
 * @brief Writes a configuration string to the file at config_location.
 *
 * Appends a trailing newline after the JSON content.
 *
 * @param[in] confString  Null-terminated JSON configuration string to write.
 * @return true on success, false if the file cannot be opened for writing.
 */
static bool write_config_to_file(const char *confString)
{
    FILE *fp = fopen(config_location, "w");
    if (!fp) {
        log_error("%s::%s(%d) : Unable to open config file %s: %s",
                  LOG_INF, config_location, strerror(errno));
        return false;
    }

    const char eol = '\n';
    fwrite(confString, 1, strlen(confString), fp);
    fwrite(&eol, 1, 1, fp);
    fclose(fp);
    return true;
} /* write_config_to_file */


/**
 * @brief Appends identity and connection fields to the JSON object.
 *
 * Covers AgentId, AgentName, ClientParameterPath, Hostname, Password,
 * Username, and VirtualDirectory.
 *
 * @param[in,out] root  JSON object node to append fields to.
 */
static void append_identity_fields_to_json(JsonNode *root)
{
    if (ConfigData->AgentId)
        json_append_member(root, "AgentId",
                           json_mkstring(ConfigData->AgentId));
    if (ConfigData->AgentName)
        json_append_member(root, "AgentName",
                           json_mkstring(ConfigData->AgentName));
    if (ConfigData->ClientParameterPath)
        json_append_member(root, "ClientParameterPath",
                           json_mkstring(ConfigData->ClientParameterPath));
    if (ConfigData->Hostname)
        json_append_member(root, "Hostname",
                           json_mkstring(ConfigData->Hostname));
    if (ConfigData->Password)
        json_append_member(root, "Password",
                           json_mkstring(ConfigData->Password));
    if (ConfigData->Username)
        json_append_member(root, "Username",
                           json_mkstring(ConfigData->Username));
    if (ConfigData->VirtualDirectory)
        json_append_member(root, "VirtualDirectory",
                           json_mkstring(ConfigData->VirtualDirectory));
} /* append_identity_fields_to_json */


/**
 * @brief Appends TLS and agent certificate fields to the JSON object.
 *
 * Covers TrustStore, UseAgentCert, AgentCert, AgentKey, AgentKeyPassword,
 * CSRKeyType, CSRKeySize, and CSRSubject.
 *
 * @param[in,out] root  JSON object node to append fields to.
 */
static void append_agent_cert_fields_to_json(JsonNode *root)
{
    if (ConfigData->TrustStore)
        json_append_member(root, "TrustStore",
                           json_mkstring(ConfigData->TrustStore));
    json_append_member(root, "UseAgentCert",
                       json_mkbool(ConfigData->UseAgentCert));
    if (ConfigData->AgentCert)
        json_append_member(root, "AgentCert",
                           json_mkstring(ConfigData->AgentCert));
    if (ConfigData->AgentKey)
        json_append_member(root, "AgentKey",
                           json_mkstring(ConfigData->AgentKey));
    if (ConfigData->AgentKeyPassword)
        json_append_member(root, "AgentKeyPassword",
                           json_mkstring(ConfigData->AgentKeyPassword));
    if (ConfigData->CSRKeyType)
        json_append_member(root, "CSRKeyType",
                           json_mkstring(ConfigData->CSRKeyType));
    if (ConfigData->CSRKeySize)
        json_append_member(root, "CSRKeySize",
                           json_mknumber(ConfigData->CSRKeySize));
    if (ConfigData->CSRSubject)
        json_append_member(root, "CSRSubject",
                           json_mkstring(ConfigData->CSRSubject));
} /* append_agent_cert_fields_to_json */


/**
 * @brief Appends bootstrap certificate fields to the JSON object.
 *
 * Covers UseBootstrapCert, BootstrapCert, BootstrapKey, and BootstrapKeyPassword.
 *
 * @param[in,out] root  JSON object node to append fields to.
 */
static void append_bootstrap_fields_to_json(JsonNode *root)
{
    json_append_member(root, "UseBootstrapCert",
                       json_mkbool(ConfigData->UseBootstrapCert));
    if (ConfigData->BootstrapCert)
        json_append_member(root, "BootstrapCert",
                           json_mkstring(ConfigData->BootstrapCert));
    if (ConfigData->BootstrapKey)
        json_append_member(root, "BootstrapKey",
                           json_mkstring(ConfigData->BootstrapKey));
    if (ConfigData->BootstrapKeyPassword)
        json_append_member(root, "BootstrapKeyPassword",
                           json_mkstring(ConfigData->BootstrapKeyPassword));
} /* append_bootstrap_fields_to_json */


/**
 * @brief Appends operational and logging fields to the JSON object.
 *
 * Covers EnrollOnStartup, UseSsl, LogFile, httpRetries, and retryInterval.
 * NOTE: LogFileIndex is intentionally excluded — it is managed by logging.c
 * in a separate index file.
 *
 * @param[in,out] root  JSON object node to append fields to.
 */
static void append_operational_fields_to_json(JsonNode *root)
{
    json_append_member(root, "EnrollOnStartup",
                       json_mkbool(ConfigData->EnrollOnStartup));
    json_append_member(root, "UseSsl",
                       json_mkbool(ConfigData->UseSsl));
    if (ConfigData->LogFile)
        json_append_member(root, "LogFile",
                           json_mkstring(ConfigData->LogFile));
    if (ConfigData->httpRetries)
        json_append_member(root, "httpRetries",
                           json_mknumber(ConfigData->httpRetries));
    if (ConfigData->retryInterval)
        json_append_member(root, "retryInterval",
                           json_mknumber(ConfigData->retryInterval));
} /* append_operational_fields_to_json */


/**
 * @brief Appends a string segment to a heap-allocated URL via realloc.
 *
 * Returns the new pointer on success. On allocation failure, frees the
 * original URL to prevent a dangling pointer and returns NULL.
 *
 * @param[in] url      Heap-allocated URL string to extend (ownership transferred).
 * @param[in] segment  Null-terminated string to append.
 * @return Extended URL string on success, NULL on allocation failure.
 */
static char *url_append_segment(char *url, const char *segment)
{
    if (!url || !segment)
        return url;

    char *tmp = realloc(url, strlen(url) + strlen(segment) + 1);
    if (!tmp) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        free(url);
        return NULL;
    }
    strcat(tmp, segment);
    return tmp;
} /* url_append_segment */


/**
 * @brief Allocates and returns the base URL: "http(s)://{Hostname}".
 *
 * @return Heap-allocated base URL string on success, NULL on failure.
 */
static char *build_url_base(void)
{
    char *url = strdup(ConfigData->UseSsl ? "https://" : "http://");
    if (!url) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        return NULL;
    }
    log_trace("%s::%s(%d) : url = %s", LOG_INF, url);

    url = url_append_segment(url, ConfigData->Hostname);
    log_trace("%s::%s(%d) : Added Hostname, url = %s", LOG_INF, url);
    return url;
} /* build_url_base */


/**
 * @brief Appends "/{VirtualDirectory}" to the URL.
 *
 * @param[in] url  Heap-allocated URL to extend (ownership transferred).
 * @return Extended URL on success, NULL on allocation failure.
 */
static char *append_virtual_directory_to_url(char *url)
{
    url = url_append_segment(url, "/");
    url = url_append_segment(url, ConfigData->VirtualDirectory);
    log_trace("%s::%s(%d) : Added VirtualDirectory, url = %s", LOG_INF, url);
    return url;
} /* append_virtual_directory_to_url */


/**
 * @brief Strips the KeyfactorAgents/ prefix from relPath and appends it to the URL.
 *
 * Prepends a "/" separator if relPath does not begin with one.
 *
 * NOTE: The strip is a workaround for a platform v7.4+ bug that always
 * prepends "KeyfactorAgents/" to endpoints. Remove once the platform is fixed.
 *
 * @param[in] url      Heap-allocated URL to extend (ownership transferred).
 * @param[in] relPath  Relative endpoint path from the platform.
 * @return Extended URL on success, NULL on allocation failure.
 */
static char *append_relpath_to_url(char *url, const char *relPath)
{
    if (strcspn(relPath, "/") != 0) {
        url = url_append_segment(url, "/");
        log_trace("%s::%s(%d) : Added leading /, url = %s", LOG_INF, url);
    }

    log_trace("%s::%s(%d) : Stripping KeyfactorAgents/ from %s", LOG_INF, relPath);
    char *stripped = util_strip_string(relPath, "KeyfactorAgents/");
    log_trace("%s::%s(%d) : Stripped relPath = %s", LOG_INF, stripped);

    url = url_append_segment(url, stripped);

    if (stripped)
        free(stripped);

    return url;
} /* append_relpath_to_url */


/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * @brief Decodes a JSON configuration string into a ConfigData structure.
 *
 * Parses all fields, optionally derives the agent name from the OS hostname
 * and current time, and prints the configuration at verbose log level.
 *
 * Call this function directly if the configuration source is not a plain
 * file — for example, when the config is stored encrypted and must be
 * decoded before passing to this function.
 *
 * NOTE: The returned structure must be freed by calling ConfigData_free()
 * before the process exits.
 *
 * @param[in] buf  Null-terminated JSON configuration string.
 * @return Heap-allocated ConfigData structure on success, NULL on failure.
 */
ConfigData_t *config_decode(const char *buf)
{
    JsonNode *jsonRoot = json_decode(buf);
    if (!jsonRoot) {
        log_error("%s::%s(%d) : Contents of %s are not valid JSON",
                  LOG_INF, config_location);
        return NULL;
    }

    ConfigData_t *config = calloc(1, sizeof(ConfigData_t));
    if (!config) {
        log_error("%s::%s(%d) : Out of memory!", LOG_INF);
        json_delete(jsonRoot);
        return NULL;
    }

    parse_config_fields(config, jsonRoot);
    json_delete(jsonRoot);

    if (use_host_as_agent_name && config->EnrollOnStartup)
        set_agent_name(config);

    if (is_log_verbose()) {
        log_verbose("%s::%s(%d) : Config parameters follow:", LOG_INF);
        print_config(config);
    }

    config_loaded = true;
    return config;
} /* config_decode */


/**
 * @brief Loads and decodes the configuration from the file at config_location.
 *
 * @return Heap-allocated ConfigData structure on success, NULL on failure.
 */
ConfigData_t *config_load(void)
{
    char buf[MAX_CONFIG_FILE_LEN];

    if (!read_config_file(buf, sizeof(buf)))
        return NULL;

    return config_decode(buf);
} /* config_load */


/**
 * @brief Serialises the current ConfigData structure to a JSON string.
 *
 * Call this function directly if the output requires additional processing
 * before writing — for example, when the config must be encrypted before
 * saving to disk.
 *
 * @return Heap-allocated JSON string on success, NULL on failure.
 *         Caller is responsible for freeing the returned string.
 */
char *config_to_json(void)
{
    JsonNode *root = json_mkobject();

    append_identity_fields_to_json(root);
    append_agent_cert_fields_to_json(root);
    append_bootstrap_fields_to_json(root);
    append_operational_fields_to_json(root);

    char *confString = json_stringify(root, "\t");
    json_delete(root);
    return confString;
} /* config_to_json */


/**
 * @brief Serialises and saves the current configuration to config_location.
 *
 * @return true on success, false if serialisation or the file write fails.
 */
bool config_save(void)
{
    if (!config_location) {
        log_error("%s::%s(%d) : Null pointer dereference - "
                  "config_location is NULL", LOG_INF);
        return false;
    }

    char *confString = config_to_json();
    if (!confString) {
        log_error("%s::%s(%d) : config_to_json returned NULL", LOG_INF);
        return false;
    }

    bool result = write_config_to_file(confString);
    free(confString);
    return result;
} /* config_save */


/**
 * @brief Validates the loaded configuration before the agent starts.
 *
 * Checks minimum field requirements, agent directory paths, trust store
 * existence, and keypair validity. Should be called after logging is
 * initialised so errors are written to the log file.
 *
 * @return true if the configuration is valid, false otherwise.
 */
bool validate_configuration(void)
{
    log_debug("%s::%s(%d) : Checking config minimum requirements", LOG_INF);
    if (!minimum_config_requirements()) {
        log_error("%s::%s(%d) : Config missing minimum requirements", LOG_INF);
        return false;
    }
    log_debug("%s::%s(%d) : Config meets minimum requirements", LOG_INF);

    log_debug("%s::%s(%d) : Checking that the agent directory exists", LOG_INF);
    if (!agent_directory_exists()) {
        log_error("%s::%s(%d) : Agent configuration is bad", LOG_INF);
        return false;
    }
    log_debug("%s::%s(%d) : Agent directory exists", LOG_INF);

    log_debug("%s::%s(%d) : Checking that the trust store exists", LOG_INF);
    if (!file_exists(ConfigData->TrustStore)) {
        log_error("%s::%s(%d) : Trust store location is bad or file not found",
                  LOG_INF);
        return false;
    }
    log_debug("%s::%s(%d) : The trust store exists", LOG_INF);

    if (ConfigData->UseAgentCert) {
        log_debug("%s::%s(%d) : Checking that the keypair looks ok", LOG_INF);
        if (!keypair_sanity_check()) {
            log_error("%s::%s(%d) : Keypair is not valid", LOG_INF);
            return false;
        }
        log_debug("%s::%s(%d) : The keypair looks ok", LOG_INF);
    }

    log_verbose("%s::%s(%d) : Config meets minimum requirements", LOG_INF);
    return true;
} /* validate_configuration */


/**
 * @brief Constructs a full URL from the platform-supplied relative endpoint.
 *
 * Builds "http(s)://{Hostname}/{VirtualDirectory}/{relPath}", stripping the
 * "KeyfactorAgents/" prefix that platform v7.4+ mistakenly prepends to all
 * endpoint paths.
 *
 * @param[in] relPath         Relative endpoint URL from the platform.
 * @param[in] vdirFromConfig  If true, insert the configured VirtualDirectory.
 * @return Heap-allocated URL string on success, NULL on failure.
 *         Caller is responsible for freeing the returned string.
 */
char *config_build_url(const char *relPath, bool vdirFromConfig)
{
    if (!ConfigData || !relPath) {
        log_error("%s::%s(%d) : Unable to build url: Invalid arguments",
                  LOG_INF);
        return NULL;
    }

    char *url = build_url_base();
    if (!url)
        return NULL;

    if (vdirFromConfig)
        url = append_virtual_directory_to_url(url);

    if (url)
        url = append_relpath_to_url(url, relPath);

    log_trace("%s::%s(%d) : Final url = %s", LOG_INF, url);
    return url;
} /* config_build_url */


/**
 * @brief Frees all heap memory associated with the global ConfigData structure.
 *
 * Sets ConfigData to NULL after freeing to prevent dangling pointer access.
 * Resets config_loaded to false.
 */
void ConfigData_free(void)
{
    if (!ConfigData)
        return;

    if (ConfigData->AgentId)             { free(ConfigData->AgentId);             ConfigData->AgentId = NULL; }
    if (ConfigData->AgentName)           { free(ConfigData->AgentName);           ConfigData->AgentName = NULL; }
    if (ConfigData->ClientParameterPath) { free(ConfigData->ClientParameterPath); ConfigData->ClientParameterPath = NULL; }
    if (ConfigData->Hostname)            { free(ConfigData->Hostname);            ConfigData->Hostname = NULL; }
    if (ConfigData->Password)            { free(ConfigData->Password);            ConfigData->Password = NULL; }
    if (ConfigData->Username)            { free(ConfigData->Username);            ConfigData->Username = NULL; }
    if (ConfigData->VirtualDirectory)    { free(ConfigData->VirtualDirectory);    ConfigData->VirtualDirectory = NULL; }
    if (ConfigData->TrustStore)          { free(ConfigData->TrustStore);          ConfigData->TrustStore = NULL; }
    if (ConfigData->AgentCert)           { free(ConfigData->AgentCert);           ConfigData->AgentCert = NULL; }
    if (ConfigData->AgentKey)            { free(ConfigData->AgentKey);            ConfigData->AgentKey = NULL; }
    if (ConfigData->AgentKeyPassword)    { free(ConfigData->AgentKeyPassword);    ConfigData->AgentKeyPassword = NULL; }
    if (ConfigData->CSRKeyType)          { free(ConfigData->CSRKeyType);          ConfigData->CSRKeyType = NULL; }
    if (ConfigData->CSRSubject)          { free(ConfigData->CSRSubject);          ConfigData->CSRSubject = NULL; }
    if (ConfigData->LogFile)             { free(ConfigData->LogFile);             ConfigData->LogFile = NULL; }
    if (ConfigData->BootstrapCert)       { free(ConfigData->BootstrapCert);       ConfigData->BootstrapCert = NULL; }
    if (ConfigData->BootstrapKey)        { free(ConfigData->BootstrapKey);        ConfigData->BootstrapKey = NULL; }
    if (ConfigData->BootstrapKeyPassword){ free(ConfigData->BootstrapKeyPassword);ConfigData->BootstrapKeyPassword = NULL; }

    free(ConfigData);
    ConfigData    = NULL;
    config_loaded = false;
} /* ConfigData_free */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
