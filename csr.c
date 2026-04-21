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

#include "csr.h"
#include "global.h"
#include "logging.h"
#include <string.h>
#include <strings.h>

#ifdef __WOLF_SSL__
#include "wolfssl_wrapper/wolfssl_wrapper.h"
#else
#ifdef __OPEN_SSL__
#include "openssl_wrapper/openssl_wrapper.h"
#else
#ifdef __TPM__
#else
#endif
#endif
#endif

/******************************************************************************/
/*************************** GLOBAL VARIABLES *********************************/
/******************************************************************************/

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
 * @brief Generates an RSA keypair of the requested size.
 *
 * On TPM builds, validates that a non-empty key path is provided before
 * calling the SSL wrapper, as the TPM interface requires a storage path.
 * On non-TPM builds the path parameter is absent and the wrapper manages
 * key storage internally.
 *
 * @param[in] keySize  Bit length of the RSA key (e.g. 2048, 4096).
 * @param[in] path     (TPM builds only) Filesystem path for private key
 * storage.
 * @return true on success, false on failure.
 */
#if defined(__TPM__)
static bool generate_rsa_keypair_impl(int keySize, const char *path) {
    if (!path || 0 == strcasecmp("", path)) {
        log_error("%s::%s(%d) : Error, you must specify a private key path "
                  "when using a TPM",
                  LOG_INF);
        return false;
    }
    return ssl_generate_rsa_keypair(keySize, path);
}
#else
static bool generate_rsa_keypair_impl(int keySize) {
    return ssl_generate_rsa_keypair(keySize);
}
#endif /* __TPM__ */

/**
 * @brief Generates an ECC keypair of the requested curve size.
 *
 * TPM builds using the SLB9670 with the tpm2tss engine do not support ECC
 * key generation. This function logs the error and returns false in that case.
 *
 * @param[in] keySize  Curve size in bits (e.g. 256, 384).
 * @return true on success, false on failure or unsupported platform.
 */
static bool generate_ecc_keypair_impl(int keySize) {
#if defined(__TPM__)
    (void)keySize;
    log_error("%s::%s(%d) : Error, SLB9670 with tpm2tss engine does not "
              "support ECC keygen",
              LOG_INF);
    return false;
#else
    return ssl_generate_ecc_keypair(keySize);
#endif /* __TPM__ */
}

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/**
 * @brief Validates the key type and dispatches to the appropriate keypair
 * generator.
 *
 * Accepts "RSA" for RSA keys and either "ECC" or "ECDSA" for elliptic curve
 * keys. Any other key type is rejected with an error.
 *
 * @param[in] keyType  Case-insensitive key type string: "RSA", "ECC", or
 * "ECDSA".
 * @param[in] keySize  Bit length of the key to generate.
 * @param[in] path     (TPM builds only) Filesystem path for private key
 * storage.
 * @return true on success, false on failure or unrecognised key type.
 */
#if defined(__TPM__)
bool generate_keypair(const char *keyType, int keySize, const char *path)
#else
bool generate_keypair(const char *keyType, int keySize)
#endif
{
    if (!keyType) {
        log_error("%s::%s(%d) : Null pointer dereference - keyType is NULL",
                  LOG_INF);
        return false;
    }

    log_verbose("%s::%s(%d) : Generating key pair with type %s and length %d",
                LOG_INF, keyType, keySize);

    if (strcasecmp(keyType, "RSA") == 0) {
#if defined(__TPM__)
        return generate_rsa_keypair_impl(keySize, path);
#else
        return generate_rsa_keypair_impl(keySize);
#endif
    }

    if (strcasecmp(keyType, "ECC") == 0 || strcasecmp(keyType, "ECDSA") == 0) {
        return generate_ecc_keypair_impl(keySize);
    }

    log_error("%s::%s(%d) : Invalid key type %s", LOG_INF, keyType);
    return false;
} /* generate_keypair */

/**
 * @brief Generates a CSR from the provided subject DN via the SSL wrapper.
 *
 * Delegates to ssl_generate_csr and translates the result into a status code.
 * The returned string is heap-allocated and must be freed by the caller.
 *
 * @param[in]  asciiSubject  Subject DN string (e.g.
 * "CN=host,OU=NA,O=Acme,C=US").
 * @param[out] csrLen        Receives the length of the returned CSR string.
 * @param[out] pMessage      Accumulates human-readable status messages.
 * @param[out] pStatus       Set to STAT_SUCCESS on success, STAT_ERR on
 * failure.
 * @return Heap-allocated PEM CSR string on success, NULL on failure.
 */
char *generate_csr(const char *asciiSubject, size_t *csrLen, char **pMessage,
                   enum AgentApiResultStatus *pStatus) {
    if (!csrLen || !pStatus) {
        log_error("%s::%s(%d) : Null pointer dereference - csrLen or pStatus "
                  "is NULL",
                  LOG_INF);
        return NULL;
    }

    *pStatus = STAT_UNK;

    char *csrString = ssl_generate_csr(asciiSubject, csrLen, pMessage);
    *pStatus = csrString ? STAT_SUCCESS : STAT_ERR;

    return csrString;
} /* generate_csr */

/**
 * @brief Saves a certificate and its private key to disk via the SSL wrapper.
 *
 * Delegates to ssl_save_cert_key and translates the result into a status code.
 * If keyPath is NULL or empty the SSL wrapper appends the encoded key to the
 * certificate file at storePath.
 *
 * @param[in]  storePath  Filesystem path for the certificate store.
 * @param[in]  keyPath    Filesystem path for the private key, or NULL to
 *                        embed the key in the store.
 * @param[in]  password   Password for private key encryption, or NULL.
 * @param[in]  cert       ASCII-encoded certificate string.
 * @param[out] pMessage   Accumulates human-readable status messages.
 * @param[out] pStatus    Set to STAT_SUCCESS on success, STAT_ERR on failure.
 * @return 0 on success, non-zero error code on failure.
 */
unsigned long save_cert_key(const char *storePath, const char *keyPath,
                            const char *password, const char *cert,
                            char **pMessage,
                            enum AgentApiResultStatus *pStatus) {
    if (!pStatus) {
        log_error("%s::%s(%d) : Null pointer dereference - pStatus is NULL",
                  LOG_INF);
        return 1;
    }

    unsigned long err =
        ssl_save_cert_key(storePath, keyPath, password, cert, pMessage);
    *pStatus = (err == 0) ? STAT_SUCCESS : STAT_ERR;

    return err;
} /* save_cert_key */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
