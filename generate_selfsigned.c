/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "logging.h"
#include "csr.h"
#include "lib/base64.h"
#include "lib/json.h"
#include <errno.h>
#include <stdint.h>
#include <time.h>

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/asn1t.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/openssl/pem.h>
#else
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#endif

int main(int argc, char* argv[]){
	int result;
        ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	struct ConfigData* config = config_load();
        EVP_PKEY* keypair = generate_keypair(config->CSRKeyType, config->CSRKeySize);
        X509_NAME* subject = parse_subject(config->CSRSubject);
	ASN1_TIME* notbefore = ASN1_TIME_new();
	ASN1_TIME* notafter = ASN1_TIME_new();

        //char* CSR = generate_csr(keypair, subject);

	X509* cert = X509_new();
	ASN1_INTEGER* serial = M_ASN1_INTEGER_new();
	result = ASN1_INTEGER_set(serial, 1);
	if (result != 1)
	{
        	log_error("Unable to set ASN1 integer");
	        return false;
	}

	result = X509_set_serialNumber(cert, serial);
	if (result != 1)
	{
        	log_error("Unable to set serial number");
        	return false;
	}

	time_t now = time(NULL);
	ASN1_TIME_set(notbefore, now);

	result = X509_set_notBefore(cert, notbefore);
        if (result != 1)
        {
                log_error("Unable to set not-before date");
                return false;
        }
	
	struct tm* later = localtime(&now);
	later->tm_year++;
	time_t later_t = mktime(later);
	ASN1_TIME_set(notafter, later_t);
	result = X509_set_notAfter(cert, notafter);
        if (result != 1)
        {
                log_error("Unable to set not-after date");
                return false;
        }

	result = X509_set_subject_name(cert, subject);
        if (result != 1)
        {
                log_error("Unable to set subject name");
                return false;
        }

	result = X509_set_issuer_name(cert, subject);
        if (result != 1)
        {
                log_error("Unable to set issuer name");
                return false;
        }

	result = X509_set_pubkey(cert, keypair);
        if (result != 1)
        {
                log_error("Unable to set public key");
                return false;
        }

	result = X509_sign(cert, keypair, EVP_sha256());
        if (result == 0)
	{
		log_error("Unable to sign certificate");
		char errBuf[120];
		unsigned long errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error("Unable to finalize decryption: %s", errBuf);

		return false;
	}

	BIO* bio = BIO_new(BIO_s_mem());
	result = PEM_write_bio_X509(bio, cert);
        if (result != 1)
        {
                log_error("Unable to write to PEM string");
                return false;
        }
	int len = bio->num_write;
	char* encoded = (char*)malloc(len+1);
	BIO_read(bio, encoded, len);
	encoded[len-strlen("\n-----END CERTIFICATE-----")] = '\0';
	char* stripped = encoded + strlen("-----BEGIN CERTIFICATE-----\n");

	char* message = malloc(1024);
	enum AgentApiResultStatus statusCode;
	save_cert_key(config->ClientCert, config->ClientKey, config->ClientKeyPassword, stripped, keypair, &message, &statusCode);

	free(message);
	free(encoded);
	BIO_free(bio);
	X509_free(cert);
	ASN1_TIME_free(notbefore);
	ASN1_TIME_free(notafter);
	M_ASN1_INTEGER_free(serial);
	X509_NAME_free(subject);
	EVP_PKEY_free(keypair);
}
