/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include <stdio.h>
#include <string.h>
#include "verify.h"
#include "utils.h"
#include "logging.h"
#include "lib/base64.h"

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/evp.h>
#else
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

static char* g_inFile = NULL;
static char* g_sigFile = NULL;
static char* g_certsFile = NULL;
static char* g_trustFile = NULL;
static bool g_b64sig = false;
static char* g_hashAlg = NULL;
static bool g_verifyChain = true;
static bool g_pkcs7sig = false;
static bool g_verifyTimestamp = false;

static void print_help()
{
	printf("Usage: verify_test -in <file> -signature <file> -certs <file> [options]\n");
	printf("-in <file>: File whose signature should be verified.\n");
	printf("-signature <file>: File containing signature to be verified.\n");
	printf("-certs <file>: File containing 1 or more PEM-encoded certificates to be used for verification.\n");
	printf("\nOptions:\n");
	printf("-pkcs7: Signature file is in PKCS7 format (default is raw signature).\n");
	printf("-trust <file>: File containing 1 or more PEM-encoded certificates to be used for chain building, including a root certificate. Required if -noverify is not specified.\n");
	printf("-noverify: Skip certificate chain building.\n");
	printf("-b64sig: Signature file is base64 encoded (default is binary).\n");
	printf("[-sha1|-sha256|-sha384|-sha512]: Hash algorithm to use for signature verification (default is hash used to sign certificate).\n");
	printf("-ts: Verify the timestamp present in the signature.\n");
}

static bool read_args(int argc, char** argv)
{
	bool valid = true;

	for(int i = 1; i < argc; ++i)
	{
		log_verbose("Arg %d: %s", i, argv[i]);
		if((i < argc - 1) && strcasecmp(argv[i], "-certs") == 0) // This flag must have a parameter after it
		{
			g_certsFile = argv[++i];
			log_verbose("Cert file path: %s", g_certsFile);
		}
		else if((i < argc - 1) && strcasecmp(argv[i], "-in") == 0)
		{
			g_inFile = argv[++i];
			log_verbose("Input file path: %s", g_inFile);
		}
		else if((i < argc - 1) && strcasecmp(argv[i], "-signature") == 0)
		{
			g_sigFile = argv[++i];
			log_verbose("Signature file path: %s", g_sigFile);
		}
		else if((i < argc - 1) && strcasecmp(argv[i], "-trust") == 0)
		{
			g_trustFile = argv[++i];
			log_verbose("Trust file path: %s", g_trustFile);
		}
		else if(strcasecmp(argv[i], "-b64sig") == 0)
		{
			g_b64sig = true;
			log_verbose("Signature is base64 encoded");
		}
		else if(strcasecmp(argv[i], "-noverify") == 0)
		{
			g_verifyChain = false;
			log_verbose("Certificate chain will not be verified");
		}
		else if(strcasecmp(argv[i], "-pkcs7") == 0)
		{
			g_pkcs7sig = true;
			log_verbose("Signature file is in PKCS7 format");
		}
		else if(strcasecmp(argv[i], "-sha1") == 0 || \
				strcasecmp(argv[i], "-sha256") == 0 || \
				strcasecmp(argv[i], "-sha384") == 0 || \
				strcasecmp(argv[i], "-sha512") == 0)
		{
			if(!g_hashAlg)
			{
				g_hashAlg = &(argv[i][1]);
				log_verbose("Hash algorithm is %s", g_hashAlg);
			}
			else
			{
				log_error("Multiple hash algorithms specified");
				valid = false;
			}
		}
		else if(strcasecmp(argv[i], "-ts") == 0)
		{
			g_verifyTimestamp = true;
			log_verbose("Timestamp will be verified");
		}
		else if(strcasecmp(argv[i], "-help") == 0)
		{
			print_help();
			exit(0);
		}
		else
		{
			log_info("Ignoring unknown parameter: %s", argv[i]);
		}
	}

	if(!g_inFile)
	{
		log_error("Input file not specified");
		valid = false;
	}
	if(!g_sigFile)
	{
		log_error("Signature file not specified");
		valid = false;
	}
	if(!g_certsFile)
	{
		log_error("Certificate file not specified");
		valid = false;
	}
	if(g_verifyChain && !g_trustFile)
	{
		log_error("Trusted certificates file not specified");
		valid = false;
	}
	if(g_verifyTimestamp && !g_pkcs7sig)
	{
		log_error("Time stamp verification needs to be done on a PKCS7 signature");
		valid = false;
	}
	if(g_verifyTimestamp && !g_trustFile)
	{
		log_error("Trusted certificates need to be included for time stamp verification");
		valid = false;
	}

	return valid;
}

int main(int argc, char** argv)
{
	log_set_verbosity(true);
	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();

	if(read_args(argc, argv))
	{
		unsigned char* fileBytes;
		size_t fileLen;
		if(read_file_bytes(g_inFile, &fileBytes, &fileLen) == 0)
		{
			log_verbose("Read %lu bytes from content file", fileLen);
		}
		else
		{
			log_error("Unable to read content file");
		}

		unsigned char* sigBytes = NULL;
		size_t sigLen;
		unsigned char* rawSigBytes = NULL;
		size_t rawSigLen;
		if(read_file_bytes(g_sigFile, &rawSigBytes, &rawSigLen) == 0)
		{
			log_verbose("Read %lu bytes from signature file", rawSigLen);
			if(g_b64sig)
			{
				sigBytes = base64_decode((char*)rawSigBytes, rawSigLen, &sigLen);
				free(rawSigBytes);
			}
			else
			{
				sigBytes = rawSigBytes;
				sigLen = rawSigLen;
			}
		}
		else
		{
			log_error("Unable to read signature file");
		}

		if(g_pkcs7sig)
		{
			if(verify_pkcs7_signature(fileBytes, fileLen, sigBytes, sigLen, g_certsFile, g_verifyChain, g_trustFile))
			{
				log_info("Signature verified successfully\n");
			}
			else
			{
				log_info("Signature did NOT verify successfully\n");
			}
		}
		else
		{
			if(verify_detached_signature(fileBytes, fileLen, sigBytes, sigLen, g_certsFile, g_verifyChain, g_trustFile, g_hashAlg))
			{
				log_info("Signature verified successfully\n");
			}
			else
			{
				log_info("Signature did NOT verify successfully\n");
			}
		}

		if(g_verifyTimestamp)
		{
			if(verify_timestamp(sigBytes, sigLen, g_trustFile))
			{
				log_info("Timestamp verified successfully\n");
			}
			else
			{
				log_info("Timestamp did NOT verify successfully\n");
			}
		}

		if(fileBytes)
		{
			free(fileBytes);
		}
		if(sigBytes)
		{
			free(sigBytes);
		}
	}
	else
	{
		log_error("Invalid parameters");
	}
	EVP_cleanup();
}
		
