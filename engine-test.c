/** @file engine-test.c */
//
// Test the engine implementation of the TSS stack
// You need to download & install:
//		tpm2-tss
//		tpm2-tss-engine
//
//		Both can be retrieved from https://github.com/tpm2-software/
//
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "logging.h"

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <tpm2-tss-engine.h>

#include "lib/base64.h"

#define MODULE "engine-test-"

/******************************************************************************/
/** @fn ENGINE* intitalize_tpm( const char* engine_id )
	@brief Tries to initialize and open the engine passed to it.
	@brief It also sets the engine as the default engine for all functions
	@param engine_id The name of the engine to use e.g., default, tpm2tss
	@returns Pointer to the initialized engine ENGINE*
*/ 
/******************************************************************************/
ENGINE* intitialize_tpm( const char *engine_id )
{
	ENGINE *e = NULL;
	ENGINE_load_builtin_engines();
	// Set the engine pointer to an instance of the engine
	if ( !( e = ENGINE_by_id( engine_id ) ) )
	{
		log_error("%s%s-Unable to find Engine: %s", 
					MODULE, "intitialize_tpm", engine_id);
		goto end;
	}
	else
	{
		log_verbose("%s%s-Found engine: %s", 
					MODULE, "intitialize_tpm", engine_id);
	}

	// Initialize the engine for use
	if ( !ENGINE_init(e) )
	{
		log_error("%s%s-Unable to init Engine: %s", 
					MODULE, "intitialize_tpm", engine_id);
		goto end;
	}
	else
	{
		log_verbose("%s%s-Initialized engine: %s", 
					MODULE, "intitialize_tpm", engine_id);
	}

		// Register the engine for use with the ECDSA algorithm
	if ( !ENGINE_set_default( e, ENGINE_METHOD_ALL ) )
	{
		log_error("%s%s-Couldn't set the default engine to %s.", 
					MODULE, "intitialize_tpm", engine_id);
		goto end;
	}
	else
	{
		log_verbose("%s%s-Successfully set the default engine to %s.", 
					MODULE, "intitialize_tpm", engine_id);
	}
	ENGINE_register_complete( e );

	end:
	return e;
} // initialize_tpm

EVP_PKEY* generate_ecc_keypair( const int eccNid )
{
	EVP_PKEY* keyPair = NULL;

	// generate the key using the engine that's set as the default
	EC_KEY* newEcc = EC_KEY_new_by_curve_name( eccNid );
	EC_KEY_set_asn1_flag( newEcc, OPENSSL_EC_NAMED_CURVE );
	if( EC_KEY_generate_key( newEcc ) )
	{
		keyPair = EVP_PKEY_new();
		EVP_PKEY_assign_EC_KEY( keyPair, newEcc );
		log_verbose("%s%s-Successfully created keypair", 
						MODULE, "generate_ecc_keypair");
	}
	else
	{
		char errBuf[120];
		unsigned long errNum = ERR_peek_last_error();
		log_error("%s%s-Coulndn't generate keypair: %ld %s", 
					MODULE, "generate_ecc_keypair", errNum, errBuf);
	}
	return keyPair;
} // generate_ecc_keypair

static int read_subject_value(const char* subject, char* buf)
{
	int subjLen = strlen(subject);
	int subInd = 0;
	int bufInd = 0;

	bool done = false;
	bool hasError = false;

	while(!done && !hasError && subInd < subjLen)
	{
		char c = subject[subInd];
		switch(c)
		{
		case '\\':
			;
			char escaped[1];
			unsigned int hexHi, hexLo;
			if(sscanf(&subject[subInd], "\\%1[\" #+,;<=>\\]", escaped) == 1)
			{
				if(buf)
				{
					buf[bufInd++] = escaped[0];
				}
				subInd += 2;
			}
			else if(sscanf(&subject[subInd], "\\%1x%1x", &hexHi, &hexLo) == 2)
			{
				if(buf)
				{
					buf[bufInd++] = (char)((hexHi << 4) | hexLo);
				}
				subInd += 3;
			}
			else
			{
				hasError = true;
			}
			break;
		case ',':
			done = true;
			break;
		default:
			if(buf)
			{
				buf[bufInd++] = c;
			}
			++subInd;
			break;
		}
	}

	if(buf)
	{
		buf[bufInd] = '\0';
	}

	return hasError ? -1 : subInd;
}

X509_NAME* parse_subject(const char* subject)
{
	X509_NAME* subjName = NULL;
	int subjLen = strlen(subject);
	int cur = 0;

	bool hasError = false;

	X509_NAME_ENTRY* rdnArr[20]; // 20 RDNs should be plenty
	int rdnCount = 0;

	while(!hasError && cur < subjLen)
	{
		int keyLen = strcspn(&subject[cur], "=");
		char keyBytes[keyLen+1];
		strncpy(keyBytes, &subject[cur], keyLen);
		keyBytes[keyLen] = '\0';
		cur += (keyLen + 1);
		log_verbose("%s%s-Key: %s", MODULE, "parse_subject", keyBytes);

		if(cur < subjLen)
		{
			int valLen = read_subject_value(&subject[cur], NULL);
			if(valLen >= 0)
			{
				char valBytes[valLen+1];
				read_subject_value(&subject[cur], valBytes);
				cur += (valLen + 1);
				log_verbose("%s%s-Value: %s",MODULE, "parse_subject", valBytes);

				rdnArr[rdnCount] = X509_NAME_ENTRY_create_by_txt(NULL, 
																keyBytes, 
																MBSTRING_UTF8, 
													(unsigned char*)valBytes, 
																-1);
				rdnCount++;

				// Don't try to advance if we just advanced 
				// past the null-terminator
				if(subject[cur-1] != '\0') 
				{
					// Whitespace between RDNs should be ignored
					cur += strspn(&subject[cur], "\t\r\n "); 
				}
			}
			else
			{
				log_error("%s%s-Input string '%s' is not a valid X500 name", 
							MODULE, "parse_subject", subject);
				hasError = true;
			}
		}
		else
		{
			log_error("%s%s-Input string '%s' is not a valid X500 name", 
						MODULE, "parse_subject", subject);
			hasError = true;
		}
	}

	if(!hasError)
	{
		subjName = X509_NAME_new();
		for(int rdnIndex = rdnCount - 1; rdnIndex >= 0; rdnIndex--)
		{
			X509_NAME_add_entry(subjName, rdnArr[rdnIndex], -1, 0);
		}
	}

	// Cleanup
	for(int rdnIndex = rdnCount - 1; rdnIndex >= 0; rdnIndex--)
	{
		X509_NAME_ENTRY_free(rdnArr[rdnIndex]);
	}

	return subjName;
}

char* generate_csr( EVP_PKEY* keyPair, const char* subject )
{
	// generate a CSR using the keypair
	char* CSR = NULL;
	X509_REQ* req = NULL;
	unsigned char* reqBytes=NULL;
	int reqLen;

	// Create a properly formatted subjectNameField
	X509_NAME* subjectName = parse_subject( subject );

	if ( subjectName )
	{
		log_verbose("%s%s-Successfully created subject name",
					MODULE, "generate_csr");
	}
	else
	{
		log_error("%s%s-Couldn't create subject name",MODULE, "generate_csr");
		goto end;
	}

	// Create a X509 CSR
	req = X509_REQ_new();
	if ( req && \
		 X509_REQ_set_subject_name( req, subjectName ) && \
		 X509_REQ_set_pubkey( req, keyPair) && \
		 X509_REQ_sign( req, keyPair, EVP_sha256() ) \
	   )
	{
		reqLen = i2d_X509_REQ( req, NULL );
		reqBytes = malloc( reqLen );
		unsigned char* tempReqBytes = reqBytes;
		i2d_X509_REQ( req, &tempReqBytes );
		CSR = base64_encode( reqBytes, (size_t)reqLen, false, NULL );
		log_verbose("%s%s-  CSR =\n%s", MODULE, "generate_csr", CSR);
	}
	else
	{
		log_error("%s%s-Failed to create CSR",MODULE, "generate_csr");
	}

end:
	free( subjectName );
	X509_REQ_free( req );
	return CSR;
} // generate_csr

void parse_parameters(int argc, const char *argv[])
{
	for(int i = 1; i < argc; ++i)
	{
		if(strcmp(argv[i], "-v") == 0)
		{
			log_set_verbosity(true);
		}
		else if (strcmp(argv[i], "-l") == 0)
		{
			if ( argc > i )
			{
				if (strcmp(argv[i+1], "v") == 0) log_set_verbosity(true); else
				if (strcmp(argv[i+1], "i") == 0) log_set_info(true); else
				if (strcmp(argv[i+1], "e") == 0) log_set_error(true); else
				if (strcmp(argv[i+1], "o") == 0) log_set_off(true); else
				// default
				fprintf(stderr,"Unknown -l switch variable %s", argv[i+1]); 
			} // if argc 
		} // else
	}
} // parse_parameters

int writeCSR_ToFile( const char* CSR, const char* filename )
{
	FILE* fp = NULL;
	const char* top = "-----BEGIN CERTIFICATE REQUEST-----\n";
	const char* btm = "\n-----END CERTIFICATE REQUEST-----\n";

	fp = fopen( filename, "w+" );
	if ( !fp ) 
	{
		log_error("%s%s-Failed to open file %s", 
					MODULE, "writeCSR_ToFile", filename);
		goto err;
	}
	else
	{
		log_verbose("%s%s-Opened %s for writing",
					MODULE, "writeCSR_ToFile", filename);
	}

	if ( !fprintf( fp, top ) ) 
	{
		log_error("%s%s-Failed to write %s to file %s", 
					MODULE, "writeCSR_ToFile", top, filename);
		goto err;
	}
	else
	{
		log_verbose("%s%s-Wrote top to file", MODULE, "writeCSR_ToFile");
	}
	if ( !fprintf( fp, CSR ) ) 
	{
		log_error("%s%s-Failed to write %s to file %s", 
					MODULE, "writeCSR_ToFile", CSR, filename);
		goto err;
	}
	else
	{
		log_verbose("%s%s-Wrote CSR to file", MODULE, "writeCSR_ToFile");
	}
	if ( !fprintf( fp, btm ) ) 
	{
		log_error("%s%s-Failed to write %s to file %s", 
					MODULE, "writeCSR_ToFile", CSR, filename);
		goto err;
	}
	else
	{
		log_verbose("%s%s-Wrote btm to file", MODULE, "writeCSR_ToFile");
	}
	if ( EOF == fclose( fp ) )
	{
		log_error("%s%s-Failed to close CSR file", MODULE, "writeCSR_ToFile");
		goto err;
	}
	else
	{
		log_verbose("%s%s-Successfully closed CSR file.", 
					MODULE, "writeCSR_ToFile");
	}
	return 0;

	err:
	return -1;
} // writeCSR_ToFile

static unsigned long write_key_bio(BIO* bio, 
									const char* password,
									const EVP_PKEY* privKey)
{
	unsigned long errNum = 0;
	const char* tmpPass = 
				(password && strcmp(password, "") != 0) ? password : NULL;
	const EVP_CIPHER* tmpCiph = 
			(password && strcmp(password, "") != 0) ? EVP_aes_256_cbc() : NULL;
	
	if(PEM_write_bio_PKCS8PrivateKey(bio, (EVP_PKEY*)privKey, 
		tmpCiph, NULL, 0, 0, (char*)tmpPass))
	{
		log_verbose("%s%s-Private key written to BIO", MODULE, "write_key_bio");
	}
	else
	{
		errNum = ERR_peek_last_error();
	}
	
	return errNum;
}

static unsigned long write_public_key_bio(BIO* bio, 
									const EVP_PKEY* pubKey)
{
	unsigned long errNum = 0;
	
	if( PEM_write_bio_PUBKEY( bio, (EVP_PKEY*)pubKey ) )
	{
		log_verbose("%s%s-Public key written to BIO", MODULE, "write_key_bio");
	}
	else
	{
		errNum = ERR_peek_last_error();
	}
	
	return errNum;
}

int replace_file(const char* file, const char* contents, long len, bool backup)
{
	int err = 0;

	if(backup)
	{
		// err = backup_file(file);
	}

	if(!err || err == ENOENT)
	{
		err = 0; // Inability to backup a file because it doesn't exist is fine

		FILE* fpWrite = fopen(file, "w");
		if(!fpWrite)
		{
			err = errno;
			char* errStr = strerror(errno);
			log_error("%s%s-Unable to open store at %s for writing: %s", 
						MODULE, "replace_file", file, errStr);
		}
		else
		{
		  log_verbose("%s%s-Preparing to write %ld bytes to the modified store",
		  				MODULE, "replace_file",  len);

			if(fwrite(contents, 1, len, fpWrite) == len)
			{
				log_verbose("%s%s-Store %s written successfully", 
							MODULE, "replace_file", file);
			}
			else
			{
				err = errno;
				char* errStr = strerror(errno);
				log_error("%s%s-Unable to write store at %s: %s", 
					MODULE, "replace_file", file, errStr);
			}
		}

		if(fpWrite)
		{
			fclose(fpWrite);
		}
	}

	return err;
}

unsigned long SavePrivKey( EVP_PKEY* privKey, const char* filename )
{
	unsigned long err = 0;
	BIO* keyBIO = BIO_new(BIO_s_mem());
	err = write_key_bio( keyBIO, "", privKey );
	if ( err )
	{
		char errBuf[120];
		ERR_error_string(err, errBuf);
		log_error("%s%s-Unable to write key to BIO: %s", 
				  MODULE, "SavePrivKey", errBuf);
		goto end;
	}

	char* data = NULL;
	long len = BIO_get_mem_data(keyBIO, &data);
	err = replace_file(filename, data, len, true);

	if( err )
	{
		char* errStr = strerror(err);
		log_error("%s%s-Unable to write key at %s: %s", 
			MODULE, "SavePrivKey", filename, errStr);
		goto end;
	}

	end:
	return err;
} // SavePrivKey

unsigned long SavePubKey( EVP_PKEY* x, const char* filename )
{
	unsigned long err = 0;
	BIO* keyBIO = BIO_new(BIO_s_mem());
	err = write_public_key_bio( keyBIO, x );
	if ( err )
	{
		char errBuf[120];
		ERR_error_string(err, errBuf);
		log_error("%s%s-Unable to write key to BIO: %s", 
				  MODULE, "SavePubKey", errBuf);
		goto end;
	}

	char* data = NULL;
	long len = BIO_get_mem_data( keyBIO, &data );
	err = replace_file( filename, data, len, true );
	if ( err )
	{
		char* errStr = strerror(err);
		log_error("%s%s-Unable to write key at %s: %s", 
			MODULE, "SavePubKey", filename, errStr);
		goto end;
	}
	
end:
	return err;
} // SavePubKey

int main(int argc, const char *argv[])
{
	const char *engine_id = "tpm2tss"; // NOTE: Change this to default to not 
									//use the tpm2tss engine
	const char *subject = "CN=engine-test"; // The subject for the CSR
	const char *pubFileName = "/home/pi/AgentPiTPM/keys/engineTest.pub";
	const char *privFileName = "/home/pi/AgentPiTPM/keys/engineTest.key";
	const char *CSRfileName = "/home/pi/AgentPiTPM/keys/engineTest.csr";

	ENGINE *e; // get an engine pointer
	int eccNid = NID_X9_62_prime256v1; // Use this ECC curve
	EVP_PKEY* keyPair = NULL; // Use this to hold the keypair

	parse_parameters( argc, &argv[0] );	
	e = intitialize_tpm( engine_id );

	if ( e )
	{
		OpenSSL_add_all_algorithms();
		keyPair = generate_ecc_keypair( eccNid );
		if ( keyPair )
		{
			char* CSR = generate_csr( keyPair, subject );
			if ( !CSR ) 
				goto err;
			else
			{
				writeCSR_ToFile( CSR, CSRfileName );
				SavePrivKey( keyPair, privFileName );
				SavePubKey( keyPair, pubFileName );
			}
		}
		else
		{
			goto err;
		}
	}
	else
	{
		goto err;
	}

	ENGINE_finish( e );
	ENGINE_free( e );

	printf("\nSuccessful test!!\n\n");
	return 0;

err:
	fprintf(stderr,"\nFailed test!!\n\n");
	return -1;
} // main
