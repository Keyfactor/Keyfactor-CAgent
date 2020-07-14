/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include "management.h"
#include "httpclient.h"
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib/base64.h"
#include <errno.h>
#include "utils.h"
#include "logging.h"

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/pkcs12.h>
#include <wolfssl/openssl/rsa.h>
#else
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#endif

#define MODULE "management-"

static int get_management_config(const char* sessionToken, const char* jobId, const char* endpoint, \
		struct ConfigData* config, struct ManagementConfigResp** pManConf)
{
	#undef FUNCTION
	#define FUNCTION "get_management_config-"
	char* url = NULL;

	log_verbose("%s%sSending management config request: %s", MODULE, FUNCTION, jobId);
	struct CommonConfigReq* req = CommonConfigReq_new();
	req->JobId = strdup(jobId);
	req->SessionToken = strdup(sessionToken);

	char* jsonReq = CommonConfigReq_toJson(req);

	char* jsonResp = NULL;
	
	url = config_build_url(config, endpoint, true);

	int res = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, \
		config->ClientKey, config->ClientKeyPassword, jsonReq, &jsonResp);
	
	if(res == 0)
	{
		*pManConf = ManagementConfigResp_fromJson(jsonResp);
	}
	else
	{
		log_error("%s%sConfig retrieval failed with error code %d", MODULE, FUNCTION, res);
	}

	free(jsonReq);
	free(jsonResp);
	free(url);
	CommonConfigReq_free(req);

	return res;
}

static int send_management_job_complete(const char* sessionToken, const char* jobId, const char* endpoint, \
		struct ConfigData* config, int jobStatus, long auditId, const char* message, struct ManagementCompleteResp** pManComp)
{
	#undef FUNCTION
	#define FUNCTION "send_management_job_complete-"
	char* url = NULL;

	log_verbose("%s%sSending management complete request: %ld for session: %s", MODULE, FUNCTION, auditId, sessionToken);
	struct CommonCompleteReq* req = CommonCompleteReq_new();
	req->SessionToken = strdup(sessionToken);
	req->JobId = strdup(jobId);
	req->Status = jobStatus;
	req->AuditId = auditId;
	req->Message = strdup(message);

	char* jsonReq = CommonCompleteReq_toJson(req);

	char* jsonResp = NULL;

	url = config_build_url(config, endpoint, true);

	int res = http_post_json(url, config->Username, config->Password, config->TrustStore, config->ClientCert, \
		config->ClientKey, config->ClientKeyPassword, jsonReq, &jsonResp);
	if(res == 0)
	{
		*pManComp = ManagementCompleteResp_fromJson(jsonResp);
	}
	else
	{
		log_error("%s%sJob completion failed with error code %d", MODULE, FUNCTION, res);
	}

	free(jsonReq);
	free(jsonResp);
	free(url);
	CommonCompleteReq_free(req);

	return res;
}

static int add_cert_to_store(const char* storePath, const unsigned char* certBytes, int certLen, char** pMessage, enum AgentApiResultStatus* pStatus)
{
	#undef FUNCTION
	#define FUNCTION "add_cert_to_store-"
	int ret = 0;
	char* newThumb = NULL;
	X509* cert = NULL;

	// TODO - File locks
	FILE* fpRead = fopen(storePath, "r");
	if(!fpRead)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s%sUnable to open store at %s: %s", MODULE, FUNCTION, storePath, errStr);
		append_linef(pMessage, "Unable to open store at %s: %s", storePath, errStr);
		*pStatus = STAT_ERR;
	}
	else if(d2i_X509(&cert, &certBytes, certLen)) // Make sure we have an actual cert
	{
		newThumb = compute_thumbprint(cert);
		log_verbose("%s%sNew cert thumbprint: %s", MODULE, FUNCTION, newThumb);

		bool foundCert = false;
	
		char* name = NULL;
		char* header = NULL;
		unsigned char* data = NULL;
		long length = 0;
		while(!foundCert && PEM_read(fpRead, &name, &header, &data, &length))
		{
			X509* storeCert = NULL;

			const unsigned char* tempData = data; // Don't lose the pointer so it can be freed

			if(strcmp(name, "CERTIFICATE") == 0 && d2i_X509(&storeCert, &tempData, length))
			{
				char* thumb = compute_thumbprint(storeCert);
				if(strcasecmp(thumb, newThumb) == 0)
				{
					foundCert = true;
				}

				free(thumb);
			}

			OPENSSL_free(name);
			OPENSSL_free(header);
			OPENSSL_free(data);


			X509_free(storeCert);
		}

		log_verbose("%s%sFound cert: %s", MODULE, FUNCTION, (foundCert ? "yes" : "no"));

		if(fpRead)
		{
			fclose(fpRead);
			fpRead = NULL;
		}

		if(!foundCert)
		{
			ret = backup_file(storePath);
			if(ret != 0 && ret != ENOENT)
			{
				char* errStr = strerror(ret);
				log_error("%s%sUnable to backup store at %s: %s\n", MODULE, FUNCTION, storePath, errStr);
				append_linef(pMessage, "Unable to open store at %s: %s", storePath, errStr);
				*pStatus = STAT_ERR;
			}
			else
			{
				FILE* fpAdd = fopen(storePath, "a");
				if(!fpAdd)
				{
					ret = errno;
					char* errStr = strerror(errno);
					log_error("%s%sUnable to open store at %s: %s", MODULE, FUNCTION, storePath, errStr);
					append_linef(pMessage, "Unable to open store at %s: %s", storePath, errStr);
					*pStatus = STAT_ERR;
				}
				else
				{
					if(!PEM_write_X509(fpAdd, cert))
					{
						char errBuf[120];
						unsigned long errNum = ERR_peek_last_error();
						ERR_error_string(errNum, errBuf);
						log_error("%s%sUnable to write certificate to store: %s", MODULE, FUNCTION, errBuf);
						append_linef(pMessage, "Unable to write certificate to store: %s", errBuf);
						*pStatus = STAT_ERR;
					}

					if(fpAdd)
					{
						fclose(fpAdd);
					}
				}
			}
		}
		else
		{
			log_info("%s%sWarning: Certificate with thumbprint %s was already present in store %s", MODULE, FUNCTION, newThumb, storePath);
			append_linef(pMessage, "Warning: Certificate with thumbprint %s was already present in store %s", newThumb, storePath);
			*pStatus = STAT_WARN;
		}
	}
	else
	{
		log_error("%s%sInvalid certificate bytes", MODULE, FUNCTION);
		append_line(pMessage, "Invalid certificate bytes");
		*pStatus = STAT_ERR;
		ret = EINVAL;
	}

	if(fpRead)
	{
		fclose(fpRead);
		fpRead = NULL;
	}

	free(newThumb);
	X509_free(cert);

	return ret;
}

static bool prepare_cert_key_removal(FILE* fp, char** pBytesOut, int* pStoreLen, X509* searchCert, const char* password, char** pMessage, enum AgentApiResultStatus* pStatus)
{
	#undef FUNCTION
	#define FUNCTION "prepare_cert_key_removal-"
	bool didRemove = false;

	char* name = NULL;
	char* header = NULL;
	unsigned char* data = NULL;
	long length = 0;

	char* searchThumb = compute_thumbprint(searchCert);

	// Write the modified store into memory
	BIO* bio = BIO_new(BIO_s_mem());

	while(PEM_read(fp, &name, &header, &data, &length))
	{
		bool excludeFromNewStore = false;

		X509* cert = NULL;
		EVP_PKEY* key = NULL;
		const unsigned char* tempData = data; // Don't lose the pointer so it can be freed

		if(strcmp(name, "CERTIFICATE") == 0 && d2i_X509(&cert, &tempData, length))
		{
			char* thumb = compute_thumbprint(cert);

			if(strcasecmp(thumb, searchThumb) == 0)
			{
				excludeFromNewStore = true;
			}
			free(thumb);
		}
		else if(strcmp(name, "PRIVATE KEY") == 0 && d2i_AutoPrivateKey(&key, &tempData, length))
		{
			excludeFromNewStore = is_cert_key_match(searchCert, key);
		}
		else if(strcmp(name, "ENCRYPTED PRIVATE KEY") == 0)
		{
			BIO* keyBio = BIO_new_mem_buf(data, length);
			if(d2i_PKCS8PrivateKey_bio(keyBio, &key, NULL, (char*)(password ? password : "")))
			{
				excludeFromNewStore = is_cert_key_match(searchCert, key);
			}
			else
			{
				char errBuf[120];
				unsigned long errNum = ERR_peek_last_error();
				ERR_error_string(errNum, errBuf);
				log_error("%s%sUnable to decrypt private key: %s", MODULE, FUNCTION, errBuf);
				append_linef(pMessage, "Unable to decrypt private key: %s", errBuf);
				*pStatus = STAT_WARN;
			}
			BIO_free(keyBio);
		}

		if(!excludeFromNewStore)
		{
			PEM_write_bio(bio, name, header, data, length);
		}
		else
		{
			didRemove = true;
		}

		OPENSSL_free(name);
		OPENSSL_free(header);
		OPENSSL_free(data);
		X509_free(cert);
		EVP_PKEY_free(key);
	}

	if(didRemove)
	{
		// Copy data into non-OpenSSL structure for return
		char* tmp = NULL;
		*pStoreLen = BIO_get_mem_data(bio, &tmp);
		*pBytesOut = malloc(*pStoreLen);
		memcpy(*pBytesOut, tmp, *pStoreLen);
	}

	free(searchThumb);
	BIO_free(bio);

	return didRemove;
}

static int remove_cert_from_store(const char* storePath, const char* searchThumb, const char* keyPath, const char* password, char** pMessage, enum AgentApiResultStatus* pStatus)
{
	#undef FUNCTION
	#define FUNCTION "remove_cert_from_store-"
	int ret = 0;

	// TODO - File locks
	FILE* fpRead = fopen(storePath, "r");
	if(!fpRead)
	{
		ret = errno;
		char* errStr = strerror(errno);
		log_error("%s%sUnable to read store at %s: %s", MODULE, FUNCTION, storePath, errStr);
		append_linef(pMessage, "Unable to read store at %s: %s", storePath, errStr);
		*pStatus = STAT_ERR;
	}
	else
	{
		X509* foundCert = NULL;
		char* name = NULL;
		char* header = NULL;
		unsigned char* data = NULL;
		long length = 0;

		// Read through once to find the cert
		while(PEM_read(fpRead, &name, &header, &data, &length))
		{
			X509* cert = NULL;
			const unsigned char* tempData = data; // Don't lose the pointer so it can be freed

			if(strcmp(name, "CERTIFICATE") == 0 && d2i_X509(&cert, &tempData, length))
			{
				char* thumb = compute_thumbprint(cert);
				if(strcasecmp(thumb, searchThumb) == 0)
				{
					foundCert = X509_dup(cert);
				}
				free(thumb);
			}

			OPENSSL_free(name);
			OPENSSL_free(header);
			OPENSSL_free(data);
			X509_free(cert);
		}

		log_verbose("%s%sFound cert: %s", MODULE, FUNCTION, (foundCert ? "yes" : "no"));

		if(foundCert)
		{
			fseek(fpRead, 0, SEEK_SET); // Rewind the file

			char* bytesOut = NULL;
			int storeLen;
			bool removedCert = prepare_cert_key_removal(fpRead, &bytesOut, &storeLen, foundCert, password, pMessage, pStatus);

			if(fpRead)
			{
				fclose(fpRead);
				fpRead = NULL;
			}

			if(removedCert && *pStatus != STAT_ERR)
			{
				ret = replace_file(storePath, bytesOut, storeLen, true);
				if(ret != 0)
				{
					char* errStr = strerror(ret);
					log_error("%s%sUnable to replace store at %s: %s", MODULE, FUNCTION, storePath, errStr);
					append_linef(pMessage, "Unable to replace store at %s: %s", storePath, errStr);
					*pStatus = STAT_ERR;
				}
			}

			if(keyPath && *pStatus != STAT_ERR)
			{
				log_verbose("%s%sChecking for keys to be removed from %s", MODULE, FUNCTION, keyPath);

				FILE* fpKey = fopen(keyPath, "r");
				if(!fpKey)
				{
					ret = errno;
					char* errStr = strerror(errno);
					log_error("%s%sUnable to read store at %s: %s", MODULE, FUNCTION, storePath, errStr);
					append_linef(pMessage, "Unable to read store at %s: %s", storePath, errStr);
					*pStatus = STAT_ERR;
				}
				else
				{
					char* keyBytesOut = NULL;
					int keyLen;
					bool removedKey = prepare_cert_key_removal(fpKey, &keyBytesOut, &keyLen, foundCert, password, pMessage, pStatus);

					if(fpKey)
					{
						fclose(fpKey);
						fpKey = NULL;
					}

					if(removedKey && *pStatus != STAT_ERR)
					{
						ret = replace_file(keyPath, keyBytesOut, keyLen, true);
						if(ret != 0)
						{
							char* errStr = strerror(ret);
							log_error("%s%sUnable to replace store at %s: %s", MODULE, FUNCTION, keyPath, errStr);
							append_linef(pMessage, "Unable to replace store at %s: %s", keyPath, errStr);
							*pStatus = STAT_ERR;
						}
					}
				}

				if(fpKey)
				{
					fclose(fpKey);
					fpKey = NULL;
				}
			}
		}
		else
		{
			log_info("%s%sWarning: Certificate with thumbprint %s was not found in store %s", MODULE, FUNCTION, searchThumb, storePath);
			append_linef(pMessage, "Warning: Certificate with thumbprint %s was not found in store %s", searchThumb, storePath);
			*pStatus = STAT_WARN;
		}

		if(fpRead)
		{
			fclose(fpRead);
			fpRead = NULL;
		}
	}

	return ret;
}

int cms_job_manage(struct SessionJob* jobInfo, struct ConfigData* config, char* sessionToken, char** chainJob)
{
	#undef FUNCTION
	#define FUNCTION "cms_job_manage-"
	int res = 0;
	struct ManagementConfigResp* manConf = NULL;
	char* statusMessage = strdup("");
	enum AgentApiResultStatus status = STAT_UNK;
	int returnable = 0;
	log_info("%s%sStarting inventory job %s", MODULE, FUNCTION, jobInfo->JobId);

	res = get_management_config(sessionToken, jobInfo->JobId, jobInfo->ConfigurationEndpoint, config, &manConf);

	if(res == 0 && manConf && AgentApiResult_log(manConf->Result, &statusMessage, &status))
	{
		if(manConf->JobCancelled)
		{
			returnable = 1;
			log_info("%s%sJob has been cancelled and will not be run", MODULE, FUNCTION);
		}
		else
		{
			long auditId = manConf->AuditId;
			log_verbose("%s%sAudit Id: %ld", MODULE, FUNCTION, auditId);

			int opType = manConf->Job.OperationType;
			switch(opType)
			{
			case OP_ADD:
				log_verbose("%s%smanagement-cms_job_manage-Add certificate operation", MODULE, FUNCTION);

				if(manConf->Job.PrivateKeyEntry)
				{
					const char* msg = "Adding a PFX is not supported at this time";
					log_verbose("%s%s%s", MODULE, FUNCTION, msg);
					status = STAT_ERR;
					append_line(&statusMessage, msg);
				}
				else
				{
					size_t certLen;
					unsigned char* certBytes = base64_decode(manConf->Job.EntryContents, -1, &certLen);
					res = add_cert_to_store(manConf->Job.StorePath, certBytes, certLen, &statusMessage, &status);
					free(certBytes);
				}
				break;
			case OP_REM:
				log_verbose("%s%sRemove certificate operation", MODULE, FUNCTION);
				res = remove_cert_from_store(manConf->Job.StorePath, manConf->Job.Alias, manConf->Job.PrivateKeyPath, manConf->Job.StorePassword, &statusMessage, &status);
				break;
			default:
				log_error("%s%sUnsupported operation type: %d", MODULE, FUNCTION, opType);
				append_linef(&statusMessage, "Unsupported operation type: %d", opType);
				status = STAT_ERR;
				break;
			}

			struct ManagementCompleteResp* manComp = NULL;
			res = send_management_job_complete(sessionToken, jobInfo->JobId, jobInfo->CompletionEndpoint, config, status+1, auditId, statusMessage, &manComp);
			if(manComp)
			{
				if(AgentApiResult_log(manComp->Result, NULL, NULL) && manComp->InventoryJob && chainJob)
				{
					*chainJob = strdup(manComp->InventoryJob);
				}
			}

			if(status >= STAT_ERR)
			{
				log_info("%s%sManagement job %s failed with error: %s", MODULE, FUNCTION, jobInfo->JobId, statusMessage);
			}
			else if(status == STAT_WARN)
			{
				log_info("%s%sManagement job %s completed with warning: %s", MODULE, FUNCTION, jobInfo->JobId, statusMessage);
			}
			else
			{
				log_info("%s%sManagement job %s completed successfully", MODULE, FUNCTION, jobInfo->JobId);
			}

			ManagementCompleteResp_free(manComp);
		}
	}

	ManagementConfigResp_free(manConf);
	free(statusMessage);

	return returnable;
}
