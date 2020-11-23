/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
#ifndef __OPENSSL_WRAPPER_H__
#define __OPENSSL_WRAPPER_H__

#include <stdbool.h>

/**************************************************************************/
/****************** GLOBAL STRUCTURE PROTOTYPES ***************************/
/**************************************************************************/

/**
 * These are the AGENT versions of the ssl_PemInventoryItems and are allocated
 * this ssl abstraction layer.  They are freed in the AGENT layer.
 */
/**
 * Define a PEM for use by the platform, the PEM may have
 * an encoded private key stored with it (or not).  If not,
 * there is an encoded file with the private key that is 
 * separate from the cert.
 *
 * The thumbprint is an ASCII sha1 hash of the cert
 */
struct PemInventoryItem
{
	char* cert;
	char* thumbprint_string;
	bool has_private_key;
};
typedef struct PemInventoryItem PemInventoryItem;

/**
 * Define a list of PEM certs held inside of a certificate store.
 * This is for use by the platform's inventory function.
 */ 
struct PemInventoryList
{
	int item_count;
	PemInventoryItem** items;
};
typedef struct PemInventoryList PemInventoryList;

/**************************************************************************/
/******************* GLOBAL FUNCTION PROTOTYPES ***************************/
/**************************************************************************/

/** 
 * Free a PemInventory item from memory
 *
 * @param  - [Input] : pem = the pem Item to free
 * @return - none
 */
 void PemInventoryItem_free(PemInventoryItem* pem);

 /**
 * Free the PemInventoryList from memory
 *
 * @param  - [Input] : list = the PemInventoryList to free from memory
 * @return - none
 */
void PemInventoryList_free(PemInventoryList* list);

/**
 * Take the ASCII entropy provide & seed the RNG for openSSL
 *
 * @param  - [Input] : b64entropy is the string to use to seed the RNG
 * @return - success : 0
 *         - failure : -1
 */
int ssl_seed_rng(const char* b64entropy);

/**
 * generate keypair functions 														 
 * these will generate a keypair of keySize and store it in a variable called: 		 
 * EVP_PKEY* keyPair which is a 'temporary' location (in the openssl case it is 
 * a locally scoped variable).
 * The variable can be saved to the file system via the save_keypair function
 * described below.                          
 */
bool ssl_generate_rsa_keypair(int keySize);
bool ssl_generate_ecc_keypair(int keySize);

/**
 * Create a CSR using the subject provided and the temporary key keyPair.
 * Return an ASCII CSR (minus the header and footer).
 *
 * @param  - [Input]  : asciiSubject string with the subject line
 *                      e.g., CN=1234,OU=NA,O=Keyfactor,C=US
 * @param  - [Output] : csrLen the # of ASCII characters in the csr
 * @param  - [Output]: pMessage = a string array containing any messages
 *                                we want to pass back to the calling function
 * @return - success : the CSR string minus the header and footer
 *           failure : NULL
 */
char* ssl_generate_csr(const char* asciiSubject, size_t* csrLen, \
	char** pMessage);

/**
 * Save the cert and key to the locations requested 
 * Store the locally global variable keyPair
 *
 * @param  - [Input] : storePath = the store location for the cert
 * @param  - [Input] : keyPath = the location to save the key, if NULL or blank, 
 *                               store the encoded key appended to the cert.
 * @param  - [Input] : password = the password for the private key
 * @param  - [Input] : cert = The cert in an ASCII encoded string
 * @param  - [Output]: pMessage = a string array containing any messages
 *                                we want to pass back to the calling function
 * @return - unsigned long error code
 */
unsigned long ssl_save_cert_key(const char* storePath, const char* keyPath,	\
	const char* password, const char* cert, char** pMessage);

/**
 * Read all of the certificates inside of the store at the path requested.
 * Convert each of these into a PemInventoryItem & add it into the variable
 * provided.
 *
 * @param  - [Input] : path = the path to the store (or the id of the store)
 * @param  - [Input] : password = the password of private keys in the store
 * @param  - [Ouput] : pPemList an array to hold the inventory 
 *                     (SEND IN A NULL VARIABLE - we create the list in the
 *                      wrapper)
 * @return - success : 0
 *		   - failure : the error code from opening the file or such
 */
int ssl_read_store_inventory(const char* path, const char* password, \
	PemInventoryList** pPemList);

/**
 * Create a PemInventoryItem (with has_private_key set to false) from an ASCII
 * cert.  Verify the cert is valid & compute its thumbprint. 
 *
 * NOTE: The PemInventoryItem must be freed by the calling function by
 *       invoking PemInventoryItem_free(pem);
 *
 * @param  - [Output] : pem = the variable which points to the new item
 * @param  - [Input] : certASCII = the b64 encoded NULL terminated certificate
 * @return - success : true
 *         - failure : false
 */
bool ssl_PemInventoryItem_create(struct PemInventoryItem** pem, \
	const char* certASCII);

/**
 * Append the certificate provided to the store.
 *
 * @param  - [Input] : storePath = where to find the store
 * @param  - [Input] : certASCII = the b64 encoded PEM string of the cert
 * @return - success : true
 *         - failure : false
 */
bool ssl_Store_Cert_add(const char* storePath, const char* certASCII);

/**
 * Remove a cert (and associated key) from a store/keystore
 *
 * @param  - [Input] : storePath = the path for the certificate store
 * @param  - [Input] : searchThumb = the sha1 hash of the cert to remove
 * @param  - [Input] : keyPath = the path of the keystore.  
 *                     if NULL an use storePath
 * @param  - [Input] : password = password for any encrypted keys
 * @return - success : true
 *           failure : false
 */
bool ssl_remove_cert_from_store(const char* storePath, const char* searchThumb,\
	const char* keyPath, const char* password);

/**
 * Initialize the platform to use openssl
 *
 * @param  - none
 * @return - none
 */
void ssl_init(void);

/**
 * Clean up all of the openSSL items that are outstanding
 *
 * @param  - none
 * @return - none
 */
void ssl_cleanup(void);


#endif

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/