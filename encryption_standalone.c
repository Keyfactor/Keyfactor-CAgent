/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include <stdio.h>
#include <string.h>
#include "encryption.h"
#include "lib/json.h"
#include <stdint.h>

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/openssl/pem.h>
#else
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#endif

int main(int argc, char* argv[]){
    char* payloadPath = argv[1];
    char* keyPath = argv[2];
    char* outputPath = argv[3];

    FILE* key = fopen(keyPath, "r");
    EVP_PKEY* pkey = NULL;
    pkey = PEM_read_PUBKEY(key, &pkey, NULL, NULL);
    fclose (key);

    FILE* payload = fopen(payloadPath, "r");
    fseek (payload, 0, SEEK_END);
    int length = ftell (payload);
    fseek (payload, 0, SEEK_SET);
    char* contents = malloc (length);
    fread (contents, 1, length, payload);
    fclose (payload);

    char* json = malloc(length+2048+strlen(payloadPath));
    encrypt(contents, pkey, &json);
    JsonNode* jsonBlob = json_decode(json);
    json_append_member(jsonBlob, "Filename", json_mkstring(payloadPath));
    free(json);
    json = json_encode(jsonBlob);
    json_delete(jsonBlob);

    FILE* output = fopen(outputPath, "w");
    fwrite(json, sizeof(char), strlen(json), output);
    fclose(output);

    return 0;
}
