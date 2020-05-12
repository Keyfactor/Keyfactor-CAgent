/*
This C Agent Reference Implementation uses the OpenSSL encryption libraries, 
which are not included as a part of this distribution.  For hardware key storage 
or TPM support, libraries such as WolfSSL may also be used in place of OpenSSL.

NOTE: usage of this file and the SDK is subject to the 
following SOFTWARE DEVELOPMENT KIT LICENSE: 

THIS IS A LICENSE AGREEMENT between you and Certified Security Solutions, Inc.,
 6050 Oak Tree Boulevard, Suite 450, Independence, Ohio 44131 (“CSS”).  This 
 License Agreement accompanies the Software Development Kit(s) (“SDK,” as 
 defined below) for CSS Products (defined below) licensed to you by CSS.  This 
 copy of the SDK is licensed to You as the end user or the representative of 
 your employer.  You represent that CSS, a licensee of one or more CSS Products
 , or a third-party working on behalf of such a licensee has authorized you to
 download this SDK.  YOU AGREE THAT THIS LICENSE AGREEMENT IS ENFORCEABLE AND 
 THAT YOUR USE OF THE SDK CONSTITUTES ACCEPTANCE OF THE AGREEMENT TERMS.  If 
 you do not agree to the terms of this Agreement, do not use this SDK.  
1. DEFINITIONS.
In this License Agreement: 
(a) “SDK” means the CSS software development kit, including any sample code, 
tools, utilities, documentation, and related explanatory materials and 
includes any upgrades, modified versions, updates, additions, and copies of 
the SDK;  
(b) “CSS Products” means[ CSS’s CMS application programs, technologies and 
software, including but not limited to CMS Enterprise, CMS Sapphire, CMS 
Topaz, and CMS VerdeTTo,] that are or may be made available for licensing, 
including any modified versions or upgrades thereof.  This License Agreement
 does not govern use of CSS Products, which are governed by separate written
 license agreements; and
(c) “You” and “your” refer to any person or entity acquiring or using the 
SDK under the terms of this License Agreement.
2. ROYALTY-FREE DEVELOPMENT LICENSE. Subject to the restrictions contained 
in this Section 2, CSS grants you limited a nonexclusive, nontransferable, 
royalty-free license to use the items in the SDK only for the purpose of 
development of software designed to interoperate with licensed CSS Products 
either on Your own behalf or on behalf of a licensee of one or more CSS
 Products.
(a) Under this License Agreement, you may use, modify, or merge all or 
portions of any sample code included in the SDK with your software .  Any 
modified or merged portion of sample code is subject to this License 
Agreement.  You are required to include CSS’s copyright notices in your 
software. You may make a reasonable, limited number of copies of the SDK to 
be used by your employees or contractors as provided herein, and not for 
general business purposes, and such employees or contractors shall be 
subject to the obligations and restrictions in this License Agreement.  
Except in accordance with the preceding sentence, you may not assign, 
sublicense, or otherwise transfer your rights or obligations granted under 
this License Agreement without the prior written consent of CSS. Any 
attempted assignment, sublicense, or transfer without such prior written 
consent shall be void and of no effect.  CSS may assign or transfer this 
License Agreement in whole or in part, and it will inure to the benefit of 
any successor or assign of CSS.
(b) Under this License Agreement, if you use, modify, or merge all or 
portions of any sample code included in the SDK with your software, you may
distribute it as part of your products solely on a royalty-free 
non-commercial basis.  Any right to distribute any part of the SDK or any 
modified, merged, or derivative version on a royalty-bearing or other 
commercial basis is subject to separate approval, and possibly the 
imposition of a royalty, by CSS.
(c) Except as expressly permitted in paragraphs 2(a) and 2(b), you may not
 sell, sublicense, rent, loan, or lease any portion of the SDK to any third
 party. You may not decompile, reverse engineer, or otherwise access or 
 attempt to access the source code for any part of the SDK not made
 available to you in source code form, nor make or attempt to make any
 modification to the SDK or remove, obscure, interfere with, or circumvent 
 any feature of the SDK, including without limitation any copyright or 
 other intellectual property notices, security, or access control mechanism.
 
3. PROPRIETARY RIGHTS. The items contained in the SDK are the intellectual
 property of CSS and are protected by United States and international 
 copyright and other intellectual property law. You agree to protect all 
 copyright and other ownership interests of CSS  in all items in the SDK 
 supplied to you under this License Agreement. You agree that all copies 
 of the items in the SDK, reproduced for any reason by you, will contain 
 the same copyright notices, and other proprietary notices as appropriate,
 as appear on or in the master items delivered by CSS in the SDK. CSS 
 retains title and ownership of the items in the SDK, the media on which 
 it is recorded, and all subsequent copies, regardless of the form or media
 in or on which the original and other copies may exist.  You may use CSS’s
 trade names, trademarks and service marks only as may be required to 
 accurately describe your products and to provide copyright notice as 
 required herein.
Except as expressly granted above, this License Agreement does not grant 
you any rights under any patents, copyrights, trade secrets, trademarks or 
any other rights in respect to the items in the SDK.
4. FEEDBACK. You are encouraged to provide CSS with comments, bug reports, 
feedback, enhancements, or modifications proposed or suggested by you for 
the SDK or any CSS Product (“Feedback”). If provided, CSS will treat such 
Feedback as non-confidential notwithstanding any notice to the contrary you 
may include in any accompanying communication, and CSS shall have the right
 to use such Feedback at its discretion, including, but not limited to, the
 incorporation of such suggested changes into the SDK or any CSS Product. 
 You hereby grant CSS a perpetual, irrevocable, transferable, sublicensable,
 royalty-free, worldwide, nonexclusive license under all rights necessary to
 so incorporate and use your Feedback for any purpose, including to make 
 and sell products and services.  
5. TERM. This License Agreement is effective until terminated.  CSS has 
the right to terminate this License Agreement immediately, without judicial
 intervention, if you fail to comply with any term herein. Upon any such
 termination you must remove all full and partial copies of the items in 
 the SDK from your computer and discontinue the use of the items in the 
 SDK.
6. DISCLAIMER OF WARRANTY. CSS licenses the SDK to you on an “AS-IS” basis.
 CSS makes no representation with respect to the adequacy of any items in
 the SDK, whether or not used by you in the development of any products, 
 for any particular purpose or with respect to their adequacy to produce 
 any particular result. CSS shall not be liable for loss or damage arising
 out of this License Agreement or from the distribution or use of your 
 products containing portions of the SDK. TO THE FULLEST EXTENT PERMITTED 
 BY LAW, CSS DISCLAIMS ALL WARRANTIES, EITHER EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO IMPLIED CONDITIONS OR WARRANTIES OF MERCHANTABILITY AND
 FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT OF ANY THIRD PARTY 
 RIGHT IN RESPECT OF THE ITEMS IN THE SDK.
CSS is under no obligation to provide any support under this License 
Agreement, including upgrades or future versions of the SDK or any portions
 thereof, to you, any end user or to any other party. 
7. LIMITATION OF LIABILITY. Notwithstanding any other provisions of this 
License Agreement, CSS’s liability to you under this License Agreement 
shall be limited to the amount you paid for the SDK or $10, whichever is 
less.
IN NO EVENT WILL CSS BE LIABLE TO YOU FOR ANY CONSEQUENTIAL, INDIRECT, 
INCIDENTAL, PUNITIVE, OR SPECIAL DAMAGES, INCLUDING DAMAGES FOR ANY LOST 
PROFITS, LOST SAVINGS, LOSS OF DATA, COSTS, FEES OR EXPENSES OF ANY KIND OR
 NATURE, ARISING OUT OF ANY PROVISION OF THIS LICENSE AGREEMENT OR THE USE
 OR INABILITY TO USE THE ITEMS IN THE SDK, EVEN IF A CSS REPRESENTATIVE HAS
 BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES, OR FOR ANY CLAIM BY ANY 
 PARTY. 
8. INDEMNIFICATION. You agree to indemnify, hold harmless, and defend CSS
 from and against any claims or lawsuits, including attorneys’ fees, that 
 arise or result from the use and distribution of your products that 
 contain or are based upon any portion of the SDK, provided that CSS gives
 you prompt written notice of any such claim, tenders the defense or 
 settlement of such a claim to you at your expense, and cooperates with 
 you, at your expense, in defending or settling any such claim.
9. CHOICE OF LAW. This Agreement will be governed by and construed in 
accordance with the substantive laws of the United States and the State of
 Ohio.  Federal and state courts located in Cuyahoga County, Ohio shall 
 have exclusive jurisdiction over all disputes relating to this Agreement.
 This Agreement will not be governed by the conflict of law rules of any 
 jurisdiction or the United Nations Convention on Contracts for the 
 International Sale of Goods, the application of which is expressly 
 excluded.
10. COMPLIANCE WITH EXPORT CONTROL LAWS. You agree that any of your 
products that include any part of the SDK will not be shipped, transferred
 or exported into any country or used in any manner prohibited by the 
 United States Export Administration Act and that you will comply with 
 all applicable export control laws. All rights to use the SDK are granted 
 on condition that such rights are forfeited if you fail to comply with the
 terms of this Agreement.
11. NON-BLOCKING OF CSS DEVELOPMENT. You acknowledge that CSS is currently 
developing or may develop technologies and products in the future that have
 or may have design and/or functionality similar to products that you may
 develop based on your license herein. Nothing in this Agreement shall
 impair, limit or curtail CSS’s right to continue with its development, 
 maintenance and/or distribution of CSS’s technology or products. You agree
 that you shall not assert any patent that you own against CSS, its 
 subsidiaries or affiliates, or their customers, direct or indirect, 
 agents and contractors for the manufacture, use, import, licensing, offer
 for sale or sale of any CSS Products.
12. OPEN SOURCE SOFTWARE. Notwithstanding anything to the contrary, you
 are not licensed to (and you agree that you will not) integrate or use 
 this SDK with any Viral Open Source Software or otherwise take any action
 that could require disclosure, distribution, or licensing of all or any 
 part of the SDK in source code form, for the purpose of making derivative
 works, or at no charge. For the purposes of this Section 12, “Viral Open
 Source Software” shall mean software licensed under the GNU General 
 Public License, the GNU Lesser General Public License, or any other 
 license terms that could require, or condition your use, modification, or
 distribution of such software on, the disclosure, distribution, or 
 licensing of any other software in source code form, for the purpose of
 making derivative works, or at no charge. Any violation of the foregoing
 provision shall immediately terminate all of your licenses and other 
 rights to the SDK granted under this Agreement.
13. WAIVER. None of the provisions of this License Agreement shall be 
deemed to have been waived by any act or acquiescence on the part of CSS, 
its agents or employees, but only by an instrument in writing signed by an 
officer of CSS.
14.  INTEGRATION. When conflicting language exists between this License 
Agreement and any other agreement included in the SDK, this License 
Agreement shall supersede. If either you or CSS employ attorneys to enforce
 any rights arising out of or relating to this License Agreement, the 
 prevailing party shall be entitled to recover reasonable attorneys’ fees. 
 You acknowledge that you have read this License Agreement, understand it
 and that it is the complete and exclusive statement of your agreement 
 with CSS that supersedes any prior agreement, oral or written, between 
 CSS and you with respect to the licensing of the SDK. No variation of 
 the terms of this License Agreement will be enforceable against CSS unless
 CSS gives its express consent, in writing signed by an officer of CSS. 
15.  GOVERNMENT LICENSE.  If the SDK is licensed to the U.S. Government
 or any agency thereof, it will be considered to be “commercial computer 
 software” or “commercial computer software documentation,” as those terms 
 are used in 48 CFR § 12.212 or 48 CFR § 227.7202, and is being licensed 
 with only those rights as are granted to all other licensees as set forth 
 in this Agreement.*/

#include "ecdh.h"

#include <stdio.h>

#ifdef __WOLF_SSL__
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/hmac.h>
#else
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif


#include "lib/base64.h"
#include "lib/json.h"
#include "logging.h"
#include "symmetricEncryption.h"

static void* KDF_SHA256_Append(const void* in, size_t inLen, void* out, size_t* outLen, const void* append, size_t appendLen)
{
	if(*outLen < SHA256_DIGEST_LENGTH)
	{
		return NULL;
	}

	size_t newInLen = inLen + appendLen;
	unsigned char* newIn = malloc(newInLen);

	/* Copy data to appended buffer */
	memcpy(newIn, in, inLen);
	memcpy(&newIn[inLen], append, appendLen);

	*outLen = SHA256_DIGEST_LENGTH;
	SHA256(newIn, newInLen, out);

	free(newIn);

	return out;
}

static void* KDF_SHA256_0001(const void* in, size_t inLen, void* out, size_t* outLen)
{
	char append[] = {0, 0, 0, 1};
	return KDF_SHA256_Append(in, inLen, out, outLen, append, 4);
}

static void* KDF_SHA256_0002(const void* in, size_t inLen, void* out, size_t* outLen)
{
	char append[] = {0, 0, 0, 2};
	return KDF_SHA256_Append(in, inLen, out, outLen, append, 4);
}

static EC_KEY* validate_unwrap_EC_KEY(EVP_PKEY* key)
{
	if(!key)
	{
		log_error("ecdh-validate_unwrap_EC_KEY-key is not specified");
		return NULL;
	}
	if(EVP_PKEY_type(key->type) != EVP_PKEY_EC)
	{
		log_error("ecdh-validate_unwrap_EC_KEY-key is not an ECC key");
		return NULL;
	}

	EC_KEY* otherEC = EVP_PKEY_get1_EC_KEY(key);

	int keyNID = EC_GROUP_get_curve_name(EC_KEY_get0_group(otherEC));
	if(keyNID != NID_X9_62_prime256v1 && keyNID != NID_secp384r1 && keyNID != NID_secp521r1)
	{
		log_error("ecdh-validate_unwrap_EC_KEY-key does not have a supported curve");
		EC_KEY_free(otherEC);
		otherEC = NULL;
	}

	return otherEC;
}

static EC_KEY* generate_ephemeral_key(EC_KEY* otherEC)
{
	EC_KEY* ephemeral = NULL;
	int keyNID = EC_GROUP_get_curve_name(EC_KEY_get0_group(otherEC));
	ephemeral = EC_KEY_new_by_curve_name(keyNID);
	EC_KEY_set_asn1_flag(ephemeral, OPENSSL_EC_NAMED_CURVE);
	EC_KEY_generate_key(ephemeral);

	return ephemeral;
}

static EC_KEY* ecdh_decode_public_key(char* b64Key)
{
	EC_KEY* key = NULL;
	EVP_PKEY* wrapKey = NULL;
	size_t decodedLen;
	unsigned char* decoded = base64_decode(b64Key, strlen(b64Key), &decodedLen);

	BIO* bio = BIO_new_mem_buf(decoded, (int)decodedLen);
	if(d2i_PUBKEY_bio(bio, &wrapKey))
	{
		key = validate_unwrap_EC_KEY(wrapKey);
	}
	else
	{
		log_error("ecdh-ecdh_decode_public_key-Unable to decode public key");
	}

	if(bio)
	{
		BIO_free(bio);
		bio = NULL;
	}
	if(decoded)
	{
		free(decoded);
		decoded = NULL;
	}
	if(wrapKey)
	{
		EVP_PKEY_free(wrapKey);
		wrapKey = NULL;
	}
	return key;
}

static char* ecdh_encode_public_key(EC_KEY* pubKey)
{
	char* encoded = NULL;
	BIO* bio = BIO_new(BIO_s_mem());
	EVP_PKEY* wrapKey = EVP_PKEY_new();

	if(EVP_PKEY_set1_EC_KEY(wrapKey, pubKey) && i2d_PUBKEY_bio(bio, wrapKey))
	{
		char* rawData;
		long rawDataLen = BIO_get_mem_data(bio, &rawData);
		encoded = base64_encode(rawData, (size_t)rawDataLen, false, NULL);
	}
	else
	{
		log_error("ecdh-ecdh_encode_public_key-Unable to encode public key");
	}

	if(wrapKey)
	{
		EVP_PKEY_free(wrapKey);
		wrapKey = NULL;
	}
	if(bio)
	{
		BIO_free(bio);
		bio = NULL;
	}

	return encoded;
}

static bool ecdh_json_decode(char* json, unsigned char** ciphertext, size_t* ciphertextLen, EC_KEY** senderKey, unsigned char** hmac, size_t* hmacLen)
{
	JsonNode* jsonRoot = NULL;
	char* rawSenderKey = NULL;
	char* rawHMAC = NULL;
	char* rawCipher = NULL;

	if(!json)
	{
		log_error("ecdh-ecdh_json_decode-JSON input is required");
		return false;
	}

	jsonRoot = json_decode(json); 
	if(jsonRoot)
	{
		rawSenderKey = json_get_member_string(jsonRoot, "PublicKey");
		rawHMAC = json_get_member_string(jsonRoot, "HMAC");
		rawCipher = json_get_member_string(jsonRoot, "Ciphertext");
	}
	else
	{
		log_error("ecdh-ecdh_json_decode-Unable to decode JSON input");
	}

	if(rawSenderKey)
	{
		*senderKey = ecdh_decode_public_key(rawSenderKey);
	}
	else
	{
		log_error("ecdh-ecdh_json_decode-Unable to decode sender key");
	}

	if(rawCipher)
	{
		*ciphertext = base64_decode(rawCipher, strlen(rawCipher), ciphertextLen);
	}
	else
	{
		log_error("ecdh-ecdh_json_decode-Unable to decode ciphertext");
	}

	if(rawHMAC && hmac)
	{
		*hmac = base64_decode(rawHMAC, strlen(rawHMAC), hmacLen);
	}

	if(jsonRoot)
	{
		json_delete(jsonRoot);
		jsonRoot = NULL;
	}
	if(rawSenderKey)
	{
		free(rawSenderKey);
		rawSenderKey = NULL;
	}
	if(rawHMAC)
	{
		free(rawHMAC);
		rawHMAC = NULL;
	}
	if(rawCipher)
	{
		free(rawCipher);
		rawCipher = NULL;
	}
	return *ciphertext && *senderKey;
}

static char* ecdh_json_encode(unsigned char* ciphertext, size_t ciphertextLen, EC_KEY* senderKey, unsigned char* hmac, size_t hmacLen)
{
	char* encodedKey = NULL;
	char* encodedCipher = NULL;
	char* encodedHMAC = NULL;
	JsonNode* jsonRoot = NULL;
	char* toReturn = NULL;

	if(!ciphertext)
	{
		log_error("ecdh-ecdh_json_encode-Ciphertext is required");
		return NULL;
	}
	if(!senderKey)
	{
		log_error("ecdh-ecdh_json_encode-Sender's public key is required");
		return NULL;
	}

	encodedKey = ecdh_encode_public_key(senderKey);
	encodedCipher = base64_encode(ciphertext, ciphertextLen, false, NULL);
	if(hmac)
	{
		encodedHMAC = base64_encode(hmac, hmacLen, false, NULL);
	}

	if(encodedKey && encodedCipher && (!hmac || encodedHMAC))
	{
		jsonRoot = json_mkobject();
		json_append_member(jsonRoot, "PublicKey", json_mkstring(encodedKey));
		json_append_member(jsonRoot, "Ciphertext", json_mkstring(encodedCipher));
		if(encodedHMAC)
		{
			json_append_member(jsonRoot, "HMAC", json_mkstring(encodedHMAC));
		}
	}

	if(jsonRoot)
	{
		toReturn = json_encode(jsonRoot);
	}

	if(jsonRoot)
	{
		json_delete(jsonRoot);
		jsonRoot = NULL;
	}
	if(encodedHMAC)
	{
		free(encodedHMAC);
		encodedHMAC = NULL;
	}
	if(encodedCipher)
	{
		free(encodedCipher);
		encodedCipher = NULL;
	}
	if(encodedKey)
	{
		free(encodedKey);
		encodedKey = NULL;
	}

	return toReturn;	
}

bool decrypt_ecdh(char* json, EVP_PKEY* recipientKey, unsigned char** plaintext, size_t* plaintextLen)
{
	bool hasError = false;
	EC_KEY* recipientEC = NULL;
	unsigned char* ciphertext = NULL;
	size_t ciphertextLen = 0;
	EC_KEY* senderKey = NULL;
	unsigned char* hmac = NULL;
	size_t hmacLen = 0;

	if(!plaintext || !recipientKey || !json)
	{
		log_error("ecdh-decrypt_ecdh-All parameters are required");
		hasError = true;
	}

	if(!hasError && !(recipientEC = validate_unwrap_EC_KEY(recipientKey)))
	{
		log_error("ecdh-decrypt_ecdh-recipientKey is not a valid ECC key");
		hasError = true;
	}

	if(!hasError && !ecdh_json_decode(json, &ciphertext, &ciphertextLen, &senderKey, &hmac, &hmacLen))
	{
		log_error("ecdh-decrypt_ecdh-Unable to decode JSON object");
		hasError = true;
	}

	// Allocate ample space for the keys
	unsigned char aesKey[100];
	unsigned char hmacKey[100];
	int aesKeyLen = 100;
	int hmacKeyLen = 100;

	*plaintext = malloc(ciphertextLen);

	unsigned int hmacBytesLen = EVP_MAX_MD_SIZE;
	unsigned char hmacBytes[EVP_MAX_MD_SIZE];

	if(!hasError && !(aesKeyLen = ECDH_compute_key(aesKey, aesKeyLen, EC_KEY_get0_public_key(senderKey), recipientEC, KDF_SHA256_0001)))
	{
		log_error("ecdh-decrypt_ecdh-Unable to compute AES key");
		hasError = true;
	}

	if(!hasError && !symmetricDecrypt(ciphertext, ciphertextLen, aesKey, NULL, *plaintext, (unsigned int*)plaintextLen))
	{
		log_error("ecdh-decrypt_ecdh-Unable to perform symmetric decryption");
		hasError = true;
	}

	if(hmac)
	{
		if(!hasError && !(hmacKeyLen = ECDH_compute_key(hmacKey, hmacKeyLen, EC_KEY_get0_public_key(senderKey), recipientEC, KDF_SHA256_0002)))
		{
			log_error("ecdh-decrypt_ecdh-Unable to compute HMAC key");
			hasError = true;
		}
		if(!hasError)
		{
			if(!HMAC(EVP_sha256(), hmacKey, hmacKeyLen, *plaintext, *plaintextLen, hmacBytes, &hmacBytesLen))
			{
				log_error("ecdh-decrypt_ecdh-Unable to perform HMAC");
				hasError = true;
			}
			else
			{
				char* hmacDebug = base64_encode(hmacBytes, hmacLen, false, NULL);
				log_verbose("ecdh-decrypt_ecdh-HMAC: %s", hmacDebug);
				free(hmacDebug);
			}
		}
		if(!hasError && (hmacLen != hmacBytesLen || memcmp(hmac, hmacBytes, hmacLen)!= 0))
		{
			log_error("ecdh-decrypt_ecdh-HMAC does not match");
			hasError = true;
		}
	}

	if(hasError && *plaintext) // Cleanup output parameters if we error out
	{
		free(*plaintext);
		*plaintext = 0;
		*plaintextLen = 0;
	}
	if(recipientEC)
	{
		EC_KEY_free(recipientEC);
		recipientEC = NULL;
	}
	if(ciphertext)
	{
		free(ciphertext);
		ciphertext = NULL;
	}
	if(senderKey)
	{
		EC_KEY_free(senderKey);
		senderKey = NULL;
	}
	if(hmac)
	{
		free(hmac);
		hmac = NULL;
	}
	return !hasError;
}

bool encrypt_ecdh(unsigned char* plaintext, size_t plaintextLen, EVP_PKEY* recipientKey, char** json)
{
	bool hasError = false;
	EC_KEY* recipientEC = NULL;
	EC_KEY* ephemeralEC = NULL;

	if(!plaintext || !recipientKey || !json)
	{
		log_error("ecdh-encrypt_ecdh-All parameters are required");
		hasError = true;
	}

	if(!hasError && !(recipientEC = validate_unwrap_EC_KEY(recipientKey)))
	{
		log_error("ecdh-encrypt_ecdh-recipientKey is not a valid ECC key");
		hasError = true;
	}
	if(!hasError && !(ephemeralEC = generate_ephemeral_key(recipientEC)))
	{
		log_error("ecdh-encrypt_ecdh-Unable to validate ephemeral key");
		hasError = true;
	}

	// Allocate ample space for the keys
	unsigned char aesKey[100];
	unsigned char hmacKey[100];
	int aesKeyLen = 100;
	int hmacKeyLen = 100;

	unsigned int ciphertextLen = plaintextLen + 100;
	unsigned char* ciphertext = malloc(ciphertextLen);

	unsigned int hmacLen = EVP_MAX_MD_SIZE;
	unsigned char hmacBytes[EVP_MAX_MD_SIZE];

	if(!hasError && !(aesKeyLen = ECDH_compute_key(aesKey, aesKeyLen, EC_KEY_get0_public_key(recipientEC), ephemeralEC, KDF_SHA256_0001)))
	{
		log_error("ecdh-encrypt_ecdh-Unable to compute AES key");
		hasError = true;
	}
	if(!hasError && !(hmacKeyLen = ECDH_compute_key(hmacKey, hmacKeyLen, EC_KEY_get0_public_key(recipientEC), ephemeralEC, KDF_SHA256_0002)))
	{
		log_error("ecdh-encrypt_ecdh-Unable to compute HMAC key");
		hasError = true;
	}

	if(!hasError)
	{
		if(!HMAC(EVP_sha256(), hmacKey, hmacKeyLen, plaintext, plaintextLen, hmacBytes, &hmacLen))
		{
			log_error("ecdh-encrypt_ecdh-Unable to perform HMAC");
			hasError = true;
		}
		else
		{
			char* hmacDebug = base64_encode(hmacBytes, hmacLen, false, NULL);
			log_verbose("HMAC: %s", hmacDebug);
			free(hmacDebug);
		}
	}

	if(!hasError && !symmetricEncrypt(plaintext, plaintextLen, aesKey, NULL, ciphertext, &ciphertextLen))
	{
		log_error("ecdh-encrypt_ecdh-Unable to perform symmetric encryption");
		hasError = true;
	}

	if(!hasError)
	{
		*json = ecdh_json_encode(ciphertext, ciphertextLen, ephemeralEC, hmacBytes, hmacLen);
	}

	if(ciphertext)
	{
		free(ciphertext);
		ciphertext = NULL;
	}
	if(recipientEC)
	{
		EC_KEY_free(recipientEC);
		recipientEC = NULL;
	}
	if(ephemeralEC)
	{
		EC_KEY_free(ephemeralEC);
		ephemeralEC = NULL;
	}

	return !hasError;
}

