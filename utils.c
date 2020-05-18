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
#include "utils.h"
#include "openssl_compat.h"
#include "logging.h"
#include "errno.h"
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>

#define MODULE "utils-"

#define SHA1LEN 20

/******************************************************************************/
/** @fn char NibbleToChar
	@brief Convert a single hex nibble 0..9..F
	@param char hexStr[] = Where to store the converted hex String
	@param int stringSize = The size of the string passed to the function
	@param unsigned char byteData[] = the byte data to convert as a byte array
	@param int byteSize = the size of the byte array
	@returns The ascii character for the hex nibble on success
	@returns A Z character if the nibble wasn't a valid hex character
*/
/******************************************************************************/
char NibbleToChar( unsigned char nibbleData )
{
	char retVal;
	if ( nibbleData <= 9 ) // note: it is unsigned so always >= 0
	{
		retVal = 0x30 + nibbleData;
	}
	else if (( nibbleData >= 10 ) && ( nibbleData <= 15 ))
	{
		// use 0x41 if you want upper case A..F
		retVal = 0x61 + ( nibbleData - 10 );
	}
	else
	{
		retVal = 'Z'; // Error!!
	}
	return retVal;
} // NibbleToChar

/******************************************************************************/
/** @fn void byte_to_hex_string
	@brief Convert a byte array into a hex string of characters.
	@param char hexStr[] = Where to store the converted hex String
	@param int stringSize = The size of the string passed to the function
	@param unsigned char byteData[] = the byte data to convert as a byte array
	@param int byteSize = the size of the byte array
	@returns 0 on success, -1 on failure
*/
/******************************************************************************/
int byte_to_hex_string( char hexStr[], int stringSize, unsigned char byteData[], int byteSize )
{
	int i = 0, c = 0;
	unsigned char lowNibble, highNibble;
	char lowNibbleChar, highNibbleChar;

	if ( stringSize < (( 2 * byteSize ) + 1) ) goto err; // string array isn't big enuf

	for ( ; byteSize > i; i++ )
	{
		lowNibble = 0x0F & byteData[i];
		highNibble = (0xF0 & byteData[i]) >> 4;
		lowNibbleChar = NibbleToChar( lowNibble );
		highNibbleChar = NibbleToChar( highNibble );
		hexStr[c++] = highNibbleChar;
		hexStr[c++] = lowNibbleChar;
	}
	hexStr[c] = '\0'; // remember to terminate the string!
	return 0; // success

err:
	return -1;
} // ByteToHexString

/******************************************************************************/
/** @fn void toLowerCase( char[] s)
	@brief convert a string to lower case, but ignore special characters
	@param char[] s = the string to convert
	@param len = the number of characters in the string
	@returns nothing
*/
/******************************************************************************/
void to_Lower_Case( char s[], const int len)
{
	int i = 0;

	for( ; len > i; i++ )
	{
		if ( s[i] >= 'A' && s[i] <= 'Z' )
		{
			s[i] = s[i] + 0x20;  // shift up 32
		}
	}
	return;
} // toLowerCase

/******************************************************************************/
/** @fn int file_exists( const char *file )
	@brief checks if a file exists already
	@param const char *file = path and filename of file to check
	@returns 0 if file does not exist, 1 if it does exist
*/
/******************************************************************************/
int file_exists( const char *file )
{
	int retval = 0;

	if ( -1 != access( file, F_OK ) )
	{
		retval = 1;
	}

	return retval;
} // file_exists


/******************************************************************************/
/** @fn int create_file( const char *file )
	@brief creates a blank file
	@param const char *file = path and filename of file to create
	@returns 0 if file file creation fails, 1 if file creation succeeds
*/
/******************************************************************************/
int create_file( const char *file )
{
	int retval = 0;
	FILE *fd;
	fd = fopen( file, "w" );
	if ( fd )
	{
		fclose( fd );
		retval = 1;
	}
	return retval;
} // create_file

char* hex_encode(unsigned char* inBuf, int len)
{
	char* thumbBuf = malloc(2 * len + 1);
	char* tempBuf = thumbBuf;

	size_t i;
	for(i=0; i < (size_t)len; i++) {
		tempBuf += sprintf(tempBuf, "%02x", inBuf[i]);
	}

	return thumbBuf;
}

char* compute_thumbprint(X509* cert)
{
	const EVP_MD* sha1 = EVP_sha1();
	unsigned char buf[SHA1LEN];
	unsigned len;

	int rc = X509_digest(cert, sha1, buf, &len);
	if (rc == 0 || len != SHA1LEN) {
		return NULL;
	}

	return hex_encode(buf, len);
}

bool is_cert_key_match(X509* cert, EVP_PKEY* key)
{
	#undef FUNCTION
	#define FUNCTION "is_cert_key_match"
	bool ret = false;
	if(cert && key)
	{
		EVP_PKEY* certPubKey = X509_get_pubkey(cert);
		int certBaseId = EVP_PKEY_base_id(certPubKey);
		int keyBaseId = EVP_PKEY_base_id(key);

		if(certBaseId == keyBaseId)
		{
			switch(certBaseId)
			{
			case EVP_PKEY_RSA:
				; // Declarations cannot start a case block
				RSA* rsaPriv = EVP_PKEY_get1_RSA(key);
				RSA* rsaCert = EVP_PKEY_get1_RSA(certPubKey);
				if(rsaCert && rsaPriv)
				{
					const BIGNUM* nCert;
					const BIGNUM* nPriv;
					RSA_get0_key(rsaCert, &nCert, NULL, NULL);
					RSA_get0_key(rsaPriv, &nPriv, NULL, NULL);
					ret = (BN_cmp(nCert, nPriv) == 0);
				}
				RSA_free(rsaPriv);
				RSA_free(rsaCert);
				break;
			case EVP_PKEY_EC:
				; // Declarations cannot start a case block
				EC_KEY* ecPriv = EVP_PKEY_get1_EC_KEY(key);
				EC_KEY* ecCert = EVP_PKEY_get1_EC_KEY(certPubKey);
				if(ecPriv && ecCert)
				{
					const EC_POINT* privPoint = EC_KEY_get0_public_key(ecPriv);
					const EC_GROUP* privGroup = EC_KEY_get0_group(ecPriv);
					char* privPubBytes = EC_POINT_point2hex(privGroup, privPoint, POINT_CONVERSION_UNCOMPRESSED, NULL);

					const EC_POINT* certPoint = EC_KEY_get0_public_key(ecCert);
					const EC_GROUP* certGroup = EC_KEY_get0_group(ecCert);
					char* certPubBytes = EC_POINT_point2hex(certGroup, certPoint, POINT_CONVERSION_UNCOMPRESSED, NULL);

					ret = (strcmp(privPubBytes, certPubBytes) == 0);

					OPENSSL_free(privPubBytes);
					OPENSSL_free(certPubBytes);
				}
				EC_KEY_free(ecCert);
				EC_KEY_free(ecPriv);
				break;
			default:
				log_error("%s%s-Unknown algorithm: %d", MODULE, FUNCTION, certBaseId);
				break;
			}
		}

		EVP_PKEY_free(certPubKey);
	}

	return ret;
}

int append_line(char** msg, const char* line)
{
	int ret = 0;

	if(msg && line)
	{
		int len = strlen(*msg) + strlen(line) + 2;
		char* tmp = realloc(*msg, len);
		if(tmp)
		{
			strcat(tmp, line);
			strcat(tmp, "\n");
			*msg = tmp;
		}
		else
		{
			ret = ENOMEM;
		}
	}
	else
	{
		ret = EINVAL;
	}

	return ret;
}

int append_linef(char** msg, const char* fmt, ...)
{
	int ret = 0;

	if(msg && fmt)
	{
		va_list args;
		va_start(args, fmt);
		int len = vsnprintf(NULL, 0, fmt, args);
		va_end(args);

		char line[len + 1];
		char* tmp = realloc(*msg, strlen(*msg) + len + 2);

		if(tmp)
		{
			va_list args2;
			va_start(args2, fmt);
			vsnprintf(line, len + 1, fmt, args2);
			va_end(args2);

			strcat(tmp, line);
			strcat(tmp, "\n");
			*msg = tmp;
		}
		else
		{
			ret = ENOMEM;
		}


	}
	else
	{
		ret = EINVAL;
	}

	return ret;
}

static int copy_file(const char* srcPath, const char* destPath)
{
	int err = 0;

	struct stat st;
	if(stat(srcPath, &st) == 0)
	{
		FILE* fpRead = fopen(srcPath, "r");
		if(!fpRead)
		{
			err = errno;
		}
		FILE* fpWrite = fopen(destPath, "w");
		if(!fpWrite)
		{
			err = errno;
		}

		if(fpRead && fpWrite)
		{
			char buf[1024];

			bool done = false;
			while(!done)
			{
				int rcnt = fread(buf, 1, 1024, fpRead);
				if(rcnt != 1024)
				{
					done = true;
					err = ferror(fpRead);
				}

				if(!err)
				{
					int wcnt = fwrite(buf, 1, rcnt, fpWrite);
					if(wcnt != rcnt)
					{
						done = true;
						err = ferror(fpWrite);
					}
				}
			}
		}

		if(fpRead)
		{
			fclose(fpRead);
		}
		if(fpWrite)
		{
			fclose(fpWrite);
		}
#ifdef __COMMENT_OUT__
		// Trying to match owner, etc. causes problems for non-privelged users. Callers of this method should get access themselves based on their circumstances
		struct stat destSt;
		if(stat(destPath, &destSt) == 0)
		{
			if(chmod(destPath, (st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO))) < 0)
			{
				err = errno;
			}

			uid_t uid = st.st_uid == destSt.st_uid ? -1 : st.st_uid;
			gid_t gid = st.st_gid == destSt.st_gid ? -1 : st.st_gid;
			if(uid != -1 || gid != -1)
			{
				if(chown(destPath, uid, gid) < 0)
				{
					err = errno;
				}
			}
		}
#endif
	}
	else
	{
		err = errno;
	}

	return err;
}

int read_file_bytes(const char* srcPath, unsigned char** pFileBytes, size_t* fileLen)
{
	int err = 0;

	FILE* fpRead = fopen(srcPath, "r");
	if(!fpRead)
	{
		err = errno;
	}
	else if(fseek(fpRead, 0, SEEK_END) != 0)
	{		
		err = ferror(fpRead);
	}
	else
	{
		*fileLen = ftell(fpRead);
		*pFileBytes = malloc(*fileLen);

		fseek(fpRead, 0, SEEK_SET);

		int rcnt = fread(*pFileBytes, 1, *fileLen, fpRead);
		if( (size_t)rcnt != *fileLen )
		{
			err = ferror(fpRead);
			free(*pFileBytes);
			*fileLen = 0;
		}

	}

	if(fpRead)
	{
		fclose(fpRead);
	}
	return err;
}

int backup_file(const char* file)
{
	#undef FUNCTION
	#define FUNCTION "backup_file"
	int err = 0;

	if(file)
	{
		// ### RAL Check if file exists, if not, create it
		if ( !file_exists( file ) )
		{
			create_file( file );
		}
		char backupPath[strlen(file) + 2];
		strcpy(backupPath, file);
		strcat(backupPath, "~");

		err = copy_file(file, backupPath);

		if(!err)
		{
			
			if(chmod(backupPath, (S_IRUSR | S_IWUSR )) < 0)
			{
				err = errno;
			}
		}
	}
	else
	{
		log_info("%s%s-No file found at %s", MODULE, FUNCTION, file);
		err = ENOENT;
	}

	return err;
}

int restore_file(const char* file)
{
	int err = 0;

	if(file)
	{
		char backupPath[strlen(file) + 2];
		strcpy(backupPath, file);
		strcat(backupPath, "~");

		err = copy_file(backupPath, file);
	}
	else
	{
		err = EINVAL;
	}

	return err;
}

int replace_file(const char* file, const char* contents, long len, bool backup)
{
	#undef FUNCTION
	#define FUNCTION "replace_file"
	int err = 0;

	if(backup)
	{
		err = backup_file(file);
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
					   MODULE, FUNCTION, file, errStr);
		}
		else
		{
			log_verbose("%s%s-Preparing to write %ld bytes to the modified store",
						MODULE, FUNCTION, len);

			if(fwrite(contents, 1, len, fpWrite) == (size_t)len)
			{
				log_verbose("%s%s-Store %s written successfully",
							MODULE, FUNCTION, file);
			}
			else
			{
				err = errno;
				char* errStr = strerror(errno);
				log_error("%s%s-Unable to write store at %s: %s",
							MODULE, FUNCTION, file, errStr);
			}
		}

		if(fpWrite)
		{
			fclose(fpWrite);
		}
	}

	return err;
}


/******************************************************************************/
/** @fn char* util_strip_string
	@brief strip a string from another string & return the result.
	       NOTE: This is a CASE SENSITIVE removal.
	@param fromString, the full string from which we want to remove
	@param stripString, the string we want to strip from fromString
*/
/******************************************************************************/
void util_strip_string(char* fromString, const char* stripString)
{
#undef FUNCTION
#define FUNCTION "util_strip_string-"
	char* beforeString = (char*) malloc(250);
	char* afterString = (char*) malloc(250);

	log_trace("%s%s-Attempting to strip %s from %s",MODULE,FUNCTION,stripString,fromString);
	afterString = strstr(fromString, stripString);
	if ( afterString )
	{

		log_trace("%s%s-After string %s",MODULE,FUNCTION,afterString);
		memcpy( beforeString, fromString, strlen(fromString) - strlen(afterString) );
		beforeString = strcat( beforeString, "\0");
		log_trace("%s%s-Before string = %s",MODULE,FUNCTION,beforeString);
		afterString = memmove( afterString, afterString + strlen(stripString),
				       strlen(afterString) - strlen(stripString) + 1 );
		log_trace("%s%s-After string = %s",MODULE,FUNCTION,afterString);
		fromString = strcat( beforeString, afterString );
	}
	else
	{
		log_trace("%s%s-afterString is null not modifying fromString",MODULE,FUNCTION);
	}

	/* Clean up */
	if ( beforeString )
	{
		log_trace("%s%s-Freeing beforeString",MODULE,FUNCTION);
		free(beforeString);
	}

	/* afterString release was causing core faults, so allow it to exist */

	log_trace("%s%s-Returning result = %s",MODULE,FUNCTION,fromString);
	return;
}
