/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file utils.c */
#include "utils.h"
#include "logging.h"
#include "errno.h"
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

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
	int err = 0;
	char* dummy = NULL;

	if(file)
	{
		/* Check if file exists, if not, create it */
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
		if ( NULL == file )
		{
			dummy = strdup("NULL");
		}
		else
		{
			dummy = strdup(file);
		}
		log_info("%s::%s(%d) : No file found at %s", \
			__FILE__, __FUNCTION__, __LINE__, dummy);
		free(dummy);
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
			log_error("%s::%s(%d) : Unable to open store at %s for writing: %s",
					   __FILE__, __FUNCTION__, __LINE__, file, errStr);
		}
		else
		{
			log_verbose("%s::%s(%d) : Preparing to write %ld bytes to the modified store",
						__FILE__, __FUNCTION__, __LINE__, len);

			if(fwrite(contents, 1, len, fpWrite) == (size_t)len)
			{
				log_verbose("%s::%s(%d) : Store %s written successfully",
							__FILE__, __FUNCTION__, __LINE__, file);
			}
			else
			{
				err = errno;
				char* errStr = strerror(errno);
				log_error("%s::%s(%d) : Unable to write store at %s: %s",
							__FILE__, __FUNCTION__, __LINE__, file, errStr);
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
char* util_strip_string(const char* fromString, const char* stripString)
{
	char* beforeString = NULL;
	char* stripPointer = NULL;
	char* afterString = NULL;
	char* returnString = NULL;
	size_t fromLen = strlen(fromString);
	size_t stripLen = strlen(stripString);
	size_t beforeLen = 0;
	size_t afterLen = 0;
	size_t stripPtrLen = 0;


	log_trace("%s::%s(%d) : Attempting to strip %s from %s", \
		__FILE__, __FUNCTION__, __LINE__, stripString,fromString);
	/* get a pointer into fromString at the staring location */
	/* of the strip string */
	stripPointer = strstr(fromString, stripString);
	if ( stripPointer )
	{
		stripPtrLen = strlen(stripPointer);
		if ( fromLen > stripPtrLen )
		{
			beforeString = calloc( (fromLen-stripPtrLen+1), sizeof(*beforeString) );
			strncpy( beforeString, fromString, (fromLen-stripPtrLen) );
		}
		else
		{
			beforeString = strdup("");
		}
		beforeLen = strlen(beforeString);
		afterString = &stripPointer[stripLen];
		afterLen = strlen(afterString);
		returnString = strdup(beforeString);
		returnString = realloc(returnString, (beforeLen+afterLen+1));
		strcat( returnString, afterString );
	}
	else
	{
		returnString = strdup(fromString);
		log_trace("%s::%s(%d) : Didn't find %s inside %s, not modifying %s",
			__FILE__, __FUNCTION__, __LINE__, stripString, fromString, fromString);
	}

	/* Clean up */
	if ( beforeString )
	{
		free(beforeString);
	}
	return returnString;
} /* util_strip_string */

/**																*/
/* Better string concatenation vs the mess that is ANSI C 		*/
/* 																*/
/* @param  - [Input] s1 = null terminated string to pre-pend 	*/
/* @param  - [Input] s2 = null terminated string to append 		*/
/* @return - failure: NULL 										*/
/*           success: ptr to the new string 					*/
/** 															*/
char* bstrcat(const char* s1, const char* s2)
{
	size_t s1Len, s2Len, i, j;
	char* result;

	s1Len = strlen(s1);
	s2Len = strlen(s2);
	result = calloc(s1Len+s2Len+1, sizeof(*result));

	i = 0;
	while ((s1Len > i) && (*(s1 + i) != '\0'))
	{
		result[i] = s1[i];
		i++;
	}
	if (s1Len != i)
	{
		if ( NULL != result ) { free(result); }
		result = NULL;
	}
	else
	{
		j = 0;
		while ((s2Len > j) && (*(s2 + j) != '\0'))
		{
			result[i] = s2[j];
			i++;
			j++;
		}
		if (s2Len != j)
		{
			if ( NULL != result ) { free(result); }
			result = NULL;
		}	
	}

	if ( NULL != result ) 
	{
		result[i] = '\0';
	}

	return result;
} /* bstrcat */