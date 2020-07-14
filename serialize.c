/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "serialize.h"
#include "logging.h"
#include "lib/json.h"

#define MODULE "serialize-"
#define SER_FILE_LEN 1024	//** Max file length 

/***************************************************************************//**
	print the serialization parameters pulled from the serialized json file
	@param a pointer to the serialization data structure
	@returns none
 ******************************************************************************/
static void SerializeData_print ( struct SerializeData* serial )
{
	printf("\n\n          ModelName = %s\n", serial->ModelName);
	printf("          NextNumber = %d\n", serial->NextNumber);
	printf("\n\n");
	return;
} // SerializeData_print

/***************************************************************************//**
	Load data from the serialization file into the serialization data structure
	@param none
	@returns a pointer to the serialization data structure
 ******************************************************************************/
struct SerializeData* serialize_load( char* fileName )
{
	#undef FUNCTION
	#define FUNCTION "serialize_load-"
	struct SerializeData* serial = NULL;

	FILE* fp = fopen(fileName, "r");
	if (fp)
	{
		char buffer[SER_FILE_LEN];
		size_t len = fread(buffer, 1, SER_FILE_LEN-1, fp);
		buffer[len++] = '\0'; // don't forget the end of string character

		JsonNode* json = json_decode(buffer);
		if (json)
		{
			serial = calloc(1, sizeof(struct SerializeData));
			if ( NULL == serial )
			{
				log_error("%s%sOut of memory! ",MODULE,FUNCTION);
				return NULL;
			}

			serial->ModelName = json_get_member_string(json, "ModelName");
			serial->NextNumber = 
							json_get_member_number(json, "NextNumber", 0);

			json_delete(json);
			log_verbose("%s%sSerialize parameters follow:",MODULE,FUNCTION);
			SerializeData_print( serial );
		}
		else
		{
			log_error("%s%s-Contents of %s are not valid JSON",
						MODULE, FUNCTION, fileName);
		}
		fclose(fp);
	}
	else
	{
		int err = errno;
		log_error("%s%s-Unable to open serialization file %s: %s",
					MODULE, FUNCTION, fileName, strerror(err));
	}
	return serial;
} // serialize_load

/***************************************************************************//**
	Save data from the serialization data structure into the serialization file
	@param a reference to a serialization data structure
	@param a string with the filename and path to the common serialization file
	@returns 1 on success
	@returns 0 on failure
 ******************************************************************************/
int serialize_save( struct SerializeData* serial, char* fileName )
{
	#undef FUNCTION
	#define FUNCTION "serialize_save-"

	JsonNode* json = json_mkobject();
	if ( NULL == json )
	{
		log_error("%s%sOut of memory! ",MODULE,FUNCTION);
		return 0; 
	}

	if(serial->ModelName)
	{
		json_append_member(json, "ModelName",
						   json_mkstring(serial->ModelName));
	}
	else
	{
		log_error("%s%sMissing required ModelName",MODULE,FUNCTION);
		return 0;
	}

	if(serial->NextNumber)
	{
		json_append_member(json, "NextNumber",
							json_mknumber(serial->NextNumber));

	}
	else
	{
		log_error("%s%sMissing required NextNumber",MODULE,FUNCTION);
		return 0;
	}

	FILE* fp = fopen(fileName,"w");
	if(fp)
	{
		char* serialString = json_stringify(json,"\t");
		size_t w = fwrite(serialString, 1, strlen(serialString), fp);
		if ( w != strlen(serialString) )
		{
			log_error("%s%sError writing to file %s",
						MODULE,FUNCTION,fileName);
			free(serialString);
			fclose(fp);
			return 0;
		}
		free(serialString);
		fclose(fp);
	}
	else
	{
		int err = errno;
		log_error("%s%sUnable to write serial file %s: %s",
				MODULE,FUNCTION,fileName,strerror(err));
		return 0;
	}
	
	return 1;
} // serialize_save

