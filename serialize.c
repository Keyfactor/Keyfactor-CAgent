/******************************************************************************/
/* Copyright 2021 Keyfactor                                                   */
/* Licensed under the Apache License, Version 2.0 (the "License"); you may    */
/* not use this file except in compliance with the License.  You may obtain a */
/* copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless */
/* required by applicable law or agreed to in writing, software distributed   */
/* under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   */
/* OR CONDITIONS OF ANY KIND, either express or implied. See the License for  */
/* thespecific language governing permissions and limitations under the       */
/* License.                                                                   */
/******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "serialize.h"
#include "logging.h"
#include "lib/json.h"

#define SER_FILE_LEN 1024	/* Max file length */

/**                                                                           */
/*	print the serialization parameters pulled from the serialized json file   */
/*	@param a pointer to the serialization data structure                      */
/*	@return none                                                              */
/*                                                                            */
static void SerializeData_print ( struct SerializeData* serial )
{
	printf("\n\n          ModelName = %s\n", serial->ModelName);
	printf("          NextNumber = %d\n", serial->NextNumber);
	printf("\n\n");
	return;
} /* SerializeData_print */

/**                                                                           */
/*	Load data from the serialization file into the serialization data         */
/*	structure                                                                 */
/*	@param none                                                               */
/*	@return a pointer to the serialization data structure                     */
/*                                                                            */
struct SerializeData* serialize_load( char* fileName )
{
	struct SerializeData* serial = NULL;

	FILE* fp = fopen(fileName, "r");
	if (fp)
	{
		char buffer[SER_FILE_LEN];
		size_t len = fread(buffer, 1, SER_FILE_LEN-1, fp);
		buffer[len++] = '\0'; /* don't forget the end of string character */

		JsonNode* json = json_decode(buffer);
		if (json)
		{
			serial = calloc(1, sizeof(struct SerializeData));
			if ( NULL == serial )
			{
				log_error("%s::%s(%d) : Out of memory! ", LOG_INF);
				fclose(fp);
				return NULL;
			}

			serial->ModelName = json_get_member_string(json, "ModelName");
			serial->NextNumber = json_get_member_number(json, "NextNumber", 0);

			json_delete(json);
			log_verbose("%s::%s(%d) : Serialize parameters follow:", LOG_INF);
			SerializeData_print( serial );
		}
		else
		{
			log_error("%s::%s(%d) : Contents of %s are not valid JSON",	
				LOG_INF, fileName);
		}
		fclose(fp);
	}
	else
	{
		int err = errno;
		log_error("%s::%s(%d) : Unable to open serialization file %s: %s", 
			LOG_INF, fileName, strerror(err));
	}
	return serial;
} /* serialize_load */

/**                                                                           */
/*	Save data from the serialization data structure into the                  */
/*	serialization file                                                        */
/*	@param a reference to a serialization data structure                      */
/*	@param a string with the filename and path to the common                  */
/*	       serialization file                                                 */
/*	@return 1 on success                                                      */
/*          0 on failure                                                      */
/*                                                                            */
int serialize_save( struct SerializeData* serial, char* fileName )
{
	JsonNode* json = json_mkobject();

	if(serial->ModelName) {
		json_append_member(json, "ModelName", json_mkstring(serial->ModelName));
	} else {
		log_error("%s::%s(%d) : Missing required ModelName", LOG_INF);
		json_delete(json);
		return 0;
	}

	if(serial->NextNumber) {
		json_append_member(json, "NextNumber", 
			json_mknumber(serial->NextNumber));

	} else	{
		log_error("%s::%s(%d) : Missing required NextNumber", LOG_INF);
		json_delete(json);
		return 0;
	}

	FILE* fp = fopen(fileName,"w");
	if(fp) {
		char* serialString = json_stringify(json,"\t");
		size_t w = fwrite(serialString, 1, strlen(serialString), fp);
		if ( w != strlen(serialString) ) {
			log_error("%s::%s(%d) : Error writing to file %s", 
				LOG_INF, fileName);
			free(serialString);
			fclose(fp);
			return 0;
		}
		free(serialString);
		fclose(fp);
	} else {
		int err = errno;
		log_error("%s::%s(%d) : Unable to write serial file %s: %s", LOG_INF, fileName, strerror(err));
		return 0;
	}
	
	json_delete(json);
	return 1;
} /* serialize_save */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/