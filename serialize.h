/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#ifndef _SERIALIZE_H_
#define _SERIALIZE_H_
#include <stdbool.h>

struct SerializeData
{
	char* ModelName;
	int NextNumber;
};

struct SerializeData* serialize_load( char* fileName );
int serialize_save( struct SerializeData* serial, char* fileName );
void SerializeData_free( struct SerializeData* serial );
#endif