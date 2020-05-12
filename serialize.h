/*
* Copyright 2018, Certified Security Solutions
* All Rights Reserved.
* This is UNPUBLISHED PROPRIETARY SOURCE CODE of Certified Security Solutions;
* the contents of this file may not be disclosed to third parties, copied
* or duplicated in any form, in whole or in part, without the prior
* written permission of Certified Security Solutions.
*/

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