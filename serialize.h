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

#endif /* _SERIALIZE_H_ */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/