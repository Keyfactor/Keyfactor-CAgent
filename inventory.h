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

#ifndef __INVENTORY_H__
#define __INVENTORY_H__

#include "dto.h"
#include "config.h"

int cms_job_inventory(struct SessionJob* jobInfo, char* sessionToken);

#endif /* __INVENTORY_H__ */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/