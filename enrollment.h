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

#ifndef ENROLLMENT_H_
#define ENROLLMENT_H_

#include "dto.h"
#include "config.h"

#define RSA_DEFAULT_EXP 65537

int cms_job_enroll(struct SessionJob* jobInfo, char* sessionToken, 
	char** chainJob);

#endif /* ENROLLMENT_H_ */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
