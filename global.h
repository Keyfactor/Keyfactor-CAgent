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

/* Global header file for things like global defines, variables, etc.         */

#ifndef _GLOBAL_H_
#define _GLOBAL_H_

/* Undefine this for HTTP version 2.0 */
#define __HTTP_1_1__

#undef __DEBUG__
#undef __PLATFORM_FIXED__

#ifdef __TPM__
extern char engine_id[21];
#endif

#define UUID_LEN 37 // 36 char per RFC 4122 + 1 for \0

#endif
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/