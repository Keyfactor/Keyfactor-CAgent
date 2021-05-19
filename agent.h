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

#ifndef AGENT_H_
#define AGENT_H_

#include "session.h"
#include "schedule.h"
#include "config.h"

int run_job(struct SessionJob* job);
int init_platform( int argc, char* argv[] );
bool release_platform( void );

/******************************************************************************/
/************************* SYSTEM GLOBAL VARIABLES ****************************/
/******************************************************************************/
extern struct SessionInfo SessionData;
extern struct ScheduledJob* JobList;
extern struct ConfigData* ConfigData;
extern struct ScheduledJob* currentJob; /* Defined in schedule.c */

#if defined(__OPEN_SSL__)
	extern char engine_id[21];
#endif
	
#if defined(__TPM__)
	#include <tpm2-tss-engine.h>
	extern ENGINE* e;
#endif

/* Versioning Information                                                     */
/* 2.0.0.0 = Created wrapper class                                            */
/* 2.1.0.0 = Added TPM for raspberry pi into version                          */
/* 2.5.0.0 = Added the following functionality:                               */
/*             * Log to file upon agent shutting down                         */
/*             * Agent runs through all jobs once,                            */
/*               this allows cron to schedule it                              */
/*             * Added warning log level                                      */
/*             * Added a priority queue for agent jobs upon initial retrieval */
/*             * Ignore any chained jobs - inventory jobs will always         */
/*               run immediate                                                */
/*             * Check if a store is a directory before reading/writing       */
/*             * Check if re-enrollment, inventory, or management jobs        */
/*               are targeting the agent certificate & don't run those jobs.  */
/*             * Added agent cert re-enrollment on Error response to reenroll */
/* 2.5.1.0 = Added the following:                                             */
/*             * Fixed a bug in openSSL cleanup causing segfaults             */
/*             * Added a check to the inventory and management jobs to        */
/*               validate cert store exists                                   */
/*             * Added sanity checks on the intital configuration file        */
/*             * Set default logging level to INFO                            */
/* 2.5.2.0 = Fixed bugs in openSSL layer when performing management jobs      */
/* 2.6.0.0 = Modified Agent to work with Keyfactor Platform v8.5.2            */
/*           Includes fixes to wrapper layers for managing keypairs           */
/* 2.6.1.0 = Added -c switch to allow config file to be passed as a parameter */
/* 2.7.0.0 = Added -h switch to use hostname_datetime for agent name          */
/*           Added second registration hit for use with RegistrationHandler   */
/* 2.7.1.0 = Fixed bug with agent cert expiry                                 */
/* 2.7.2.0 = Fixed bug with HResult being returned instead of CodeString      */
/* 2.8.0.0 = Added the following:                                             */
/*              * Updated licensing information                               */
/*              * Added Bootstrap certificate support via config file         */
/* 2.8.1.0 = Fixed logging to file bug                                        */
/* 2.8.2.0 = Fixed some memory leaks                                          */
/* 2.8.3.0 = Fixed more memory leak posibilities                              */
#define AGENT_VERSION 0x0002000800030000

#endif /* AGENT_H_ */
