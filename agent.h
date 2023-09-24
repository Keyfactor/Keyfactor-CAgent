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
#ifdef __MAKE_LIBRARY__
int KF_main( int argc, char* argv[]);
#endif

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
/*             * Added sanity checks on the initial configuration file        */
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
/* 2.8.4.0 = Fixed re-registration issue where AgentId was not updated        */
/* 2.8.5.0 = Changed logging functionality                                    */
/* 2.8.6.0 = Minor bug fixes                                                  */
/* 2.8.7.0 = Fixed Agent cert renewal issue for A0100007 and A0100008 codes   */
/* 2.8.8.0 = Agent now re-registers as new agent if its own certificate       */
/*           has expired                                                      */
/* 2.9.0.0 = Added custom client parameters stub to sessions.  These params   */
/*           get added to every hit of /Session/Register                      */
/* 2.9.1.0 = Fixed issue where CSRs max length was too small for RSA/4096     */
/* 2.9.2.0 = Fixed but in getting date time for agent's name                  */
/* 2.10.0.0 = Fixed issue with openSSL management remove job                  */
/* 2.11.0.0 = Allow agent to be made into a library                           */
/* 2.12.0.0 = Update bootstrap certificate use case                           */
/* 2.14.0.0 = Add command line switch to send X-ARR-ClientCert header to KF   */
/* 2.14.1.0 = Updated logging associated with v2.14.0.0                       */
/* 2.14.2.0 = Updated parameter processing & usage printing                   */
/* 2.14.2.1 = Set up long options & cleaned usage output                      */
/* 2.14.3.0 = Upgraded for EJBCA DN State Key & openssl v3.0 compatibility    */
#define AGENT_VERSION 0x0002000E00030000

#endif /* AGENT_H_ */
