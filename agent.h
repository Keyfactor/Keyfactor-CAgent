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

#define _POSIX_C_SOURCE 200809L   // POSIX.1-2008

#include "session.h"
#include "schedule.h"
#include "config.h"

int run_job(SessionJob_t* job);
int init_platform( int argc, char* argv[] );
bool release_platform( void );
#ifdef __MAKE_LIBRARY__
int KF_main( int argc, char* argv[]);
#endif

/******************************************************************************/
/************************* SYSTEM GLOBAL VARIABLES ****************************/
/******************************************************************************/
extern SessionInfo_t SessionData;
extern ScheduledJob_t* JobList;
extern ConfigData_t* ConfigData;
extern ScheduledJob_t* currentJob; /* Defined in schedule.c */
extern bool success;   /* Used to define the program/library exit code */

#if defined(__OPEN_SSL__) && defined(__TPM__)
	extern char engine_id[21];
#endif
	
#if defined(__TPM__)
	#include <tpm2-tss-engine.h>
	extern ENGINE* e;
#endif

/* Versioning Information                                                     */
/* 3.0.0.3 = Release candidate for agent v3                                   */
#define AGENT_MAJOR 3ULL
#define AGENT_MINOR 0ULL
#define AGENT_MICRO 0ULL

#ifdef __QATESTING__
  #define AGENT_BUILD 999ULL // Special build number for QA testing
#else
  #define AGENT_BUILD 3ULL
#endif

#define AGENT_VERSION \
((AGENT_MAJOR << 48) | \
(AGENT_MINOR << 32) | \
(AGENT_MICRO << 16) | \
(AGENT_BUILD))

#endif /* AGENT_H_ */
