
/******************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT 
 * LICENSE included here as README-LICENSE.txt.  Additionally, this C Agent 
 * Reference Implementation uses the OpenSSL encryption libraries, which are 
 * not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also
 * be used in place of OpenSSL.
 ******************************************************************************/
/** @file agent.h */
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
extern struct ScheduledJob* currentJob; // Defined in schedule.c
#if defined(__OPEN_SSL__)
extern char engine_id[21];
#endif
#if defined(__TPM__)
#include <tpm2-tss-engine.h>
extern ENGINE* e;
#endif

/* Versioning Information */
/* 2.0.0.0 = Created wrapper class */
/* 2.1.0.0 = Added TPM for raspberry pi into version */
/* 2.5.0.0 = Added the following functionality: */
/*             * Log to file upon agent shutting down */
/*             * Agent runs through all jobs once, this allows cron to schedule it */
/*             * Added warning log level */
/*             * Added a priority queue for agent jobs upon initial retrieval */
/*             * Ignore any chained jobs - inventory jobs will always run immediate */
/*             * Check if a store is a directory before reading/writing */
/*             * Check if re-enrollment, inventory, or management jobs are targeting */
/*               the agent certificate & don't run those jobs. */
/*             * Added agent cert re-enrollment on Error response to reenroll */
/* 2.5.1.0 = Added the following: */
/*             * Fixed a bug in openSSL cleanup causing segfaults */
/*             * Added a check to the inventory and management jobs to validate cert store exists */
/*             * Added sanity checks on the intital configuration file */
/*             * Added ECC 192 key generation */
/*             * Set default logging level to INFO */
/* 2.5.2.0 = Fixed bugs in openSSL layer when performing management jobs */
/* 2.6.0.0 = Modified Agent to work with Keyfactor Platform v8.5.2 */
/*           Includes fixes to wrapper layers for managing keypairs */
/* 2.6.1.0 = Added -c switch to allow config file to be passed as a parameter */
#define AGENT_VERSION 0x0002000600010000

#endif // AGENT_H_
