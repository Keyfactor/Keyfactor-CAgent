
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
struct SessionInfo SessionData;
struct ScheduledJob* JobList;
struct ConfigData* ConfigData;

/* Versioning Information */
/* 2.0.0.0 = Created wrapper class */
#define AGENT_VERSION 0x0002000000000000

#endif // AGENT_H_
