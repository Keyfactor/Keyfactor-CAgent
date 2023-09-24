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

#ifndef CSS_SESSION_H
#define CSS_SESSION_H

#include <time.h>
#include "constants.h"
#include "config.h"
#include "schedule.h"

struct SessionInfo
{
	char Token[GUID_SIZE];
	char AgentId[GUID_SIZE];
	time_t NextExecution;
	int UnreachableCount;
	int Interval;
};

int register_session(struct SessionInfo* session, 
	struct ScheduledJob** pJobList, uint64_t agentVersion);

#if defined(__INFINITE_AGENT__)
int heartbeat_session(struct SessionInfo* session, 
	struct ScheduledJob** pJobList, uint64_t agentVersion);
#endif

#endif /* CSS_SESSION_H */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
