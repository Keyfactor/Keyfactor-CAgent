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

#ifndef SCHEDULE_H_
#define SCHEDULE_H_

#include <time.h>
#include "dto.h"

struct ScheduledJob
{
	struct SessionJob* Job;
	time_t NextExecution;

	struct ScheduledJob* NextJob;
};

struct SessionJob* get_runnable_job(struct ScheduledJob** pList, time_t now);

struct SessionJob* get_job_by_id(struct ScheduledJob** pList, 
	const char* jobId);

void clear_job_schedules(struct ScheduledJob** pList);

void schedule_job(struct ScheduledJob** pList, struct SessionJob* job, 
	time_t prev);

time_t next_execution(char* sch, time_t prev);

#endif /* SCHEDULE_H_ */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/