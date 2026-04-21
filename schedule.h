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

#define _POSIX_C_SOURCE 200809L // POSIX.1-2008

#include "dto.h"
#include <time.h>

typedef struct ScheduledJob_s {
    SessionJob_t *Job;
    time_t NextExecution;
    struct ScheduledJob_s *NextJob;
} ScheduledJob_t;

SessionJob_t *get_runnable_job(ScheduledJob_t **pList, time_t now);

SessionJob_t *get_job_by_id(ScheduledJob_t **pList, const char *jobId);

void clear_job_schedules(ScheduledJob_t **pList);

void schedule_job(ScheduledJob_t **pList, SessionJob_t *job);

#endif /* SCHEDULE_H_ */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
