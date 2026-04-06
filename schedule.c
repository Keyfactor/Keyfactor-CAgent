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

#include "schedule.h"
#include "logging.h"
#include "agent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/
ScheduledJob_t *currentJob;     /* Defined in schedule.c */

/******************************************************************************/
/************************* LOCAL GLOBAL VARIABLES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/*                                                                            */
/* Retrieve the Local offset from UTC. Negative if local time is "behind" UTC */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success : The difference between time(NULL) & UTC time(NULL)     */
/* failure : n/a                                                              */
/*                                                                            */
static time_t get_utc_offset(void){
    time_t start = time(NULL);
    struct tm       tmp;
    gmtime_r(&start, &tmp);
    tmp.tm_isdst = 0;
    time_t rt = mktime(&tmp);

    return (start - rt);
} /* get_utc_offset */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/*                                                                            */
/* Go through the job list and see if it is time to run a job.                */
/* If so, return it.  If not, return null.                                    */
/*                                                                            */
/* @param  - [Input] pList: Linked list of ScheduledJobs                      */
/* @param  - [Input] now: current time                                        */
/* @return - NULL if no jobs are runnable                                     */
/* - The SessionJob* to the job to execute                                    */
/*                                                                            */
SessionJob_t   *get_runnable_job(ScheduledJob_t * *pList, time_t now)
{
    ScheduledJob_t *current = *pList;

    while (current) {
        log_trace("%s::%s(%d) : Checking job %s NextExecution = %ld Now = %ld",
                  LOG_INF, current->Job->JobId, current->NextExecution, now);
        if (current->NextExecution <= now) {
            return current->Job;
        }

        current = current->NextJob;
    }

    log_verbose("%s::%s(%d) : No jobs to run", LOG_INF);
    return NULL;
}

/*                                                                            */
/* Loop through the job list & retrieve the job structure based on jobId      */
/*                                                                            */
/* @param  - [Input] jobId = the jobId who's details to retrieve              */
/* @param  - [Input] pList = the list of scheduled jobs                       */
/* @return - success : a pointer to the found job                             */
/* failure : NULL                                                             */
/*                                                                            */
SessionJob_t   *get_job_by_id(ScheduledJob_t * *pList, const char *jobId)
{
    ScheduledJob_t *current = *pList;

    while (current) {
        if (strcasecmp(current->Job->JobId, jobId) == 0) {
            return current->Job;
        }

        current = current->NextJob;
    }

    log_verbose("%s::%s(%d) : -Job %s not found", LOG_INF, jobId);
    return NULL;
} /* get_job_by_id */

/*                                                                            */
/* Clear all scheduled jobs (also free data structures)                       */
/*                                                                            */
/* @param  - [Input/Ouput] pList = A list of scheduled jobs                   */
/* @return - none                                                             */
/*                                                                            */
void clear_job_schedules(ScheduledJob_t * *pList)
{
    ScheduledJob_t *current = *pList;

    while (current) {
        ScheduledJob_t *temp = current->NextJob;

        if (current->Job) {
            log_info("%s::%s(%d) : Freeing job # %s", LOG_INF,
                     current->Job->JobId);
            SessionJob_free(current->Job);
            current->Job = NULL;
            current->NextJob = NULL;
        }
        free(current);
        current = temp;
    }

} /* clear_job_schedules */

/*                                                                            */
/* Add a job to a scheduled job list                                          */
/*                                                                            */
/* @param  - [Output] pList = a list of scheduled jobs to add a new job into  */
/* @param  - [Input] job = a filled job session to add to the scheduled list  */
/* @return - none                                                             */
/*                                                                            */
void schedule_job(ScheduledJob_t * *pList,
                  SessionJob_t * job
                 )
{
  ScheduledJob_t *newSchJob = calloc(1, sizeof(ScheduledJob_t));
  if (!newSchJob) {
      log_error("%s::%s(%d) : Out of memory", LOG_INF);
      return;
  }
  newSchJob->Job = job;

  if (!(*pList)) {
    *pList = newSchJob;
  } else {
    ScheduledJob_t *prev = NULL;
    ScheduledJob_t *current = *pList;

    /* Go through the list of jobs & update that job if it is already */
    /* In the list of jobs, if not, add the job to the end of the list */
    while (current) {
      if (strcasecmp(current->Job->JobId, job->JobId) == 0) {
        log_verbose("%s::%s(%d) : Rescheduling job %s",
                    LOG_INF, job->JobId);

        if (
          current->NextExecution > 0 && \
          (!job->Schedule || job->Schedule[0] == 'O')
          ) {
            log_verbose("%s::%s(%d) : Job %s is a one-time job, ", LOG_INF, job->JobId);

            if (prev) {
                prev->NextJob = current->NextJob;
            } else {    /* Removing first element */
                *pList = current->NextJob;
            }

            SessionJob_free(current->Job);
            free(current);
        } else {
            current->NextExecution = newSchJob->NextExecution;
        }
        /*
         * Don't need the new struct, there is already one for this
         * job
         */
        free(newSchJob);
        newSchJob = NULL;

        return;
      }

      prev = current;
      current = current->NextJob;
    }

    if (prev)
      prev->NextJob = newSchJob;
  }
} /* schedule_job */
/******************************************************************************/
/******************************* END OF FILE **********************************/
