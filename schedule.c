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

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/
struct ScheduledJob* currentJob; /* Defined in schedule.c */

/******************************************************************************/
/************************* LOCAL GLOBAL VARIABLES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* Retrieve the Local offset from UTC. Negative if local time is "behind" UTC */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success : The difference between time(NULL) & UTC time(NULL)     */
/*           failure : n/a                                                    */
/*                                                                            */
static time_t get_utc_offset(void)
{
	time_t start = time(NULL);
	struct tm tmp;
	gmtime_r(&start, &tmp);
	tmp.tm_isdst = 0;
	time_t rt = mktime(&tmp);

	return (start - rt);
} /* get_utc_offset */

/**                                                                           */
/* Add the number of minutes to a time.                                       */
/*                                                                            */
/* @param  - [Input] prev = The time to be added to                           */
/* @param  - [Input] intSch = a string representing the # of minutes to add   */
/* @return - success : the time intSch from prev                              */
/*           failure : prev                                                   */
/*                                                                            */
static time_t next_interval(char* intSch, time_t prev)
{
	int mins = atoi(intSch);
	if(mins > 0)
	{
		return (mins * 60) + prev;
	}
	else
	{
		log_error("%s::%s(%d) : Invalid interval: %s", LOG_INF, intSch);
		return prev;
	}
} /* next_interval */

/**                                                                           */
/* Add the number of days to a time                                           */
/*                                                                            */
/* @param  - [Input] prev = The time to be added to                           */
/* @param  - [Input] dailySch = a string representing the # of days to add    */
/* @return - success : the time dailySch from prev                            */
/*           failure : prev                                                   */
/*                                                                            */
static time_t next_daily(char* dailySch, time_t prev)
{
	int hrs, mins;
	if((2 == sscanf(dailySch, "%d:%d", &hrs, &mins))
			&& hrs >= 0 && hrs <=23 && mins >= 0 && mins <= 59)
	{
		struct tm prevStruct;
		gmtime_r(&prev, &prevStruct);

		prevStruct.tm_hour = hrs;
		prevStruct.tm_min = mins;
		prevStruct.tm_sec = 0;
		/* Should guarantee this is before prev (up to 37 hrs of skew from */
		/* setting hour, etc. and TZ)*/
		prevStruct.tm_mday-=2; 
		prevStruct.tm_isdst = 0;

		time_t rtTime = mktime(&prevStruct);
		rtTime += get_utc_offset();

		while(rtTime <= prev)
		{
			rtTime += 60 * 60 * 24; /* Step forward 1 day */
		}

		return rtTime;
	}
	else
	{
		log_error("%s::%s(%d) : Invalid daily: %s", LOG_INF, dailySch);
		return prev;
	}
} /* next_daily */

/**                                                                           */
/* Add the number of weeks to a time                                          */
/*                                                                            */
/* @param  - [Input] prev = The time to be added to                           */
/* @param  - [Input] weeklySch = a string representing the # of weeks to add  */
/* @return - success : the time weeklySch from prev                           */
/*           failure : prev                                                   */
/*                                                                            */
static time_t next_weekly(char* weeklySch, time_t prev)
{
	int dows;
	int hrs, mins;
	if((3 == sscanf(weeklySch, "%d_%d:%d", &dows, &hrs, &mins))
			&& hrs >= 0 && hrs <=23 && mins >= 0 && mins <= 59)
	{
		struct tm prevStruct;
		gmtime_r(&prev, &prevStruct);

		if(
			hrs <= prevStruct.tm_hour || \
			(hrs == prevStruct.tm_hour && mins <= prevStruct.tm_min) )
		{
			/* This gets us to the first time after prev with the right hrs */ 
			/* and mins Either later in the same day, or earlier in the next*/
			prevStruct.tm_mday++;
			prevStruct.tm_wday++;
		}
		prevStruct.tm_hour = hrs;
		prevStruct.tm_min = mins;
		prevStruct.tm_sec = 0;
		prevStruct.tm_isdst = 0;

		int smallest = 10;
		while(dows > 0)
		{
			int dow = dows % 10;
			/* Add 7 to guarantee positive. */
			/* Add 1 to account for 0-based prevStruct */
			int offset = ((dow + 7) - (prevStruct.tm_wday + 1)) % 7; 
			smallest = (smallest > offset) ? offset : smallest;

			dows /= 10;
		}

		/*/ Number of days (0 to 6) to advance to get to the appropriate day */
		prevStruct.tm_mday += smallest; 

		time_t rtTime = mktime(&prevStruct);
		rtTime += get_utc_offset();

		return rtTime;
	}
	else
	{
		log_error("%s::%s(%d) : Invalid weekly: %s", LOG_INF, weeklySch);
		return prev;
	}
} /* next_weekly */

/**                                                                           */
/* Add the number of months to a time                                         */
/*                                                                            */
/* @param  - [Input] prev = The time to be added to                           */
/* @param  - [Input] monthSch = a string representing the # of months to add  */
/* @return - success : the time monthSch from prev                            */
/*           failure : prev                                                   */
/*                                                                            */
static time_t next_monthly(char* monthSch, time_t prev)
{
	int dom, hrs, mins;
	if(
			(3 == sscanf(monthSch, "%d_%d:%d", &dom, &hrs, &mins)) &&
			hrs >= 0 && hrs <=23 && 
			mins >= 0 && mins <= 59 && 
			dom >=1 && dom <= 31 )
	{
		struct tm prevStruct;
		gmtime_r(&prev, &prevStruct);

		prevStruct.tm_hour = hrs;
		prevStruct.tm_min = mins;
		prevStruct.tm_sec = 0;
		prevStruct.tm_mday = dom;
		prevStruct.tm_mon--; /* Make sure we are before prev */
		prevStruct.tm_isdst = 0;

		time_t rtTime;
		do
		{
			rtTime = mktime(&prevStruct);
			rtTime += get_utc_offset();
			prevStruct.tm_mon++; /* For the next time around the loop */
		}
		while(rtTime <= prev);

		return rtTime;
	}
	else if((2 == sscanf(monthSch, "L_%d:%d", &hrs, &mins))
			&& hrs >= 0 && hrs <=23 && mins >= 0 && mins <= 59)
	{
		struct tm prevStruct;
		gmtime_r(&prev, &prevStruct);

		prevStruct.tm_hour = hrs;
		prevStruct.tm_min = mins;
		prevStruct.tm_sec = 0;
		prevStruct.tm_mday = 0;
		prevStruct.tm_mon--; /* Make sure we are before prev */
		prevStruct.tm_isdst = 0;

		int curMon = prevStruct.tm_mon;
		time_t rtTime;
		do
		{
			rtTime = mktime(&prevStruct);
			rtTime += get_utc_offset();
			/* For the next time around the loop, if needed */
			prevStruct.tm_mon = ++curMon; 
			prevStruct.tm_mday = 0;
		}
		while(rtTime <= prev);

		return rtTime;
	}
	else
	{
		log_error("%s::%s(%d) : Invalid monthly: %s", LOG_INF, monthSch);
		return prev;
	}
} /* next_monthly */

/**                                                                           */
/* Decode a scheduled datetime into a time_t structure.                       */
/* NOTE: This does not verify that the date is a future date.                 */
/*                                                                            */
/* @param  - [Input] oneTimeSch is a string designating a date time in the    */
/*                   format of :  YYYY-MM-DDTHH:mm where                      */
/*                   YYYY = Year                                              */
/*                   MM = Month [01..12]                                      */
/*                   DD = Day of Month [01..31]                               */
/*                   HH = Hours [00..23]                                      */
/*                   mm = Minutes [00..59]                                    */
/* @return  - success : the formatted string as a time_t structure            */
/*            failure : time(NULL)                                            */
/*                                                                            */
static time_t next_one_time(char* oneTimeSch)
{
	int year, mon, day, hrs, mins;
	if(
		(5 == sscanf(oneTimeSch, "%d-%d-%dT%d:%d", &year, 
					&mon, &day, &hrs, &mins)) &&
		hrs >= 0 && hrs <=23 && 
		mins >= 0 && mins <= 59 && 
		mon >=1 && mon <= 12 && 
		day >= 1 && day <=31)
	{
		struct tm tStruct;

		tStruct.tm_hour = hrs;
		tStruct.tm_min = mins;
		tStruct.tm_sec = 0;
		tStruct.tm_mday = day;
		tStruct.tm_mon = mon - 1; // Months go from 0 to 11
		tStruct.tm_year = year - 1900; // Years since 1900
		tStruct.tm_isdst = 0;

		time_t rtTime = mktime(&tStruct);
		rtTime += get_utc_offset();

		return rtTime;
	}
	else
	{
		log_error("%s::%s(%d) : Invalid one-time: %s", LOG_INF, oneTimeSch);
		return time(NULL);
	}
} /* next_one_time */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* Get the time of the next execution of a job based on the previous job      */
/* execution and the schedule string.                                         */
/*                                                                            */
/* @param  - [Input] sch = The schedule string in the form of                 */
/*                   T_X where:                                               */
/*                   T = job type.  Which is one of:                          */
/*                       D = Daily                                            */
/*                       M = Monthly                                          */
/*                       O = One-time execution                               */
/*                       I = Interval (aka Minutes)                           */
/*                       W = Weekly                                           */
/*                   X = Integer or substring indicating the time delay       */
/*            (e.g., I_5 = 5 minutes, D_2 = every other day,                  */
/*                   M_1_3:0 = 1st day hour 3 minute 0 of each month          */
/*                   O_2020-10-31T13:30 = One time job @ 31-Oct-2020 & 1:30pm)*/
/* @param  - [Input] prev the last time the job ran                           */
/*           (set to time(NULL) if never)                                     */
/* @return - success : time_t = the next time the job runs                    */
/*           failure : -1                                                     */
/*                                                                            */
time_t next_execution(char* sch, time_t prev)
{
	time_t next = -1;

	if(!sch || strlen(sch) < 3)
	{
		log_verbose("%s::%s(%d) : Schedule is not provided, indicating "
			"job should be run immediately", LOG_INF);
		return next = prev;
	}

	switch(sch[0])
	{
		case 'D':
			log_verbose("%s::%s(%d) : Daily schedule: %s", LOG_INF, sch);
			next = next_daily(&sch[2], prev);
			break;
		case 'M':
			log_verbose("%s::%s(%d) : Monthly schedule: %s", LOG_INF, sch);
			next = next_monthly(&sch[2], prev);
			break;
		case 'O':
			log_verbose("%s::%s(%d) : One-time schedule: %s", LOG_INF, sch);
			next = next_one_time(&sch[2]);
			break;
		case 'I':
			log_verbose("%s::%s(%d) : Interval schedule: %s", LOG_INF, sch);
			next = next_interval(&sch[2], prev);
			break;
		case 'W':
			log_verbose("%s::%s(%d) : Weekly schedule: %s", LOG_INF, sch);
			next = next_weekly(&sch[2], prev);
			break;
		default:
			log_error("%s::%s(%d) : Unknown schedule: %s", LOG_INF, sch);
			break;
	}

	return next;
} /* next_execution */

/**                                                                           */
/* Go through the job list and see if it is time to run a job.                */
/* If so, return it.  If not, return null.                                    */
/*                                                                            */
/* @param  - [Input] pList: Linked list of ScheduledJobs                      */
/* @param  - [Input] now: current time                                        */
/* @return - NULL if no jobs are runnable                                     */
/*         - The SessionJob* to the job to execute                            */
/*                                                                            */
struct SessionJob* get_runnable_job(struct ScheduledJob** pList, time_t now)
{
	struct ScheduledJob* current = *pList;

	while(current)
	{
		log_trace("%s::%s(%d) : Checking job %s NextExecution = %ld Now = %ld", 
			LOG_INF, current->Job->JobId,current->NextExecution,now);
		if(current->NextExecution <= now)
		{
			return current->Job;
		}

		current = current->NextJob;
	}

	log_verbose("%s::%s(%d) : No jobs to run", LOG_INF);
	return NULL;
}

/**                                                                           */
/* Loop through the job list & retrieve the job structure based on jobId      */
/*                                                                            */
/* @param  - [Input] jobId = the jobId who's details to retrieve              */
/* @param  - [Input] pList = the list of scheduled jobs                       */
/* @return - success : a pointer to the found job                             */
/*           failure : NULL                                                   */
/*                                                                            */
struct SessionJob* get_job_by_id(struct ScheduledJob** pList, const char* jobId)
{
	struct ScheduledJob* current = *pList;

	while(current)
	{
		if(strcasecmp(current->Job->JobId, jobId) == 0)
		{
			return current->Job;
		}

		current = current->NextJob;
	}

	log_verbose("%s::%s(%d) : -Job %s not found", LOG_INF, jobId);
	return NULL;
} /* get_job_by_id */

/**                                                                           */
/* Clear all scheduled jobs (also free data structures)                       */
/*                                                                            */
/* @param  - [Input/Ouput] pList = A list of scheduled jobs                   */
/* @return - none                                                             */
/*                                                                            */
void clear_job_schedules(struct ScheduledJob** pList)
{
	struct ScheduledJob* current = *pList;

	while(current)
	{
		struct ScheduledJob* temp = current->NextJob;

		if ( current->Job ) 
		{
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

/**                                                                           */
/* Add a job to a scheduled job list                                          */
/*                                                                            */
/* @param  - [Output] pList = a list of scheduled jobs to add a new job into  */
/* @param  - [Input] job = a filled job session to add to the scheduled list  */
/* @param  - [Input] prev = the timestamp of the previous job run             */
/* @return - none                                                             */
/*                                                                            */
void schedule_job(struct ScheduledJob** pList, struct SessionJob* job, 
	time_t prev)
{
	struct ScheduledJob* newSchJob = calloc(1, sizeof(struct ScheduledJob));
	if ( !newSchJob )
	{
		log_error("%s::%s(%d) : Out of memory", LOG_INF);
		return;
	}
	newSchJob->Job = job;

	newSchJob->NextExecution = next_execution(job->Schedule, prev);

	if(!(*pList))
	{
		*pList = newSchJob;
	}
	else
	{
		struct ScheduledJob* prev = NULL;
		struct ScheduledJob* current = *pList;

		/* Go through the list of jobs & update that job if it is already */
		/* In the list of jobs, if not, add the job to the end of the list */
		while(current)
		{
			if(strcasecmp(current->Job->JobId, job->JobId) == 0)
			{
				log_verbose("%s::%s(%d) : Rescheduling job %s", 
					LOG_INF, job->JobId);

				if(
					current->NextExecution > 0 && \
					(!job->Schedule || job->Schedule[0] == 'O') )
				{
					log_verbose("%s::%s(%d) : Job %s is a one-time job, "
						"and will not be rescheduled", LOG_INF, job->JobId);

					if(prev)
					{
						prev->NextJob = current->NextJob;
					}
					else /* Removing first element */
					{
						*pList = current->NextJob;
					}

					SessionJob_free(current->Job);
					free(current);
				}
				else
				{
					current->NextExecution = newSchJob->NextExecution;
				}
				/*Don't need the new struct, there is already one for this job*/
				free(newSchJob); 
				newSchJob = NULL;

				return;
			}

			prev = current;
			current = current->NextJob;
		}

		prev->NextJob = newSchJob;
	}
} /* schedule_job */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/