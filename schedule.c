/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
#include "schedule.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Local offset from UTC. Negative if local time is "behind" UTC
 */
static time_t get_utc_offset()
{
	time_t start = time(NULL);
	struct tm tmp;
	gmtime_r(&start, &tmp);
	tmp.tm_isdst = 0;
	time_t rt = mktime(&tmp);

	return start - rt;
}

static time_t next_interval(char* intSch, time_t prev)
{
	int mins = atoi(intSch);
	if(mins > 0)
	{
		return (mins * 60) + prev;
	}
	else
	{
		log_error("schedule-next_interval-Invalid interval: %s", intSch);
		return -1;
	}
}

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
		prevStruct.tm_mday-=2; // Should guarantee this is before prev (up to 37 hrs of skew from setting hour, etc. and TZ)
		prevStruct.tm_isdst = 0;

		time_t rtTime = mktime(&prevStruct);
		rtTime += get_utc_offset();

		while(rtTime <= prev)
		{
			rtTime += 60 * 60 * 24; // Step forward 1 day
		}

		return rtTime;
	}
	else
	{
		log_error("schedule-next_daily-Invalid daily: %s", dailySch);
		return -1;
	}
}

static time_t next_weekly(char* weeklySch, time_t prev)
{
	int dows;
	int hrs, mins;
	if((3 == sscanf(weeklySch, "%d_%d:%d", &dows, &hrs, &mins))
			&& hrs >= 0 && hrs <=23 && mins >= 0 && mins <= 59)
	{
		struct tm prevStruct;
		gmtime_r(&prev, &prevStruct);

		if(hrs <= prevStruct.tm_hour || (hrs == prevStruct.tm_hour && mins <= prevStruct.tm_min))
		{
			// This gets us to the first time after prev with the right hrs and mins
			// Either later in the same day, or earlier in the next
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
			int offset = ((dow + 7) - (prevStruct.tm_wday + 1)) % 7; // Add 7 to guarantee positive. Add 1 to account for 0-based prevStruct
			smallest = (smallest > offset) ? offset : smallest;

			dows /= 10;
		}

		prevStruct.tm_mday += smallest; // Number of days (0 to 6) to advance to get to the appropriate day

		time_t rtTime = mktime(&prevStruct);
		rtTime += get_utc_offset();

		return rtTime;
	}
	else
	{
		log_error("schedule-next_weekly-Invalid weekly: %s", weeklySch);
		return -1;
	}
}

static time_t next_monthly(char* dailySch, time_t prev)
{
	int dom, hrs, mins;
	if((3 == sscanf(dailySch, "%d_%d:%d", &dom, &hrs, &mins))
			&& hrs >= 0 && hrs <=23 && mins >= 0 && mins <= 59 && dom >=1 && dom <= 31)
	{
		struct tm prevStruct;
		gmtime_r(&prev, &prevStruct);

		prevStruct.tm_hour = hrs;
		prevStruct.tm_min = mins;
		prevStruct.tm_sec = 0;
		prevStruct.tm_mday = dom;
		prevStruct.tm_mon--; // Make sure we are before prev
		prevStruct.tm_isdst = 0;

		time_t rtTime;
		do
		{
			rtTime = mktime(&prevStruct);
			rtTime += get_utc_offset();
			prevStruct.tm_mon++; // For the next time around the loop, if needed
		}
		while(rtTime <= prev);

		return rtTime;
	}
	else if((2 == sscanf(dailySch, "L_%d:%d", &hrs, &mins))
			&& hrs >= 0 && hrs <=23 && mins >= 0 && mins <= 59)
	{
		struct tm prevStruct;
		gmtime_r(&prev, &prevStruct);

		prevStruct.tm_hour = hrs;
		prevStruct.tm_min = mins;
		prevStruct.tm_sec = 0;
		prevStruct.tm_mday = 0;
		prevStruct.tm_mon--; // Make sure we are before prev
		prevStruct.tm_isdst = 0;

		int curMon = prevStruct.tm_mon;
		time_t rtTime;
		do
		{
			rtTime = mktime(&prevStruct);
			rtTime += get_utc_offset();
			prevStruct.tm_mon = ++curMon; // For the next time around the loop, if needed
			prevStruct.tm_mday = 0;
		}
		while(rtTime <= prev);

		return rtTime;
	}
	else
	{
		log_error("schedule-next_monthly-Invalid monthly: %s", dailySch);
		return -1;
	}
}

static time_t next_one_time(char* oneTimeSch)
{
	int year, mon, day, hrs, mins;
	if((5 == sscanf(oneTimeSch, "%d-%d-%dT%d:%d", &year, &mon, &day, &hrs, &mins))
			&& hrs >= 0 && hrs <=23 && mins >= 0 && mins <= 59 && mon >=1 && mon <= 12 && day >= 1 && day <=31)
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
		log_error("schedule-next_one_time-Invalid one-time: %s", oneTimeSch);
		return -1;
	}
}

time_t next_execution(char* sch, time_t prev)
{
	time_t next = -1;

	if(!sch || strlen(sch) < 3)
	{
		log_verbose("schedule-next_execution-Schedule is not provided, indicating job should be run immediately");
		return next = prev;
	}

	switch(sch[0])
	{
	case 'D':
		log_verbose("schedule-next_execution-Daily schedule: %s", sch);
		next = next_daily(&sch[2], prev);
		break;
	case 'M':
		log_verbose("schedule-next_execution-Monthly schedule: %s", sch);
		next = next_monthly(&sch[2], prev);
		break;
	case 'O':
		log_verbose("schedule-next_execution-One-time schedule: %s", sch);
		next = next_one_time(&sch[2]);
		break;
	case 'I':
		log_verbose("schedule-next_execution-Interval schedule: %s", sch);
		next = next_interval(&sch[2], prev);
		break;
	case 'W':
		log_verbose("schedule-next_execution-Weekly schedule: %s", sch);
		next = next_weekly(&sch[2], prev);
		break;
	default:
		log_error("schedule-next_execution-Unknown schedule: %s", sch);
		break;
	}

	return next;
}

struct SessionJob* get_runnable_job(struct ScheduledJob** pList, time_t now)
{
	struct ScheduledJob* current = *pList;

	while(current)
	{
		if(current->NextExecution <= now)
		{
			return current->Job;
		}

		current = current->NextJob;
	}

	log_verbose("schedule-get_runnable_job-No jobs to run");
	return NULL;
}

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

	log_verbose("schedule-get_job_by_id-Job %s not found", jobId);
	return NULL;
}

void clear_job_schedules(struct ScheduledJob** pList)
{
	struct ScheduledJob* current = *pList;

	while(current)
	{
		struct ScheduledJob* temp = current->NextJob;

		SessionJob_free(current->Job);
		free(current);

		current = temp;
	}

	*pList = NULL;
}

void schedule_job(struct ScheduledJob** pList, struct SessionJob* job, time_t prev)
{
	struct ScheduledJob* newSchJob = calloc(1, sizeof(struct ScheduledJob));
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

		while(current)
		{
			if(strcasecmp(current->Job->JobId, job->JobId) == 0)
			{
				log_verbose("schedule-schedule_job-Rescheduling job %s", job->JobId);

				if(current->NextExecution > 0 && (!job->Schedule || job->Schedule[0] == 'O'))
				{
					log_verbose("schedule-schedule_job-Job %s is a one-time job, and will not be rescheduled", job->JobId);

					if(prev)
					{
						prev->NextJob = current->NextJob;
					}
					else // Removing first element
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
				free(newSchJob); // Don't need the new struct, as there is already one for this job

				return;
			}

			prev = current;
			current = current->NextJob;
		}

		prev->NextJob = newSchJob;
	}
}

