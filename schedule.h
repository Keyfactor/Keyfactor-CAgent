/************************************************************************************************
 * Usage of this file and the SDK is subject to the SOFTWARE DEVELOPMENT KIT LICENSE 
 * included here as README-LICENSE.txt.  Additionally, this C Agent Reference Implementation 
 * uses the OpenSSL encryption libraries, which are not included as a part of this distribution.  
 * For hardware key storage or TPM support, libraries such as WolfSSL may also be used in place 
 * of OpenSSL.
 **********************************************************************************************/
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

struct SessionJob* get_job_by_id(struct ScheduledJob** pList, const char* jobId);

void clear_job_schedules(struct ScheduledJob** pList);

void schedule_job(struct ScheduledJob** pList, struct SessionJob* job, time_t prev);

time_t next_execution(char* sch, time_t prev);

#endif /* SCHEDULE_H_ */
