// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <util/batchpriority.h>

#include <util/log.h>
#include <util/syserror.h>

#include <string>

#ifndef WIN32
#include <pthread.h>
#include <sched.h>
#endif

void ScheduleBatchPriority()
{
#ifdef SCHED_BATCH
    const static sched_param param{};
    const int rc = pthread_setschedparam(pthread_self(), SCHED_BATCH, &param);
    if (rc != 0) {
        LogWarning("Failed to pthread_setschedparam: %s", SysErrorString(rc));
    }
#endif
}