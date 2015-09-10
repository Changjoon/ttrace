/*
 * =============================================================================
 *
 * SLP
 * Copyright (c) 2012 Samsung Electronics, Inc.
 * All rights reserved.
 *
 * This software is a confidential and proprietary information
 * of Samsung Electronics, Inc. ("Confidential Information").  You
 * shall not disclose such Confidential Information and shall use
 * it only in accordance with the terms of the license agreement
 * you entered into with Samsung Electronics.
 *
 * @file:  trace.c
 * @brief:  trace public api
 * @author:  @samsung.com
 * @created:  Thursday 27 September 2012 08:05:23  KST
 * @compiler:  gcc
 * @company:  Samsung
 * @version:  0.1
 * @revision:  none
 *
 * =============================================================================
 */
#include "ttrace.h"
#include "stdarg.h"

#define ENABLE_TTRACE
#define MAX_LEN 512

#ifdef ENABLE_TTRACE
/*
 * Tracing API for Native Application
 * - tag: the tracing tag
 * - name: the event name
 * - value: the value tracing
 */
void trace_begin(const char *name, ...)
{
	va_list ap;
	char v_name[MAX_LEN];

	va_start(ap, name);
	vsnprintf(v_name, MAX_LEN, name, ap);

	traceBegin(TTRACE_TAG_APP, v_name);
	va_end(ap);
}

void trace_end()
{
	traceEnd(TTRACE_TAG_APP);
}

void trace_async_begin(int cookie, const char *name, ...)
{
	va_list ap;
	char v_name[MAX_LEN];

	va_start(ap, name);
	vsnprintf(v_name, MAX_LEN, name, ap);

	traceAsyncBegin(TTRACE_TAG_APP, cookie, v_name);
	va_end(ap);
}

void trace_async_end(int cookie, const char *name, ...)
{
	va_list ap;
	char v_name[MAX_LEN];

	va_start(ap, name);
	vsnprintf(v_name, MAX_LEN, name, ap);

	traceAsyncEnd(TTRACE_TAG_APP, cookie, v_name);
	va_end(ap);
}

void trace_update_counter(int value, const char *name, ...)
{
	va_list ap;
	char v_name[MAX_LEN];

	va_start(ap, name);
	vsnprintf(v_name, MAX_LEN, name, ap);

	traceCounter(TTRACE_TAG_APP, value, v_name);
	va_end(ap);
}
#else
void trace_begin(const char *name, ...)
{; }

void trace_end()
{; }

void trace_async_begin(int cookie, const char *name, ...)
{; }

void trace_async_end(int cookie, const char *name, ...)
{; }

void trace_update_counter(int value, const char *name, ...)
{; }
#endif
