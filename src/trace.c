/*
 * T-trace
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
