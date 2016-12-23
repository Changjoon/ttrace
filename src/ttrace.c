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
#include "trace.h"
#include "dlog.h"

#define ENABLE_TTRACE

#ifdef ENABLE_TTRACE
/* In "TTRACE_DEBUG" mode, dlog will print T-trace debug log */
#define TTRACE_DEBUG
#undef TTRACE_DEBUG

#ifdef TTRACE_DEBUG
#define TTRACE_LOG(format, arg...)	dlog_print(3, "TTRACE", format, ##arg)
#else
#define TTRACE_LOG(format, arg...)
#endif

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#define TRACE_FILE "/sys/kernel/debug/tracing/trace_marker"

#define MAX_TRACE_LEN 1024
#define MAX_LEN 512
#define MAX_TAIL_LEN 13
#define MAX_HEAD_LEN 8
#define POS_LABEL_ST (MAX_LEN - MAX_HEAD_LEN)
#define POS_LABEL_ED (MAX_LEN - MAX_TAIL_LEN)

#define FD_INITIAL_VALUE -1
#define TRACE_FILE_NOT_EXIST -2

void __attribute__ ((constructor)) libttrace_init(void);
void __attribute__ ((destructor)) libttrace_fini(void);

int g_trace_handle_fd = FD_INITIAL_VALUE;
int g_enabled_tag_fd = FD_INITIAL_VALUE;

static uint64_t dummy = 0;
uint64_t *cur_enabled_tag = (void *)&dummy;

void libttrace_init()
{
	return;
}

void libttrace_fini()
{
	if (g_trace_handle_fd > FD_INITIAL_VALUE)
		close(g_trace_handle_fd);
	if (g_enabled_tag_fd > FD_INITIAL_VALUE)
		close(g_enabled_tag_fd);
	return;
}


static uint64_t traceInit()
{
	uint64_t *sm_for_enabled_tag;
	TTRACE_LOG("traceInit: %p %p", cur_enabled_tag, ((void *)&dummy));

	if (cur_enabled_tag == ((void *)&dummy)) {
		g_enabled_tag_fd = open(ENABLED_TAG_FILE, O_RDONLY | O_CLOEXEC);
		if (g_enabled_tag_fd < 0) {
			TTRACE_LOG("Fail to open enabled_tag file: %s(%d)", strerror(errno), errno);
			return 0;
		}
		sm_for_enabled_tag = mmap(NULL, sizeof(uint64_t), PROT_READ, MAP_SHARED, g_enabled_tag_fd, 0);
		if (sm_for_enabled_tag == MAP_FAILED) {
			TTRACE_LOG("error: mmap() failed(%s)\n", strerror(errno));
			close(g_enabled_tag_fd);
			return 0;
		}
		cur_enabled_tag = sm_for_enabled_tag;
	}

	/* access trace_marker after ensuring tag file creation */
	if(g_trace_handle_fd == FD_INITIAL_VALUE) {
		g_trace_handle_fd = open(TRACE_FILE, O_WRONLY);
		if (g_trace_handle_fd < 0) {
			TTRACE_LOG("Fail to open trace file: %s(%d)", strerror(errno), errno);
			/*
			 * If ftrace debugfs is not mounted, ttrace does not call traceInit() anymore. 
			 * we should decide how to handle if file permission is not given properly. keep try? or Nerver try agin? 
			*/
			if (errno == ENOENT)
				g_trace_handle_fd = TRACE_FILE_NOT_EXIST;

			set_last_result(TRACE_ERROR_IO_ERROR);
			return 0;
		}
	}
	TTRACE_LOG("traceInit:: cur_enabled_tag >> %u", *cur_enabled_tag);

	return *cur_enabled_tag;
}

static inline uint64_t isTagEnabled(uint64_t cur_tag)
{
	if (g_trace_handle_fd == TRACE_FILE_NOT_EXIST)
		return 0;
	/* if no tag is enabled, trace all tags. */
	cur_tag |= TTRACE_TAG_ALWAYS;

	if (g_trace_handle_fd == FD_INITIAL_VALUE || cur_enabled_tag == ((void *)&dummy))
		return (cur_tag & traceInit());

	return (cur_tag & *cur_enabled_tag);
}

int check_params(int fd, char* buf, int len, const char* func)
{
	if (fd <= 0 || buf == NULL || len < 0) {
		TTRACE_LOG("Currupted arguments, fd: %d, buf: %p, len: %d at %s.\n",
				fd, buf, len, func);
		return -1;
	}
	return 0;
}

/*
 * Tracing API for synchronous events: traceBegin()/traceEnd()
 * - tag: the tracing tag
 * - name: the event name
 */
void traceBegin(uint64_t tag, const char *name, ...)
{
	if (isTagEnabled(tag)) {
		char buf[MAX_LEN];
		int len = MAX_HEAD_LEN, ret = 0;
		va_list ap;

		TTRACE_LOG("traceBegin:: write >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);

		va_start(ap, name);
		snprintf(buf, MAX_LEN, "B|%5d|", getpid());
		len += vsnprintf(buf + MAX_HEAD_LEN, POS_LABEL_ST, name, ap);
		va_end(ap);

		if (len > MAX_LEN) len = MAX_LEN - 1;

		if (check_params(g_trace_handle_fd, buf, len, __func__) < 0)
			return;

		ret = write(g_trace_handle_fd, buf, len);
		if (ret < 0)
			TTRACE_LOG("error writing, len: %d, ret: %d, errno: %d at traceBegin.\n",
					len, ret, errno);
	}
	else
		TTRACE_LOG("traceBegin:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
}

void traceEnd(uint64_t tag)
{
	if (isTagEnabled(tag)) {
		int ret = 0;
		int len = 1;
		char end = 'E';
		TTRACE_LOG("traceEnd:: write>> tag: %u tag_bit: %u", tag, *cur_enabled_tag);

		if (check_params(g_trace_handle_fd, &end, len, __func__) < 0)
			return;

		ret = write(g_trace_handle_fd, &end, len);
		if (ret < 0)
			TTRACE_LOG("error writing, len: %d, ret: %d, errno: %d at traceEnd.\n",
					len, ret, errno);
	}
	else
		TTRACE_LOG("traceEnd:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
}

/*
 * Tracing API for asynchronous events: traceAsyncBegin()/traceAsyncEnd()
 * - tag: the tracing tag
 * - name: the event name
 * - cookie: an unique identifier for distinguishing simultaneous events.
 * The name and cookie used to begin an event must be used to end it.
 */
void traceAsyncBegin(uint64_t tag, int32_t cookie, const char *name, ...)
{
	if (isTagEnabled(tag)) {
		char buf[MAX_LEN];
		int len = MAX_HEAD_LEN, ret = 0;
		va_list ap;

		TTRACE_LOG("traceAsyncBegin:: write >> tag: %u tag_bit: %u cookie: %d", tag, *cur_enabled_tag, cookie);

		va_start(ap, name);
		snprintf(buf, MAX_LEN, "S|%5d|", getpid());
		len += vsnprintf(buf + MAX_HEAD_LEN, POS_LABEL_ST, name, ap);
		va_end(ap);

		if (len + MAX_TAIL_LEN < MAX_LEN) {
			len += snprintf(buf + len, MAX_LEN - len, "|%d", cookie);
		}
		else {
			snprintf(buf + POS_LABEL_ED, MAX_TAIL_LEN, "|%d", cookie);
			len = MAX_LEN - 1;
		}

		if (check_params(g_trace_handle_fd, buf, len, __func__) < 0)
			return;

		ret = write(g_trace_handle_fd, buf, len);
		if (ret < 0)
			TTRACE_LOG("error writing, len: %d, ret: %d, errno: %d at traceAsyncBegin.\n",
					len, ret, errno);
	}
	else
		TTRACE_LOG("traceAsyncBegin:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
}

void traceAsyncEnd(uint64_t tag, int32_t cookie, const char *name, ...)
{
	if (isTagEnabled(tag)) {
		char buf[MAX_LEN];
		int len = MAX_HEAD_LEN, ret = 0;
		va_list ap;

		TTRACE_LOG("traceAsyncEnd:: write>> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
		va_start(ap, name);
		snprintf(buf, MAX_LEN, "F|%5d|", getpid());
		len += vsnprintf(buf + MAX_HEAD_LEN, POS_LABEL_ST, name, ap);
		va_end(ap);

		if (len + MAX_TAIL_LEN < MAX_LEN) {
			len += snprintf(buf + len, MAX_LEN - len, "|%d", cookie);
		}
		else {
			snprintf(buf + POS_LABEL_ED, MAX_TAIL_LEN, "|%d", cookie);
			len = MAX_LEN - 1;
		}

		if (check_params(g_trace_handle_fd, buf, len, __func__) < 0)
			return;

		ret = write(g_trace_handle_fd, buf, len);
		if (ret < 0)
			TTRACE_LOG("error writing, len: %d, ret: %d, errno: %d at traceAsyncEnd.\n",
					len, ret, errno);
	}
	else
		TTRACE_LOG("traceAsyncEnd:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
}

/*
 * Tracing API for marking occurrences of trace event: traceMark
 * - tag: the tracing tag
 * - name: the event name
 */
/* LCOV_EXCL_START */
void traceMark(uint64_t tag, const char *name, ...)
{
	if (isTagEnabled(tag)) {
		char buf[MAX_LEN], end = 'E';
		int len = MAX_HEAD_LEN, ret = 0;
		va_list ap;

		TTRACE_LOG("traceMark:: write >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
		va_start(ap, name);
		snprintf(buf, MAX_LEN, "B|%5d|", getpid());
		len += vsnprintf(buf + MAX_HEAD_LEN, POS_LABEL_ST, name, ap);
		va_end(ap);

		if (len > MAX_LEN) len = MAX_LEN - 1;

		if (check_params(g_trace_handle_fd, buf, len, __func__) < 0)
			return;

		ret = write(g_trace_handle_fd, buf, len);
		if (ret < 0)
			TTRACE_LOG("error writing, len: %d, ret: %d, errno: %d at traceMark.\n",
					len, ret, errno);
		len = 1;
		if (check_params(g_trace_handle_fd, &end, len, __func__) < 0)
			return;

		ret = write(g_trace_handle_fd, &end, len);
		if (ret < 0)
			TTRACE_LOG("error writing, len: %d, ret: %d, errno: %d at traceMark.\n",
					len, ret, errno);
	}
	else
		TTRACE_LOG("traceMark:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
}

/* LCOV_EXCL_STOP */
/*
 * Tracing API for tracing change of integer counter value: traceCounter
 * - tag: the tracing tag
 * - name: the event name
 * - value: the value tracing
 */
void traceCounter(uint64_t tag, int32_t value, const char *name, ...)
{
	if (isTagEnabled(tag)) {
		char buf[MAX_LEN];
		int len = MAX_HEAD_LEN, ret = 0;
		va_list ap;

		va_start(ap, name);

		snprintf(buf, MAX_LEN, "C|%5d|", getpid());
		len += vsnprintf(buf + MAX_HEAD_LEN, POS_LABEL_ST, name, ap);
		va_end(ap);

		if (len + MAX_TAIL_LEN < MAX_LEN) {
			len += snprintf(buf + len, MAX_LEN - len, "|%d", value);
		}
		else {
			snprintf(buf + POS_LABEL_ED, MAX_TAIL_LEN, "|%d", value);
			len = MAX_LEN - 1;
		}

		if (check_params(g_trace_handle_fd, buf, len, __func__) < 0)
			return;

		ret = write(g_trace_handle_fd, buf, len);
		if (ret < 0)
			TTRACE_LOG("error writing, len: %d, ret: %d, errno: %d at traceCounter.\n",
					len, ret, errno);
	}
	else
		TTRACE_LOG("traceCounter:: disabled tag");
}

#else
void traceBegin(uint64_t tag, const char *name, ...)
{; }

void traceEnd(uint64_t tag)
{; }

void traceAsyncBegin(uint64_t tag, int32_t cookie, const char *name, ...)
{; }

void traceAsyncEnd(uint64_t tag, int32_t cookie, const char *name, ...)
{; }

void traceMark(uint64_t tag, const char *name, ...)
{; }

void traceCounter(uint64_t tag, int value, const char *name, ...)
{; }
#endif
