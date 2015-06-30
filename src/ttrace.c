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
 * @file:  ttrace.c
 * @brief:  ttrace
 * @author:  @samsung.com
 * @created:  Thursday 27 September 2012 08:05:23  KST
 * @compiler:  gcc
 * @company:  Samsung
 * @version:  0.1
 * @revision:  none
 *
 * =============================================================================
 */
#include "dlog.h"
#include "ttrace.h"
#include "trace.h"
#include "stdint.h"
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

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#define TRACE_FILE "/sys/kernel/debug/tracing/trace_marker"

#define MAX_TRACE_LEN 1024
#define MAX_LEN 512
#define FD_INITIAL_VALUE -1
#define TRACE_FILE_NOT_EXIST -2

int g_trace_handle_fd = FD_INITIAL_VALUE;
int g_enabled_tag_fd = FD_INITIAL_VALUE;

static uint64_t dummy = 0;
uint64_t *cur_enabled_tag = (void *)&dummy;

static uint64_t traceInit()
{
	uint64_t *sm_for_enabled_tag;

	g_trace_handle_fd = open(TRACE_FILE, O_WRONLY);
	if (g_trace_handle_fd < 0) {
		TTRACE_LOG("Fail to open trace file: %s(%d)", strerror(errno), errno);
		/* in case ftrace debugfs is not mounted, ttrace does not call traceInit() anymore. */
		if (errno == ENOENT)
			g_trace_handle_fd = TRACE_FILE_NOT_EXIST;

		set_last_result(TRACE_ERROR_IO_ERROR);
		return 0;
	}
	if (cur_enabled_tag == ((void *)&dummy)) {
		g_enabled_tag_fd = open(ENABLED_TAG_FILE, O_RDONLY | O_CLOEXEC);
		if (g_enabled_tag_fd < 0) {
			TTRACE_LOG("Fail to open enabled_tag file: %s(%d)", strerror(errno), errno);
			if (errno == ENOENT)
				g_enabled_tag_fd = TRACE_FILE_NOT_EXIST;

			return 0;
		}
		sm_for_enabled_tag = mmap(NULL, sizeof(uint64_t), PROT_READ, MAP_SHARED, g_enabled_tag_fd, 0);
		if (sm_for_enabled_tag == MAP_FAILED) {
			TTRACE_LOG("error: mmap() failed(%s)\n", strerror(errno));
			return 0;
		}
		cur_enabled_tag = sm_for_enabled_tag;
		TTRACE_LOG("cur_enabled_tag: %u %p", *cur_enabled_tag, cur_enabled_tag);

		return *cur_enabled_tag;
	} else {
		TTRACE_LOG("traceInit: %u", *cur_enabled_tag);
		return *cur_enabled_tag;
	}
}

static inline uint64_t isTagEnabled(uint64_t cur_tag)
{
	if (g_trace_handle_fd == TRACE_FILE_NOT_EXIST || g_enabled_tag_fd == TRACE_FILE_NOT_EXIST)
		return 0;
	/* if no tag is enabled, trace all tags. */
	cur_tag |= TTRACE_TAG_ALWAYS;

	if (g_trace_handle_fd < 0 || cur_enabled_tag == ((void *)&dummy))
		return (cur_tag & traceInit());

	return (cur_tag & *cur_enabled_tag);
}

/*
 * Tracing API for synchronous events: traceBegin()/traceEnd()
 * - tag: the tracing tag
 * - name: the event name
 */
inline void traceBegin(int tag, const char *name, ...)
{
	if (isTagEnabled(tag)) {
		char buf[MAX_LEN];
		int len = 0;
		va_list ap;

		TTRACE_LOG("traceBegin:: write >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
		va_start(ap, name);
		len = snprintf(buf, MAX_LEN, "B|%d|", getpid());
		len += vsnprintf(buf + len, MAX_LEN - len, name, ap);
		va_end(ap);
		write(g_trace_handle_fd, buf, len);
	}
#ifdef TTRACE_DEBUG
	else
		TTRACE_LOG("traceBegin:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);

#endif

}

inline void traceEnd(int tag)
{
	if (isTagEnabled(tag)) {
		char end = 'E';
		TTRACE_LOG("traceEnd:: write>> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
		write(g_trace_handle_fd, &end, 1);
	}
#ifdef TTRACE_DEBUG
	else
		TTRACE_LOG("traceEnd:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);

#endif
}

/*
 * Tracing API for asynchronous events: traceAsyncBegin()/traceAsyncEnd()
 * - tag: the tracing tag
 * - name: the event name
 * - cookie: an unique identifier for distinguishing simultaneous events.
 * The name and cookie used to begin an event must be used to end it.
 */
inline void traceAsyncBegin(int tag, int cookie, const char *name, ...)
{
	if (isTagEnabled(tag)) {
		char buf[MAX_LEN];
		int len = 0;
		va_list ap;

		TTRACE_LOG("traceAsyncBegin:: write >> tag: %u tag_bit: %u cookie: %d", tag, *cur_enabled_tag, cookie);
		va_start(ap, name);
		len = snprintf(buf, MAX_LEN, "S|%d|", getpid());
		len += vsnprintf(buf + len, MAX_LEN - len, name, ap);
		len += snprintf(buf + len, MAX_LEN - len, "|%d", cookie);
		va_end(ap);
		write(g_trace_handle_fd, buf, len);
	}
#ifdef TTRACE_DEBUG
	else
		TTRACE_LOG("traceAsyncBegin:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);

#endif
}

inline void traceAsyncEnd(int tag, int cookie, const char *name, ...)
{
	if (isTagEnabled(tag)) {
		char buf[MAX_LEN];
		int len = 0;
		va_list ap;

		TTRACE_LOG("traceAsyncEnd:: write>> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
		va_start(ap, name);
		len = snprintf(buf, MAX_LEN, "F|%d|", getpid());
		len += vsnprintf(buf + len, MAX_LEN - len, name, ap);
		len += snprintf(buf + len, MAX_LEN - len, "|%d", cookie);
		write(g_trace_handle_fd, buf, len);
	}
#ifdef TTRACE_DEBUG
	else
		TTRACE_LOG("traceAsyncEnd:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);

#endif
}

/*
 * Tracing API for marking occurrences of trace event: traceMark
 * - tag: the tracing tag
 * - name: the event name
 */
/* LCOV_EXCL_START */
inline void traceMark(int tag, const char *name, ...)
{
	if (isTagEnabled(tag)) {
		char buf[MAX_LEN], end = 'E';
		int len = 0;
		va_list ap;

		TTRACE_LOG("traceMark:: write >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
		va_start(ap, name);
		len = snprintf(buf, MAX_LEN, "B|%d|", getpid());
		len += vsnprintf(buf + len, MAX_LEN - len, name, ap);
		va_end(ap);
		write(g_trace_handle_fd, buf, len);
		write(g_trace_handle_fd, &end, 1);
	}
#ifdef TTRACE_DEBUG
	else
		TTRACE_LOG("traceMark:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);

#endif
}

/* LCOV_EXCL_STOP */
/*
 * Tracing API for tracing change of integer counter value: traceCounter
 * - tag: the tracing tag
 * - name: the event name
 * - value: the value tracing
 */
inline void traceCounter(int tag, int value, const char *name, ...)
{
	if (isTagEnabled(tag)) {
		char buf[MAX_LEN];
		int len = 0;
		va_list ap;

		va_start(ap, name);

		len = snprintf(buf, MAX_LEN, "C|%d|", getpid());
		len += vsnprintf(buf + len, MAX_LEN - len, name, ap);
		len += snprintf(buf + len, MAX_LEN - len, "|%d", value);
		write(g_trace_handle_fd, buf, len);
	}
#ifdef TTRACE_DEBUG
	else
		TTRACE_LOG("traceCounter:: disabled tag");

#endif
}

/*
 * Tracing API for Native Application
 * - tag: the tracing tag
 * - name: the event name
 * - value: the value tracing
 */
inline void trace_begin(const char *name, ...)
{
	va_list ap;
	char v_name[MAX_LEN];

	va_start(ap, name);
	vsnprintf(v_name, MAX_LEN, name, ap);

	traceBegin(TTRACE_TAG_APP, v_name);
	va_end(ap);
}

inline void trace_end()
{
	traceEnd(TTRACE_TAG_APP);
}

inline void trace_async_begin(int cookie, const char *name, ...)
{
	va_list ap;
	char v_name[MAX_LEN];

	va_start(ap, name);
	vsnprintf(v_name, MAX_LEN, name, ap);

	traceAsyncBegin(TTRACE_TAG_APP, cookie, v_name);
	va_end(ap);
}

inline void trace_async_end(int cookie, const char *name, ...)
{
	va_list ap;
	char v_name[MAX_LEN];

	va_start(ap, name);
	vsnprintf(v_name, MAX_LEN, name, ap);

	traceAsyncEnd(TTRACE_TAG_APP, cookie, v_name);
	va_end(ap);
}

inline void trace_update_counter(int value, const char *name, ...)
{
	va_list ap;
	char v_name[MAX_LEN];

	va_start(ap, name);
	vsnprintf(v_name, MAX_LEN, name, ap);

	traceCounter(TTRACE_TAG_APP, value, v_name);
	va_end(ap);
}
#else
inline void traceBegin(int tag, const char *name, ...)
{; }

inline void traceEnd(int tag)
{; }

inline void traceAsyncBegin(int tag, int cookie, const char *name, ...)
{; }

inline void traceAsyncEnd(int tag, int cookie, const char *name, ...)
{; }

inline void traceMark(int tag, const char *name, ...)
{; }

inline void traceCounter(int tag, int value, const char *name, ...)
{; }

inline void trace_begin(const char *name, ...)
{; }

inline void trace_end()
{; }

inline void trace_async_begin(int cookie, const char *name, ...)
{; }

inline void trace_async_end(int cookie, const char *name, ...)
{; }

inline void trace_update_counter(int value, const char *name, ...)
{; }
#endif

