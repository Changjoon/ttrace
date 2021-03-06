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
#include "ttrace.h"
#include "trace.h"
#include "dlog.h"
#include "ttrace-extension.h"

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

#define EXT_DEACTIVATED 0
#define EXT_ACTIVATED 1

int g_trace_handle_fd = FD_INITIAL_VALUE;
int g_enabled_tag_fd = FD_INITIAL_VALUE;
int g_extension_state = EXT_DEACTIVATED;

static uint64_t dummy = 0;
uint64_t *cur_enabled_tag = (void *)&dummy;

static uint64_t traceInit()
{
	uint64_t *sm_for_enabled_tag;
	TTRACE_LOG("traceInit: %p %p", cur_enabled_tag, ((void *)&dummy));

	g_extension_state = EXT_ACTIVATED;
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

	/* ttrace is ready. deactive g_extension_state */
	g_extension_state = EXT_DEACTIVATED;
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

/*
 * Tracing API for synchronous events: traceBegin()/traceEnd()
 * - tag: the tracing tag
 * - name: the event name
 */
void traceBegin(uint64_t tag, const char *name, ...)
{
	if (isTagEnabled(tag) || g_extension_state == EXT_ACTIVATED) { 
		char buf[MAX_LEN];
		int len = MAX_HEAD_LEN, ret = 0;
		va_list ap;

		TTRACE_LOG("traceBegin:: write >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);

		va_start(ap, name);
		snprintf(buf, MAX_LEN, "B|%5d|", getpid());
		len += vsnprintf(buf + MAX_HEAD_LEN, POS_LABEL_ST, name, ap);
		va_end(ap);
		
		if (len > MAX_LEN) len = MAX_LEN - 1;

		if (g_extension_state == EXT_ACTIVATED)	ttrace_extension_write(buf, len);
		else 		ret = write(g_trace_handle_fd, buf, len);
#ifdef TTRACE_DEBUG
		if (ret < 0)
			fprintf(stderr, "error writing, len: %d, ret: %d, errno: %d at traceBegin.\n", len, ret, errno);
#endif
	}
#ifdef TTRACE_DEBUG	
	else {
		TTRACE_LOG("traceBegin:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);

#endif
}

void traceEnd(uint64_t tag)
{
	if (isTagEnabled(tag) || g_extension_state == EXT_ACTIVATED) { 
		int ret = 0;
		char end = 'E';
		TTRACE_LOG("traceEnd:: write>> tag: %u tag_bit: %u", tag, *cur_enabled_tag);

		if (g_extension_state == EXT_ACTIVATED)	ttrace_extension_write("E", 1);
		else 		ret = write(g_trace_handle_fd, &end, 1);
#ifdef TTRACE_DEBUG
		if (ret < 0)
			fprintf(stderr, "error writing, len: %d, ret: %d, errno: %d at traceEnd.\n", 1, ret, errno);
#endif
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
void traceAsyncBegin(uint64_t tag, int32_t cookie, const char *name, ...)
{
	if (isTagEnabled(tag) || g_extension_state == EXT_ACTIVATED) { 
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

		if (g_extension_state == EXT_ACTIVATED)	ttrace_extension_write(buf, len);
		else	ret = write(g_trace_handle_fd, buf, len);
#ifdef TTRACE_DEBUG
		if (ret < 0)
			fprintf(stderr, "error writing, len: %d, ret: %d, errno: %d at traceAsyncBegin.\n", len, ret, errno);
#endif
	}
#ifdef TTRACE_DEBUG
	else
		TTRACE_LOG("traceAsyncBegin:: disabled tag >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);

#endif
}

void traceAsyncEnd(uint64_t tag, int32_t cookie, const char *name, ...)
{
	if (isTagEnabled(tag) || g_extension_state == EXT_ACTIVATED) { 
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


		if (g_extension_state == EXT_ACTIVATED)	ttrace_extension_write(buf, len);
		else	ret = write(g_trace_handle_fd, buf, len);
#ifdef TTRACE_DEBUG
		if (ret < 0)
			fprintf(stderr, "error writing, len: %d, ret: %d, errno: %d at traceAsyncEnd.\n", len, ret, errno);
#endif
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
void traceMark(uint64_t tag, const char *name, ...)
{
	if (isTagEnabled(tag) || g_extension_state == EXT_ACTIVATED) { 
		char buf[MAX_LEN], end = 'E';
		int len = MAX_HEAD_LEN, ret = 0;
		va_list ap;

		TTRACE_LOG("traceMark:: write >> tag: %u tag_bit: %u", tag, *cur_enabled_tag);
		va_start(ap, name);
		snprintf(buf, MAX_LEN, "B|%5d|", getpid());
		len += vsnprintf(buf + MAX_HEAD_LEN, POS_LABEL_ST, name, ap);
		va_end(ap);

		if (len > MAX_LEN) len = MAX_LEN - 1;

		if (g_extension_state == EXT_ACTIVATED) ttrace_extension_write(buf, len);
		else	ret = write(g_trace_handle_fd, buf, len);

#ifdef TTRACE_DEBUG
		if (ret < 0)
			fprintf(stderr, "error writing, len: %d, ret: %d, errno: %d at traceMark.\n", len, ret, errno);
#endif

		if (g_extension_state == EXT_ACTIVATED) ttrace_extension_write("E", 1);
		else	ret = write(g_trace_handle_fd, &end, 1);
#ifdef TTRACE_DEBUG
		if (ret < 0)
			fprintf(stderr, "error writing, len: %d, ret: %d, errno: %d at traceMark.\n", 1, ret, errno);
#endif
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
void traceCounter(uint64_t tag, int32_t value, const char *name, ...)
{
	if (isTagEnabled(tag) || g_extension_state == EXT_ACTIVATED) { 
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

		if (g_extension_state == EXT_ACTIVATED) ttrace_extension_write(buf, len);
		else	ret = write(g_trace_handle_fd, buf, len);
#ifdef TTRACE_DEBUG
		if (ret < 0)
			fprintf(stderr, "error writing, len: %d, ret: %d, errno: %d at traceCounter.\n", len, ret, errno);
#endif
	}
#ifdef TTRACE_DEBUG
	else
		TTRACE_LOG("traceCounter:: disabled tag");

#endif
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
