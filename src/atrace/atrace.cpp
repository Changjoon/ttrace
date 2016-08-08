/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define DEVICE_TYPE_TIZEN		//build atrace for tizen platform

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <time.h>
#include <zlib.h>
#include <pwd.h>

#ifdef DEVICE_TYPE_TIZEN
#include <stdint.h>
#include <strings.h>
#include <string.h>
#include <grp.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/smack.h>
#include <unistd.h>
#include "ttrace.h"
#define TTRACE_TAG_NONE		9999
#define TAG_NONE_IDX		0

#define BACKUP_TRACE	"/tmp/trace.backup"
#define BOOTUP_TRACE	"/etc/ttrace.conf"
#define DEF_GR_SIZE	1024
#else
#include <binder/IBinder.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>

#include <cutils/properties.h>

#include <utils/String8.h>
#include <utils/Trace.h>

using namespace android;
#endif
#define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))

enum { MAX_SYS_FILES = 8 };

const char* k_traceTagsProperty = "debug.atrace.tags.enableflags";
const char* k_traceAppCmdlineProperty = "debug.atrace.app_cmdlines";

typedef enum { OPT, REQ } requiredness  ;

char str_error[256] = "";

struct CommonNode {
	const char* path;
	const mode_t	perms;
};

typedef enum {
	TTRACE_TAG_IDX = 0,
	DEBUG_FS_IDX,
	TRACING_FS_IDX,
	TRACE_MARKER_IDX,
	ESSENCE_NODE_IDX
} commonNodeIdx;

static const CommonNode commonNodes[] = {
    {	ENABLED_TAG_FILE,                                                   0666},
    {	"/sys/kernel/debug",                                                0755},
    {	"/sys/kernel/debug/tracing",                                        0755},
    {	"/sys/kernel/debug/tracing/trace_marker",                           0222},
    {	"/sys/kernel/debug/tracing/trace_clock",                            0666},
    {	"/sys/kernel/debug/tracing/buffer_size_kb",                         0666},
    {	"/sys/kernel/debug/tracing/current_tracer",                         0666},
    {	"/sys/kernel/debug/tracing/tracing_on",                             0666},
    {	"/sys/kernel/debug/tracing/trace",                                  0666},
    {	"/sys/kernel/debug/tracing/options/overwrite",                      0666},
    {	"/sys/kernel/debug/tracing/options/print-tgid",                     0666},
    {	"/sys/kernel/debug/tracing/events/sched/sched_switch/enable",       0666},
    {	"/sys/kernel/debug/tracing/events/sched/sched_wakeup/enable",       0666},
    {	"/sys/kernel/debug/tracing/events/power/cpu_frequency/enable",      0666},
    {	"/sys/kernel/debug/tracing/events/memory_bus/enable",               0666},
    {	"/sys/kernel/debug/tracing/events/power/cpu_idle/enable",           0666},
    {	"/sys/kernel/debug/tracing/events/ext4/ext4_sync_file_enter/enable",0666},
    {	"/sys/kernel/debug/tracing/events/ext4/ext4_sync_file_exit/enable", 0666},
    {	"/sys/kernel/debug/tracing/events/block/block_rq_issue/enable",     0666},
    {	"/sys/kernel/debug/tracing/events/block/block_rq_complete/enable",  0666},
    {	"/sys/kernel/debug/tracing/events/mmc/enable",                      0666},
    {	"/sys/kernel/debug/tracing/events/cpufreq_interactive/enable",      0666},
    {	"/sys/kernel/debug/tracing/events/sync/enable",                     0666},
    {	"/sys/kernel/debug/tracing/events/workqueue/enable",                0666},
};

struct TracingCategory {
    // The name identifying the category.
    const char* name;

    // A longer description of the category.
    const char* longname;

    // The userland tracing tags that the category enables.
    uint64_t tags;

    // The fname==NULL terminated list of /sys/ files that the category
    // enables.
    struct {
        // Whether the file must be writable in order to enable the tracing
        // category.
        requiredness required;

        // The path to the enable file.
        const char* path;
    } sysfiles[MAX_SYS_FILES];
};

/* Tracing categories */
static const TracingCategory k_categories[] = {
#ifdef DEVICE_TYPE_TIZEN
    { "none",        "None",                TTRACE_TAG_NONE, { } }, //do not change "none" option's index
    { "gfx",         "Graphics",            TTRACE_TAG_GRAPHICS, { } },
    { "input",       "Input",               TTRACE_TAG_INPUT, { } },
    { "view",        "View System",         TTRACE_TAG_VIEW, { } },
    { "web",         "Web",                 TTRACE_TAG_WEB, { } },
    { "wm",          "Window Manager",      TTRACE_TAG_WINDOW_MANAGER, { } },
    { "am",          "Application Manager", TTRACE_TAG_APPLICATION_MANAGER, { } },
    { "image",       "Image",               TTRACE_TAG_IMAGE, { } },
    { "audio",       "Audio",               TTRACE_TAG_AUDIO, { } },
    { "video",       "Video",               TTRACE_TAG_VIDEO, { } },
    { "camera",      "Camera",              TTRACE_TAG_CAMERA, { } },
    { "hal",         "Hardware Modules",    TTRACE_TAG_HAL, { } },
    { "mc",          "Multimedia content",  TTRACE_TAG_MEDIA_CONTENT, { } },
    { "mdb",         "Multimedia database", TTRACE_TAG_MEDIA_DB, { } },
    { "scmirroring", "Screen mirroring",    TTRACE_TAG_SCREEN_MIRRORING, { } },
    { "efl",         "EFL",                 TTRACE_TAG_EFL, { } },
    { "app",         "Application",         TTRACE_TAG_APP, { } },
#else		// Android tags
    { "gfx",        "Graphics",         ATRACE_TAG_GRAPHICS, { } },
    { "input",      "Input",            ATRACE_TAG_INPUT, { } },
    { "view",       "View System",      ATRACE_TAG_VIEW, { } },
    { "webview",    "WebView",          ATRACE_TAG_WEBVIEW, { } },
    { "wm",         "Window Manager",   ATRACE_TAG_WINDOW_MANAGER, { } },
    { "am",         "Activity Manager", ATRACE_TAG_ACTIVITY_MANAGER, { } },
    { "audio",      "Audio",            ATRACE_TAG_AUDIO, { } },
    { "video",      "Video",            ATRACE_TAG_VIDEO, { } },
    { "camera",     "Camera",           ATRACE_TAG_CAMERA, { } },
    { "hal",        "Hardware Modules", ATRACE_TAG_HAL, { } },
    { "res",        "Resource Loading", ATRACE_TAG_RESOURCES, { } },
    { "dalvik",     "Dalvik VM",        ATRACE_TAG_DALVIK, { } },
    { "rs",         "RenderScript",     ATRACE_TAG_RS, { } },
#endif	// Linux kernel tags
    { "sched",      "CPU Scheduling",   0, {
        { REQ,      "/sys/kernel/debug/tracing/events/sched/sched_switch/enable" },
        { REQ,      "/sys/kernel/debug/tracing/events/sched/sched_wakeup/enable" },
    } },
    { "freq",       "CPU Frequency",    0, {
        { REQ,      "/sys/kernel/debug/tracing/events/power/cpu_frequency/enable" },
        { OPT,      "/sys/kernel/debug/tracing/events/power/clock_set_rate/enable" },
    } },
    { "membus",     "Memory Bus Utilization", 0, {
        { REQ,      "/sys/kernel/debug/tracing/events/memory_bus/enable" },
    } },
    { "idle",       "CPU Idle",         0, {
        { REQ,      "/sys/kernel/debug/tracing/events/power/cpu_idle/enable" },
    } },
    { "disk",       "Disk I/O",         0, {
        { REQ,      "/sys/kernel/debug/tracing/events/ext4/ext4_sync_file_enter/enable" },
        { REQ,      "/sys/kernel/debug/tracing/events/ext4/ext4_sync_file_exit/enable" },
        { REQ,      "/sys/kernel/debug/tracing/events/block/block_rq_issue/enable" },
        { REQ,      "/sys/kernel/debug/tracing/events/block/block_rq_complete/enable" },
    } },
    { "mmc",        "eMMC commands",    0, {
        { REQ,      "/sys/kernel/debug/tracing/events/mmc/enable" },
    } },
    { "load",       "CPU Load",         0, {
        { REQ,      "/sys/kernel/debug/tracing/events/cpufreq_interactive/enable" },
    } },
    { "sync",       "Synchronization",  0, {
        { REQ,      "/sys/kernel/debug/tracing/events/sync/enable" },
    } },
    { "workq",      "Kernel Workqueues", 0, {
        { REQ,      "/sys/kernel/debug/tracing/events/workqueue/enable" },
    } },
#ifdef TTRACE_PROFILE_MOBILE
#elif defined TTRACE_PROFILE_TV
    { "system",       "System",        	TTRACE_TAG_SYSTEM, { } },
#elif defined TTRACE_PROFILE_WEARABLE
#endif
};

/* Command line options */
static int g_traceDurationSeconds = 5;
static bool g_traceOverwrite = false;
static int g_traceBufferSizeKB = 2048;
static bool g_compress = false;
static bool g_nohup = false;
static int g_initialSleepSecs = 0;
static const char* g_kernelTraceFuncs = NULL;
static const char* g_debugAppCmdLine = "";

/* Global state */
static bool g_traceAborted = false;
static bool g_categoryEnables[NELEM(k_categories)] = {};

#ifdef DEVICE_TYPE_TIZEN
static bool g_init_exec = false;
static bool g_append_trace = false;
static bool g_backup_trace = false;
static struct group group_dev;
static struct passwd passwd_dev;
#if TTRACE_TIZEN_VERSION_MAJOR < 3
#define TTRACE_USER_NAME	"root"
#define TTRACE_GROUP_NAME	"developer"
#else
#define TTRACE_USER_NAME	"system_fw"
#define TTRACE_GROUP_NAME	"system_fw"
#endif
static struct group* group_ptr;
static struct passwd* passwd_ptr;

#endif

/* Sys file paths */
static const char* k_traceClockPath =
    "/sys/kernel/debug/tracing/trace_clock";

static const char* k_traceBufferSizePath =
    "/sys/kernel/debug/tracing/buffer_size_kb";

static const char* k_tracingOverwriteEnablePath =
    "/sys/kernel/debug/tracing/options/overwrite";

static const char* k_currentTracerPath =
    "/sys/kernel/debug/tracing/current_tracer";

static const char* k_printTgidPath =
    "/sys/kernel/debug/tracing/options/print-tgid";

static const char* k_funcgraphAbsTimePath =
    "/sys/kernel/debug/tracing/options/funcgraph-abstime";

static const char* k_funcgraphCpuPath =
    "/sys/kernel/debug/tracing/options/funcgraph-cpu";

static const char* k_funcgraphProcPath =
    "/sys/kernel/debug/tracing/options/funcgraph-proc";

static const char* k_funcgraphFlatPath =
    "/sys/kernel/debug/tracing/options/funcgraph-flat";

static const char* k_funcgraphDurationPath =
    "/sys/kernel/debug/tracing/options/funcgraph-duration";

static const char* k_ftraceFilterPath =
    "/sys/kernel/debug/tracing/set_ftrace_filter";

static const char* k_tracingOnPath =
    "/sys/kernel/debug/tracing/tracing_on";

static const char* k_tracePath =
    "/sys/kernel/debug/tracing/trace";

// Check whether a file exists.
static bool fileExists(const char* filename) {
    return access(filename, F_OK) != -1;
}

// Check whether a file is writable.
static bool fileIsWritable(const char* filename) {
    return access(filename, W_OK) != -1;
}

static bool setFilePermission (const char *path, const mode_t perms) {
	//fprintf(stderr, "path: %s, perms: %d, gid: %d\n", path,perms, group_dev.gr_gid);
	if (0 > chown(path, passwd_dev.pw_uid, group_dev.gr_gid)) return false;
	if (0 > chmod(path, perms)) return false;
	if (0 > smack_setlabel(path, "*", SMACK_LABEL_ACCESS)) return false;

	return true;
}

static bool initSysfsPermission() {
	for (int i = TTRACE_TAG_IDX + 1 ; i < NELEM(commonNodes); i++) {
		const CommonNode &node = commonNodes[i];
		printf("initsysfsperm: path- %s, perms- %d\n", node.path, node.perms);
		if (fileExists(node.path)) {
			if (i == DEBUG_FS_IDX || i == TRACING_FS_IDX) {
				if(0 > chmod(node.path, node.perms))
					return false;
			}
			else {
				if (!setFilePermission(node.path, node.perms))
					return false;
			}
		}
		else {
			if(i < ESSENCE_NODE_IDX)
			{
				return false;
			}
		}
	}
    return true;
}

// Truncate a file.
static bool truncateFile(const char* path)
{
    // This uses creat rather than truncate because some of the debug kernel
    // device nodes (e.g. k_ftraceFilterPath) currently aren't changed by
    // calls to truncate, but they are cleared by calls to creat.
    int traceFD = creat(path, 0);
    if (traceFD == -1) {
        fprintf(stderr, "error truncating %s: %s (%d)\n", path,
            strerror_r(errno, str_error, sizeof(str_error)), errno);
        return false;
    }

    close(traceFD);

    return true;
}

static bool _writeStr(const char* filename, const char* str, int flags)
{
    int fd = open(filename, flags);
    if (fd == -1) {
        fprintf(stderr, "error opening %s: %s (%d)\n", filename,
                strerror_r(errno, str_error, sizeof(str_error)), errno);
        return false;
    }

    bool ok = true;
    ssize_t len = strlen(str);
    if (write(fd, str, len) != len) {
        fprintf(stderr, "error writing to %s: %s (%d)\n", filename,
                strerror_r(errno, str_error, sizeof(str_error)), errno);
        ok = false;
    }

    close(fd);

    return ok;
}

// Write a string to a file, returning true if the write was successful.
static bool writeStr(const char* filename, const char* str)
{
    return _writeStr(filename, str, O_WRONLY);
}

// Append a string to a file, returning true if the write was successful.
static bool appendStr(const char* filename, const char* str)
{
    return _writeStr(filename, str, O_APPEND|O_WRONLY);
}

// Enable or disable a kernel option by writing a "1" or a "0" into a /sys
// file.
static bool setKernelOptionEnable(const char* filename, bool enable)
{
    return writeStr(filename, enable ? "1" : "0");
}

// Check whether the category is supported on the device with the current
// rootness.  A category is supported only if all its required /sys/ files are
// writable and if enabling the category will enable one or more tracing tags
// or /sys/ files.
static bool isCategorySupported(const TracingCategory& category)
{
    bool ok = category.tags != 0;
    for (int i = 0; i < MAX_SYS_FILES; i++) {
        const char* path = category.sysfiles[i].path;
        bool req = category.sysfiles[i].required == REQ;
        if (path != NULL) {
            if (req) {
                if (!fileIsWritable(path)) {
                    return false;
                } else {
                    ok = true;
                }
            } else {
                ok |= fileIsWritable(path);
            }
        }
    }
    return ok;
}

// Check whether the category would be supported on the device if the user
// were root.  This function assumes that root is able to write to any file
// that exists.  It performs the same logic as isCategorySupported, but it
// uses file existance rather than writability in the /sys/ file checks.
static bool isCategorySupportedForRoot(const TracingCategory& category)
{
    bool ok = category.tags != 0;
    for (int i = 0; i < MAX_SYS_FILES; i++) {
        const char* path = category.sysfiles[i].path;
        bool req = category.sysfiles[i].required == REQ;
        if (path != NULL) {
            if (req) {
                if (!fileExists(path)) {
                    return false;
                } else {
                    ok = true;
                }
            } else {
                ok |= fileExists(path);
            }
        }
    }
    return ok;
}

// Enable or disable overwriting of the kernel trace buffers.  Disabling this
// will cause tracing to stop once the trace buffers have filled up.
static bool setTraceOverwriteEnable(bool enable)
{
    return setKernelOptionEnable(k_tracingOverwriteEnablePath, enable);
}

// Enable or disable kernel tracing.
static bool setTracingEnabled(bool enable)
{
    return setKernelOptionEnable(k_tracingOnPath, enable);
}

// Clear the contents of the kernel trace.
static bool clearTrace()
{
    return truncateFile(k_tracePath);
}

// Set the size of the kernel's trace buffer in kilobytes.
static bool setTraceBufferSizeKB(int size)
{
    char str[32] = "1";
    if (size < 1) {
        size = 1;
    }
    snprintf(str, 32, "%d", size);
    return writeStr(k_traceBufferSizePath, str);
}

// Enable or disable the kernel's use of the global clock.  Disabling the global
// clock will result in the kernel using a per-CPU local clock.
static bool setGlobalClockEnable(bool enable)
{
    return writeStr(k_traceClockPath, enable ? "global" : "local");
}

static bool setPrintTgidEnableIfPresent(bool enable)
{
    if (fileExists(k_printTgidPath)) {
        return setKernelOptionEnable(k_printTgidPath, enable);
    }
    return true;
}

// Poke all the binder-enabled processes in the system to get them to re-read
// their system properties.
static bool pokeBinderServices()
{
#ifndef DEVICE_TYPE_TIZEN
    sp<IServiceManager> sm = defaultServiceManager();
    Vector<String16> services = sm->listServices();
    for (size_t i = 0; i < services.size(); i++) {
        sp<IBinder> obj = sm->checkService(services[i]);
        if (obj != NULL) {
            Parcel data;
            if (obj->transact(IBinder::SYSPROPS_TRANSACTION, data,
                    NULL, 0) != OK) {
                if (false) {
                    // XXX: For some reason this fails on tablets trying to
                    // poke the "phone" service.  It's not clear whether some
                    // are expected to fail.
                    String8 svc(services[i]);
                    fprintf(stderr, "error poking binder service %s\n",
                        svc.string());
                    return false;
                }
            }
        }
    }
#endif
    return true;
}

// Set the trace tags that userland tracing uses, and poke the running
// processes to pick up the new value.
static bool setTagsProperty(uint64_t tags)
{
#ifdef DEVICE_TYPE_TIZEN
	uint64_t *sm_for_enabled_tag = NULL;
	int fd = -1;
	const CommonNode &tag_node = commonNodes[TTRACE_TAG_IDX];

//atrace "--init_exec" mode
	if(g_init_exec) {
		size_t bufSize = DEF_GR_SIZE;
		char buf[DEF_GR_SIZE];
		int ret = 0;
        bool isInvalid = false;

		if(fileExists(ENABLED_TAG_FILE)) {
			fprintf(stderr, "[Info] T-trace has been already initailized\n");
			return false; //atrace has been already initailized.
		}

		ret = getgrnam_r(TTRACE_GROUP_NAME, &group_dev, buf, bufSize, &group_ptr);

		if (ret != 0 && ret != ERANGE)
		{
			fprintf(stderr, "Fail to group[%s] info: %s(%d)\n", TTRACE_GROUP_NAME, strerror_r(errno, str_error, sizeof(str_error)), errno);
			return false;
		}

		isInvalid = false;
		while(ret == ERANGE)
		{
			long int tmpSize = -1;

			if(!isInvalid)
				tmpSize = sysconf(_SC_GETGR_R_SIZE_MAX);

			if (tmpSize == -1)
			{
				bufSize *= 2;
			}
			else bufSize = (size_t) tmpSize;

			char *dynbuf = (char *) malloc(bufSize);
			if(dynbuf == NULL)
			{
				fprintf(stderr, "Fail to allocate buffer for group[%s]: %s(%d)\n", TTRACE_GROUP_NAME, strerror_r(errno, str_error, sizeof(str_error)), errno);
				return false;
			}
			ret = getgrnam_r(TTRACE_GROUP_NAME, &group_dev, dynbuf, bufSize, &group_ptr);
			if(ret == ERANGE) isInvalid = true;
			free(dynbuf);
		}

		ret = getpwnam_r(TTRACE_USER_NAME, &passwd_dev, buf, bufSize, &passwd_ptr);

		if (ret != 0 && ret != ERANGE)
		{
			fprintf(stderr, "Fail to group[%s] info: %s(%d)\n", TTRACE_USER_NAME, strerror_r(errno, str_error, sizeof(str_error)), errno);
			return false;
		}
		
		isInvalid = false;
		while(ret == ERANGE)
		{
			long int tmpSize = -1;

			if(!isInvalid)
				tmpSize = sysconf(_SC_GETGR_R_SIZE_MAX);

			if (tmpSize == -1)
			{
				bufSize *= 2;
			}
			else bufSize = (size_t) tmpSize;

			char *dynbuf = (char *) malloc(bufSize);
			if(dynbuf == NULL)
			{
				fprintf(stderr, "Fail to allocate buffer for group[%s]: %s(%d)\n", TTRACE_GROUP_NAME, strerror_r(errno, str_error, sizeof(str_error)), errno);
				return false;
			}
			ret = getpwnam_r(TTRACE_USER_NAME, &passwd_dev, dynbuf, bufSize, &passwd_ptr);
			if(ret == ERANGE) isInvalid = true;
			free(dynbuf);
		}

		fd = open("/tmp/tmp_tag", O_CREAT | O_RDWR | O_CLOEXEC, 0666);
		if(fd < 0){
			fprintf(stderr, "Fail to open enabled_tag file: %s(%d)\n", strerror_r(errno, str_error, sizeof(str_error)), errno);
			return false;
		}
		//set file permission, smack label to "/tmp/tmp_tag" and then change it's name to "/tmp/ttrace_tag"
		if (!setFilePermission("/tmp/tmp_tag", tag_node.perms))
		{
			fprintf(stderr, "setFilePermission failed(%s): /tmp/tmp_tag\n", strerror_r(errno, str_error, sizeof(str_error)));
			close(fd);
			return false;
		}

		if (ftruncate(fd, sizeof(uint64_t)) < 0) {
			fprintf(stderr, "ftruncate() failed(%s)\n", strerror_r(errno, str_error, sizeof(str_error)));
			close(fd);
			return false;
		}
		sm_for_enabled_tag = (uint64_t*)mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

		if(sm_for_enabled_tag == MAP_FAILED) {
			fprintf(stderr, "mmap() failed(%s)\n", strerror_r(errno, str_error, sizeof(str_error)));
			close(fd);
			return false;
		}
		//for auto-mounting tracingfs (>= linux 4.1.x)
		system("ls -al /sys/kernel/debug/tracing > /dev/null 2>&1");
		if(!initSysfsPermission()) {
			fprintf(stderr, "Fail to init sysfs permisions: %s(%d)\n", strerror_r(errno, str_error, sizeof(str_error)), errno);
			munmap(sm_for_enabled_tag, sizeof(uint64_t));
			close(fd);
			return false;
		}

		memset(sm_for_enabled_tag, 0, sizeof(uint64_t));
		if(-1 == rename("/tmp/tmp_tag", tag_node.path)) {
			fprintf(stderr, "Fail to rename enabled_tag file: %s(%d)\n", strerror_r(errno, str_error, sizeof(str_error)), errno);
		}

		if(fileExists(BOOTUP_TRACE)) {
			FILE *ifile = NULL;
			char bootup_cmd[128];
			ifile = fopen(BOOTUP_TRACE, "r");
			if (ifile == NULL) {
				munmap(sm_for_enabled_tag, sizeof(uint64_t));
				close(fd);
				return false;
			}
			if (fgets(bootup_cmd, sizeof(bootup_cmd), ifile) == NULL) {
				munmap(sm_for_enabled_tag, sizeof(uint64_t));
				close(fd);
				fclose(ifile);
				return false;
			}
			fclose(ifile);
			remove(BOOTUP_TRACE);
			if (0 > system(bootup_cmd)) {
				munmap(sm_for_enabled_tag, sizeof(uint64_t));
				close(fd);
				return false;
			}
		}
	}
//atrace normal mode
	else {
		fd = open(ENABLED_TAG_FILE, O_RDWR | O_CLOEXEC, 0666);
		if(fd < 0){
			fprintf(stderr, "Fail to open enabled_tag file: %s(%d)\n", strerror_r(errno, str_error, sizeof(str_error)), errno);
			return false;
		}
		sm_for_enabled_tag = (uint64_t*)mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if(sm_for_enabled_tag == MAP_FAILED) {
			fprintf(stderr, "mmap() failed(%s)\n", strerror_r(errno, str_error, sizeof(str_error)));
			close(fd);
			return false;
		}
		*sm_for_enabled_tag = tags;
	}
	// For debug
	//fprintf(stderr, "Enabled TAGs: %u\n", (uint32_t)*sm_for_enabled_tag);
	//
	munmap(sm_for_enabled_tag, sizeof(uint64_t));
	close(fd);
#else
    char buf[64];
    snprintf(buf, 64, "%#llx", tags);
    if (property_set(k_traceTagsProperty, buf) < 0) {
        fprintf(stderr, "error setting trace tags system property\n");
        return false;
    }
#endif
    return true;
}

// Set the system property that indicates which apps should perform
// application-level tracing.
static bool setAppCmdlineProperty(const char* cmdline)
{
#ifndef DEVICE_TYPE_TIZEN
    if (property_set(k_traceAppCmdlineProperty, cmdline) < 0) {
        fprintf(stderr, "error setting trace app system property\n");
        return false;
    }
#endif
    return true;
}

// Disable all /sys/ enable files.
static bool disableKernelTraceEvents() {
    bool ok = true;
    for (int i = 0; i < NELEM(k_categories); i++) {
        const TracingCategory &c = k_categories[i];
        for (int j = 0; j < MAX_SYS_FILES; j++) {
            const char* path = c.sysfiles[j].path;
            if (path != NULL && fileIsWritable(path)) {
                ok &= setKernelOptionEnable(path, false);
            }
        }
    }
    return ok;
}

// Verify that the comma separated list of functions are being traced by the
// kernel.
static bool verifyKernelTraceFuncs(const char* funcs)
{
#ifndef DEVICE_TYPE_TIZEN
    int fd = open(k_ftraceFilterPath, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "error opening %s: %s (%d)\n", k_ftraceFilterPath,
            strerror_r(errno, str_error, sizeof(str_error)), errno);
        return false;
    }

    char buf[4097];
    ssize_t n = read(fd, buf, 4096);
    close(fd);
    if (n == -1) {
        fprintf(stderr, "error reading %s: %s (%d)\n", k_ftraceFilterPath,
            strerror_r(errno, str_error, sizeof(str_error)), errno);
        return false;
    }

    buf[n] = '\0';
    String8 funcList = String8::format("\n%s", buf);

    // Make sure that every function listed in funcs is in the list we just
    // read from the kernel.
    bool ok = true;
    char* myFuncs = strdup(funcs);
    char* func = strtok(myFuncs, ",");
    while (func) {
        String8 fancyFunc = String8::format("\n%s\n", func);
        bool found = funcList.find(fancyFunc.string(), 0) >= 0;
        if (!found || func[0] == '\0') {
            fprintf(stderr, "error: \"%s\" is not a valid kernel function "
                "to trace.\n", func);
            ok = false;
        }
        func = strtok(NULL, ",");
    }
    free(myFuncs);
	return ok;
#else
    return true;
#endif
}

// Set the comma separated list of functions that the kernel is to trace.
static bool setKernelTraceFuncs(const char* funcs)
{
    bool ok = true;
    char *ptr[2];

    if (funcs == NULL || funcs[0] == '\0') {
        // Disable kernel function tracing.
        if (fileIsWritable(k_currentTracerPath)) {
            ok &= writeStr(k_currentTracerPath, "nop");
        }
        if (fileIsWritable(k_ftraceFilterPath)) {
            ok &= truncateFile(k_ftraceFilterPath);
        }
    } else {
        // Enable kernel function tracing.
        ok &= writeStr(k_currentTracerPath, "function_graph");
        ok &= setKernelOptionEnable(k_funcgraphAbsTimePath, true);
        ok &= setKernelOptionEnable(k_funcgraphCpuPath, true);
        ok &= setKernelOptionEnable(k_funcgraphProcPath, true);
        ok &= setKernelOptionEnable(k_funcgraphFlatPath, true);
        ok &= setKernelOptionEnable(k_funcgraphDurationPath, true);

        // Set the requested filter functions.
        ok &= truncateFile(k_ftraceFilterPath);
        char* myFuncs = strdup(funcs);
        char* func = strtok_r(myFuncs, ",", &ptr[0]);
        while (func) {
            ok &= appendStr(k_ftraceFilterPath, func);
            func = strtok_r(NULL, ",", &ptr[1]);
        }
        free(myFuncs);

        // Verify that the set functions are being traced.
        if (ok) {
            ok &= verifyKernelTraceFuncs(funcs);
        }
    }

    return ok;
}

// Enable tracing in the kernel.
static bool startTrace()
{
    return setTracingEnabled(true);
}

// Set all the kernel tracing settings to the desired state for this trace
// capture.
static bool setUpTrace()
{
    bool ok = true;

    // Set up the tracing options.
    ok &= setTraceOverwriteEnable(g_traceOverwrite);
#ifdef DEVICE_TYPE_TIZEN
    if(!g_append_trace) {
    	ok &= setTraceBufferSizeKB(g_traceBufferSizeKB);
	ok &= setGlobalClockEnable(true);
        ok &= setKernelTraceFuncs(g_kernelTraceFuncs);
    }
#else
    ok &= setTraceBufferSizeKB(g_traceBufferSizeKB);
    ok &= setGlobalClockEnable(true);
    ok &= setKernelTraceFuncs(g_kernelTraceFuncs);
#endif
    ok &= setPrintTgidEnableIfPresent(true);

    // Set up the tags property.
    uint64_t tags = 0;
#ifdef DEVICE_TYPE_TIZEN
    if (g_categoryEnables[TAG_NONE_IDX]) tags = TTRACE_TAG_NEVER;
    else {
#endif
    for (int i = 0; i < NELEM(k_categories); i++) {
        if (g_categoryEnables[i]) {
            const TracingCategory &c = k_categories[i];
            tags |= c.tags;
        }
    }
#ifdef DEVICE_TYPE_TIZEN
    if (tags == 0) tags |= TTRACE_TAG_ALWAYS;
}
    ok &= startTrace();
	if(!g_append_trace) {
		// For debug
		// printf("\nclear the trace\n");
		//
	    ok &= clearTrace();
	}
#endif
    ok &= setTagsProperty(tags);
    ok &= setAppCmdlineProperty(g_debugAppCmdLine);
    ok &= pokeBinderServices();

    // Disable all the sysfs enables.  This is done as a separate loop from
    // the enables to allow the same enable to exist in multiple categories.
    ok &= disableKernelTraceEvents();

    // Enable all the sysfs enables that are in an enabled category.
    for (int i = 0; i < NELEM(k_categories); i++) {
        if (g_categoryEnables[i]) {
            const TracingCategory &c = k_categories[i];
            for (int j = 0; j < MAX_SYS_FILES; j++) {
                const char* path = c.sysfiles[j].path;
                bool required = c.sysfiles[j].required == REQ;
                if (path != NULL) {
                    if (fileIsWritable(path)) {
                        ok &= setKernelOptionEnable(path, true);
                    } else if (required) {
                        fprintf(stderr, "error writing file %s\n", path);
                        ok = false;
                    }
                }
            }
        }
    }

    return ok;
}

// Reset all the kernel tracing settings to their default state.
static void cleanUpTrace()
{
    // Disable all tracing that we're able to.
    disableKernelTraceEvents();

    // Reset the system properties.
#ifndef DEVICE_TYPE_TIZEN
    setTagsProperty(0);
#endif
    setAppCmdlineProperty("");
    pokeBinderServices();

    // Set the options back to their defaults.
    setTraceOverwriteEnable(true);
    setTraceBufferSizeKB(1);
    setGlobalClockEnable(false);
    setPrintTgidEnableIfPresent(false);
    setKernelTraceFuncs(NULL);
}

// Disable tracing in the kernel.
static void stopTrace()
{
#ifdef DEVICE_TYPE_TIZEN
    setTagsProperty(0);
#endif
    setTracingEnabled(false);
}

// Read the current kernel trace and write it to stdout.
#ifdef DEVICE_TYPE_TIZEN
static void dumpTrace(bool startup)
{	
    int backup_fd = -1;
    int traceFD = open(k_tracePath, O_RDWR);

    if(startup) {
	backup_fd = open(BACKUP_TRACE, O_CREAT|O_RDWR|O_TRUNC, 0666);

    	if (backup_fd == -1) {
        	fprintf(stderr, "error opening %s: %s (%d)\n", BACKUP_TRACE,
        	strerror_r(errno, str_error, sizeof(str_error)), errno);
        	if (traceFD > -1)
        		close(traceFD);
        	return;
    	}
    }

#else
static void dumpTrace()
{
    int traceFD = open(k_tracePath, O_RDWR);
#endif
    if (traceFD == -1) {
        fprintf(stderr, "error opening %s: %s (%d)\n", k_tracePath,
                strerror_r(errno, str_error, sizeof(str_error)), errno);
#ifdef DEVICE_TYPE_TIZEN
        if (backup_fd > -1)
   		close(backup_fd);
#endif
        return;
    }

    if (g_compress) {
        z_stream zs;
        uint8_t *in, *out;
        int result, flush;

        bzero(&zs, sizeof(zs));
        result = deflateInit(&zs, Z_DEFAULT_COMPRESSION);
        if (result != Z_OK) {
            fprintf(stderr, "error initializing zlib: %d\n", result);
            close(traceFD);
#ifdef DEVICE_TYPE_TIZEN
            if (backup_fd > -1)
		close(backup_fd);
#endif
            return;
        }

        const size_t bufSize = 64*1024;
        in = (uint8_t*)malloc(bufSize);
        out = (uint8_t*)malloc(bufSize);
        if ((in == NULL) || (out == NULL)) {
        	fprintf(stderr, "Could not allocate memory");
        	if (in != NULL)
							free(in);
					if (out != NULL)
							free(out);
        	close(traceFD);
#ifdef DEVICE_TYPE_TIZEN
        	if (backup_fd > -1)
        			close(backup_fd);
#endif
        	return;
				}
        flush = Z_NO_FLUSH;

        zs.next_out = out;
        zs.avail_out = bufSize;

        do {

            if (zs.avail_in == 0) {
                // More input is needed.
                result = read(traceFD, in, bufSize);
                if (result < 0) {
                    fprintf(stderr, "error reading trace: %s (%d)\n",
                            strerror_r(errno, str_error, sizeof(str_error)), errno);
                    result = Z_STREAM_END;
                    break;
                } else if (result == 0) {
                    flush = Z_FINISH;
                } else {
                    zs.next_in = in;
                    zs.avail_in = result;
                }
            }

            if (zs.avail_out == 0) {
                // Need to write the output.
#ifdef DEVICE_TYPE_TIZEN
		if(startup)	result = write(backup_fd, out, bufSize);
		else 		result = write(STDOUT_FILENO, out, bufSize);
#else
                result = write(STDOUT_FILENO, out, bufSize);
#endif
                if ((size_t)result < bufSize) {
                    fprintf(stderr, "error writing deflated trace: %s (%d)\n",
                            strerror_r(errno, str_error, sizeof(str_error)), errno);
                    result = Z_STREAM_END; // skip deflate error message
                    zs.avail_out = bufSize; // skip the final write
                    break;
                }
                zs.next_out = out;
                zs.avail_out = bufSize;
            }

        } while ((result = deflate(&zs, flush)) == Z_OK);

        if (result != Z_STREAM_END) {
            fprintf(stderr, "error deflating trace: %s\n", zs.msg);
        }

        if (zs.avail_out < bufSize) {
            size_t bytes = bufSize - zs.avail_out;
#ifdef DEVICE_TYPE_TIZEN
    	    if(startup)		result = write(backup_fd, out, bytes);
	    else 		result = write(STDOUT_FILENO, out, bytes);
#else
            result = write(STDOUT_FILENO, out, bytes);
#endif
            if ((size_t)result < bytes) {
                fprintf(stderr, "error writing deflated trace: %s (%d)\n",
                        strerror_r(errno, str_error, sizeof(str_error)), errno);
            }
        }

        result = deflateEnd(&zs);
        if (result != Z_OK) {
            fprintf(stderr, "error cleaning up zlib: %d\n", result);
        }

        free(in);
        free(out);
    } else {
		ssize_t sent = 0;
#ifdef DEVICE_TYPE_TIZEN 
		if (startup) 
			while ((sent = sendfile(backup_fd, traceFD, NULL, 64*1024*1024)) > 0);
		else 
			while ((sent = sendfile(STDOUT_FILENO, traceFD, NULL, 64*1024*1024)) > 0);
#else
		while ((sent = sendfile(STDOUT_FILENO, traceFD, NULL, 64*1024*1024)) > 0);
#endif
		if (sent == -1) {
			fprintf(stderr, "error dumping trace: %s (%d)\n", strerror_r(errno, str_error, sizeof(str_error)),
					errno);
		}
    }

#ifdef DEVICE_TYPE_TIZEN
	if (backup_fd > -1)
		close(backup_fd);
#endif
    close(traceFD);
}

static void handleSignal(int signo)
{
    if (!g_nohup) {
        g_traceAborted = true;
    }
}

static void registerSigHandler()
{
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handleSignal;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static bool setCategoryEnable(const char* name, bool enable)
{
    for (int i = 0; i < NELEM(k_categories); i++) {
        const TracingCategory& c = k_categories[i];
        if (strcmp(name, c.name) == 0) {
            if (isCategorySupported(c)) {
                g_categoryEnables[i] = enable;
                return true;
            } else {
                if (isCategorySupportedForRoot(c)) {
                    fprintf(stderr, "error: category \"%s\" requires root "
                            "privileges.\n", name);
                } else {
                    fprintf(stderr, "error: category \"%s\" is not supported "
                            "on this device.\n", name);
                }
                return false;
            }
        }
    }
    fprintf(stderr, "error: unknown tracing category \"%s\"\n", name);
    return false;
}

static void listSupportedCategories()
{
    for (int i = 0; i < NELEM(k_categories); i++) {
#ifdef DEVICE_TYPE_TIZEN
        if(i==TAG_NONE_IDX) continue;
#endif
        const TracingCategory& c = k_categories[i];
        if (isCategorySupported(c)) {
            printf("  %10s - %s\n", c.name, c.longname);
        }
    }
}

// Print the command usage help to stderr.
static void showHelp(const char *cmd)
{
    fprintf(stderr, "usage: %s [options] [categories...]\n", cmd);
    fprintf(stderr, "options include:\n"
#ifndef DEVICE_TYPE_TIZEN
                    "  -a appname      enable app-level tracing for a comma "
                        "separated list of cmdlines\n"
#endif
                    "  -b N            use a trace buffer size of N KB\n"
                    "  -c              trace into a circular buffer\n"
                    "  -k fname,...    trace the listed kernel functions\n"
                    "  -n              ignore signals\n"
                    "  -s N            sleep for N seconds before tracing [default 0]\n"
                    "  -t N            trace for N seconds [defualt 5]\n"
                    "  -z              compress the trace dump\n"
                    "  --async_start   start circular trace and return immediatly\n"
                    "  --async_dump    dump the current contents of circular trace buffer\n"
                    "  --async_stop    stop tracing and dump the current contents of circular\n"
                    "                    trace buffer\n"
#ifdef DEVICE_TYPE_TIZEN
                    "  --append        append traces to the existing traces. do not clear the trace buffer\n"
		    "  --backup        back up the existing traces to /tmp/trace.backup and then clear the trace buffer\n"
#endif
                    "  --list_categories\n"
                    "                  list the available tracing categories\n"
            );
}

int main(int argc, char **argv)
{
    bool async = false;
    bool traceStart = true;
    bool traceStop = true;
    bool traceDump = true;

    if (argc == 2 && 0 == strcmp(argv[1], "--help")) {
        showHelp(argv[0]);
        exit(0);
    }

    for (;;) {
        int ret;
        int option_index = 0;
        static struct option long_options[] = {
            {"async_start",     no_argument, 0,  0 },
            {"async_stop",      no_argument, 0,  0 },
            {"async_dump",      no_argument, 0,  0 },
            {"list_categories", no_argument, 0,  0 },
#ifdef DEVICE_TYPE_TIZEN
            {"init_exec",	no_argument, 0,  0 },
            {"append",		no_argument, 0,  0 },
            {"backup",    	no_argument, 0,  0 },
#endif
            {           0,                0, 0,  0 }
        };
#ifndef DEVICE_TYPE_TIZEN
        ret = getopt_long(argc, argv, "a:b:ck:ns:t:z:p",
                          long_options, &option_index);
#else
		ret = getopt_long(argc, argv, "b:ck:ns:t:z",
                          long_options, &option_index);
#endif
        if (ret < 0) {
            for (int i = optind; i < argc; i++) {
                if (!setCategoryEnable(argv[i], true)) {
                    fprintf(stderr, "error enabling tracing category \"%s\"\n", argv[i]);
                    exit(1);
                }
            }
            break;
        }

        switch(ret) {
            case 'a':
                g_debugAppCmdLine = optarg;
            break;

            case 'b':
                g_traceBufferSizeKB = atoi(optarg);
            break;

            case 'c':
                g_traceOverwrite = true;
            break;

            case 'k':
                g_kernelTraceFuncs = optarg;
            break;

            case 'n':
                g_nohup = true;
            break;

            case 's':
                g_initialSleepSecs = atoi(optarg);
            break;

            case 't':
                g_traceDurationSeconds = atoi(optarg);
            break;

            case 'z':
                g_compress = true;
            break;

            case 0:
#ifdef DEVICE_TYPE_TIZEN
		if (!strcmp(long_options[option_index].name, "list_categories")) {
                    listSupportedCategories();
                    exit(0);
                }
                if (!strcmp(long_options[option_index].name, "async_start")) {
                    async = true;
                    traceStop = false;
                    traceDump = false;
                    g_traceOverwrite = true;
                } else if (!strcmp(long_options[option_index].name, "async_stop")) {
                    async = true;
                    traceStart = false;
                    traceStop = true;
                } else if (!strcmp(long_options[option_index].name, "async_dump")) {
                    async = true;
                    traceStart = false;
                    traceStop = false;
                } else if (!strcmp(long_options[option_index].name, "list_categories")) {
                    listSupportedCategories();
                    exit(0);
                } else if (!strcmp(long_options[option_index].name, "init_exec")) {
                    fprintf(stderr, "[Info] Initailize T-trace\n");
                    g_init_exec = true;
                    setTagsProperty(0);
                    exit(0);
		} else if (!strcmp(long_options[option_index].name, "append")) {
                    g_append_trace = true;
		} else if (!strcmp(long_options[option_index].name, "backup")) {
                    g_backup_trace = true;
		}
#else
            case 0:
#endif
            break;

            default:
                fprintf(stderr, "\n");
                showHelp(argv[0]);
                exit(-1);
            break;
        }
    }

    registerSigHandler();

    if (g_initialSleepSecs > 0) {
        sleep(g_initialSleepSecs);
    }

    bool ok = true;
#ifdef DEVICE_TYPE_TIZEN
    if(traceStart && g_backup_trace) {
//before start tracing by atrace, backup existig traces
		stopTrace();
    	dumpTrace(true);
    }
#endif
    if (!(async && !g_traceOverwrite)) {
	    ok &= setUpTrace();
    }
#ifndef DEVICE_TYPE_TIZEN
    ok &= startTrace();
#endif
    if (ok && traceStart) {
    	// For debug
        // printf("capturing trace...");
        //
        fflush(stdout);

        // We clear the trace after starting it because tracing gets enabled for
        // each CPU individually in the kernel. Having the beginning of the trace
        // contain entries from only one CPU can cause "begin" entries without a
        // matching "end" entry to show up if a task gets migrated from one CPU to
        // another.
#ifndef DEVICE_TYPE_TIZEN
		if(!g_append_trace) {
		// For debug
		// printf("\nclear the trace\n");
		//
	        ok = clearTrace();
		}
#endif
        if (ok && !async) {
            // Sleep to allow the trace to be captured.
            struct timespec timeLeft;
            timeLeft.tv_sec = g_traceDurationSeconds;
            timeLeft.tv_nsec = 0;
            do {
                if (g_traceAborted) {
                    break;
                }
            } while (nanosleep(&timeLeft, &timeLeft) == -1 && errno == EINTR);
        }
    }

    // Stop the trace and restore the default settings.
    if (traceStop)
        stopTrace();

    if (ok && traceDump) {
        if (!g_traceAborted) {
            printf(" done\nTRACE:\n");
            fflush(stdout);
#ifdef DEVICE_TYPE_TIZEN
	    	dumpTrace(false);
#else
            dumpTrace();
#endif
        } else {
            printf("\ntrace aborted.\n");
            fflush(stdout);
        }
        clearTrace();
    } else if (!ok) {
        fprintf(stderr, "unable to start tracing\n");
    }

    // Reset the trace buffer size to 1.
    if (traceStop)
        cleanUpTrace();

    return g_traceAborted ? 1 : 0;
}
