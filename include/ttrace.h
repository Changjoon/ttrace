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

#ifndef _CDBG_TIZEN_TTRACE_H_
#define _CDBG_TIZEN_TTRACE_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Define TTRACE_TAG */
#define TTRACE_TAG_NEVER               0       // This tag is never enabled.
#define TTRACE_TAG_ALWAYS              (1<<0)  // This tag is always enabled.
#define TTRACE_TAG_GRAPHICS            (1<<1)
#define TTRACE_TAG_INPUT               (1<<2)
#define TTRACE_TAG_VIEW                (1<<3)
#define TTRACE_TAG_WEB                 (1<<4)
#define TTRACE_TAG_WINDOW_MANAGER      (1<<5)
#define TTRACE_TAG_APPLICATION_MANAGER (1<<6)
#define TTRACE_TAG_IMAGE               (1<<7)
#define TTRACE_TAG_AUDIO               (1<<8)
#define TTRACE_TAG_VIDEO               (1<<9)
#define TTRACE_TAG_CAMERA              (1<<10)
#define TTRACE_TAG_HAL                 (1<<11)
#define TTRACE_TAG_MEDIA_CONTENT       (1<<12)
#define TTRACE_TAG_MEDIA_DB            (1<<13)
#define TTRACE_TAG_SCREEN_MIRRORING    (1<<14)
#define TTRACE_TAG_APP                 (1<<15)
#define TTRACE_TAG_LAST                TTRACE_TAG_APP

#define ENABLED_TAG_FILE "/etc/ttrace/ttrace_tag"
void traceBegin(int tag, const char *name, ...);
void traceEnd(int tag);
void traceAsyncBegin(int tag, int cookie, const char *name, ...);
void traceAsyncEnd(int tag, int cookie, const char *name, ...);
void traceMark(int tag, const char *name, ...);
void traceCounter(int tag, int value, const char *name, ...);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _CDBG_TIZEN_TTRACE_H_ */

