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

/**
 * @file trace.h
 * @brief This file contains the tracing API.
 */

#ifndef _CDBG_TIZEN_TRACE_H_
#define _CDBG_TIZEN_TRACE_H_

#include <tizen.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @addtogroup CAPI_SYSTEM_TRACE_MODULE
 * @{
 *
 */

/**
* @brief Enumeration for Trace Error.
* @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
*/
typedef enum {
	TRACE_ERROR_NONE = TIZEN_ERROR_NONE,	/**< Successful */
	TRACE_ERROR_IO_ERROR = TIZEN_ERROR_IO_ERROR	/**< I/O error */
} trace_error_e;

/**
 * @brief Writes a trace event to indicate that a synchronous event has begun.
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 * @param[in] name The name of event (optionally containing format specifiers)
 * @exception TRACE_ERROR_NONE	Success
 * @exception TRACE_ERROR_IO_ERROR	I/O error
 * @see trace_end()
 */
void trace_begin(const char *name, ...);

/**
 * @brief Writes a trace event to indicate that the synchronous event has ended.
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks trace_end() ends the most recently called trace_begin().
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 * @exception TRACE_ERROR_NONE  Success
 * @exception TRACE_ERROR_IO_ERROR      I/O error
 * @see trace_begin()
 */
void trace_end();

/**
 * @brief Writes a trace event to indicate that an asynchronous event has begun.
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 * @param[in] cookie An unique identifier for distinguishing simultaneous events
 * @param[in] name The name of event (optionally containing format specifiers)
 * @exception TRACE_ERROR_NONE	Success
 * @exception TRACE_ERROR_IO_ERROR	I/O error
 * @see trace_async_end()
 */
void trace_async_begin(int cookie, const char *name, ...);

/**
 * @brief Writes a trace event to indicate that the asynchronous event has ended.
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks trace_async_end() ends matched trace_async_begin() which has same cookie and name.
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 * @param[in] cookie An unique identifier for distinguishing simultaneous events
 * @param[in] name The name of event (optionally containing format specifiers)
 * @exception TRACE_ERROR_NONE  Success
 * @exception TRACE_ERROR_IO_ERROR      I/O error
 * @see trace_async_begin()
 */
void trace_async_end(int cookie, const char *name, ...);

/**
 * @brief Writes a trace event to track change of integer counter
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 * @param[in] value The counter value
 * @param[in] name The name of event (optionally containing format specifiers)
 * @exception TRACE_ERROR_NONE  Success
 * @exception TRACE_ERROR_IO_ERROR      I/O error
 */
void trace_update_counter(int value, const char *name, ...);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _CDBG_TIZEN_TRACE_H_ */

