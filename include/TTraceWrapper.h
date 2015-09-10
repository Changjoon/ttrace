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

#ifndef __TTRACE_WRAPPER_H_
#define __TTRACE_WRAPPER_H_

#define MAX_LEN 512

#include <ttrace.h>
#include <stdarg.h>
#include <stdint.h>

class TTraceWrapper {
	private:
		uint64_t tag;
	public:
		TTraceWrapper(uint64_t tags, const char* label, ...);
		~TTraceWrapper();
};

#define TTRACE(tags, label, args...)	TTraceWrapper ttrace(tags, label, ##args)

#endif

