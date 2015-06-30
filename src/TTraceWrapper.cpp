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

#include "TTraceWrapper.h"
#include <stdio.h>

TTraceWrapper::TTraceWrapper(int tags, const char* label, ...) {
	va_list ap;
	char fmtd_label[MAX_LEN];

	tag = tags;
	va_start(ap, label);
	vsnprintf(fmtd_label, MAX_LEN, label, ap);
	
	traceBegin(tag, fmtd_label);
	va_end(ap);
}

TTraceWrapper::~TTraceWrapper() {
	traceEnd(tag);
}