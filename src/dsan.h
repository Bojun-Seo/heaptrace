/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HEAPTRACE_DSAN_H
#define HEAPTRACE_DSAN_H

#include "stacktrace.h"

void dsan_record_free(void *addr, const object_info_t &object_info, size_t alloc_depth,
		      stack_trace_t &stack_trace, int nptrs);

// Forget the free record of an address that got allocated again.
void dsan_forget(void *addr);

void dsan_clear(void);

#endif /* HEAPTRACE_DSAN_H */
