/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HEAPTRACE_DSAN_H
#define HEAPTRACE_DSAN_H

#include "stacktrace.h"

// dsan releases the objects it quarantines, so it needs the real free().
using real_free_fn_t = void (*)(void *);

void dsan_init(real_free_fn_t fn);

bool dsan_is_freed(void *addr);

// Returns false when the address has no free record.
bool dsan_report_double_free(void *addr, stack_trace_t &stack_trace, int nptrs);

free_action_t dsan_record_free(void *addr, const object_info_t &object_info, size_t alloc_depth,
			       stack_trace_t &stack_trace, int nptrs);

// Forget the free record of an address that got allocated again.
void dsan_forget(void *addr);

void dsan_dump_summary(void);

void dsan_clear(void);

#endif /* HEAPTRACE_DSAN_H */
