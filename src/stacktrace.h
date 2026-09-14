/* Copyright (c) 2022 LG Electronics Inc. */
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HEAPTRACE_STACKTRACE_H
#define HEAPTRACE_STACKTRACE_H

#include <cstdint>
#include <execinfo.h>

#include <array>
#include <chrono>

#include "compiler.h"
#include "heaptrace.h"

using stack_trace_t = std::array<void *, DEPTH>;
using addr_t = void *;
using time_point_t = std::chrono::steady_clock::time_point;

struct stack_info_t {
	size_t stack_depth;
	uint64_t total_size;
	uint64_t peak_total_size;
	size_t count;
	size_t peak_count;
	time_point_t birth_time;
};

struct object_info_t {
	stack_trace_t stack_trace;
	uint64_t size;
};

// What the caller of release_backtrace() should do with the given pointer.
enum class free_action_t {
	// pass the pointer to the real free()
	release,
	// heaptrace has taken the ownership of the object or has rejected the
	// free, so the caller must not release it
	skip,
};

void __record_backtrace(size_t size, void *addr, stack_trace_t &stack_trace, int nptrs);

// This is defined as a inline function to avoid having one more useless
// backtrace in the recorded stacktrace.
// Most of the work will be done inside __record_backtrace().
inline void record_backtrace(size_t size, void *addr)
{
	int nptrs;
	stack_trace_t stack_trace{};

	if (unlikely(!addr))
		return;

	nptrs = backtrace(stack_trace.data(), DEPTH);
	__record_backtrace(size, addr, stack_trace, nptrs);
}

free_action_t __release_backtrace(void *addr, stack_trace_t &stack_trace, int nptrs);

// This is defined as an inline function for the same reason as
// record_backtrace().  The backtrace of the free point is only used by the
// dsan feature, so it is not collected unless dsan is enabled.
inline free_action_t release_backtrace(void *addr)
{
	int nptrs = 0;
	stack_trace_t stack_trace{};

	if (unlikely(!addr))
		return free_action_t::release;

	if (opts.dsan)
		nptrs = backtrace(stack_trace.data(), DEPTH);

	return __release_backtrace(addr, stack_trace, nptrs);
}

// Tell the recorded size of a live object.  It returns false when the given
// address is not tracked by heaptrace.
bool get_object_size(void *addr, size_t *size);

void dump_stackmap(const char *sort_keys, bool flamegraph = false);

void clear_stackmap(void);

#endif /* HEAPTRACE_STACKTRACE_H */
