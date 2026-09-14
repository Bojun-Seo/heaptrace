/* SPDX-License-Identifier: GPL-2.0 */
#include <cstdio>
#include <cstdlib>

#include <chrono>
#include <map>
#include <mutex>

#include "compiler.h"
#include "dsan.h"
#include "heaptrace.h"
#include "stacktrace.h"
#include "utils.h"

struct free_info_t {
	stack_trace_t alloc_stack_trace;
	stack_trace_t free_stack_trace;
	size_t alloc_stack_depth;
	size_t free_stack_depth;
	uint64_t size;
	long tid;
	time_point_t free_time;
	// the position of this record in the free history
	uint64_t serial;
};

/*
 * The free history.  free_order holds the same records sorted by age so that
 * the oldest one is evicted first.  Both are std::map because it allocates
 * nothing in its constructor, which would be traced as a leak of libheaptrace.
 */
static std::map<addr_t, free_info_t> freemap;
static std::map<uint64_t, addr_t> free_order;
static uint64_t free_serial;

static std::recursive_mutex dsan_mutex;

static void release_oldest(void)
{
	const auto &oldest = free_order.begin();
	addr_t addr = oldest->second;

	free_order.erase(oldest);

	const auto &it = freemap.find(addr);
	if (unlikely(it == freemap.end()))
		return;

	freemap.erase(it);
}

// Once an address leaves the history, dsan can no longer tell that it was
// freed before.
static void shrink_history(void)
{
	while (!free_order.empty() && free_order.size() > opts.dsan_history)
		release_oldest();
}

void dsan_record_free(void *addr, const object_info_t &object_info, size_t alloc_depth,
		      stack_trace_t &stack_trace, int nptrs)
{
	std::lock_guard<std::recursive_mutex> lock(dsan_mutex);
	struct free_info_t free_info {};

	free_info.alloc_stack_trace = object_info.stack_trace;
	free_info.alloc_stack_depth = alloc_depth;
	free_info.free_stack_trace = stack_trace;
	free_info.free_stack_depth = nptrs;
	free_info.size = object_info.size;
	free_info.tid = utils::gettid();
	free_info.free_time = std::chrono::steady_clock::now();
	free_info.serial = free_serial++;

	freemap[addr] = free_info;
	free_order[free_info.serial] = addr;

	shrink_history();
}

void dsan_forget(void *addr)
{
	std::lock_guard<std::recursive_mutex> lock(dsan_mutex);

	const auto &it = freemap.find(addr);
	if (likely(it == freemap.end()))
		return;

	// The address is alive again, so the free record no longer applies.
	free_order.erase(it->second.serial);
	freemap.erase(it);
}

void dsan_clear(void)
{
	std::lock_guard<std::recursive_mutex> lock(dsan_mutex);

	while (!free_order.empty())
		release_oldest();

	freemap.clear();
}
