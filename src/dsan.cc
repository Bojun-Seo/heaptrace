/* SPDX-License-Identifier: GPL-2.0 */
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <chrono>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>

#include "compiler.h"
#include "dsan.h"
#include "heaptrace.h"
#include "stacktrace.h"
#include "utils.h"

// Reading this pattern back is a hint of a use after free.
#define DSAN_POISON_BYTE 0x5a

// A report goes to stderr in flamegraph mode because outfp carries the
// folded stacks there and must not be mixed with anything else.
#define pr_report(fmt, ...) fprintf(opts.flamegraph ? stderr : outfp, fmt, ##__VA_ARGS__)

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
	bool quarantined;
};

/*
 * The free history.  free_order holds the same records sorted by age so that
 * the oldest one is evicted first.  Both are std::map because it allocates
 * nothing in its constructor, which would be traced as a leak of libheaptrace.
 */
static std::map<addr_t, free_info_t> freemap;
static std::map<uint64_t, addr_t> free_order;
static uint64_t free_serial;

// A place that has freed an object twice, keyed by its backtrace.
struct report_info_t {
	size_t count;
	bool ignored;
};

static std::map<stack_trace_t, report_info_t> reportmap;

static uint64_t quarantine_size;
static size_t double_free_count;
static size_t ignored_count;

static real_free_fn_t real_free_fn;

static std::recursive_mutex dsan_mutex;

void dsan_init(real_free_fn_t fn)
{
	real_free_fn = fn;
}

static void release_oldest(void)
{
	const auto &oldest = free_order.begin();
	addr_t addr = oldest->second;

	free_order.erase(oldest);

	const auto &it = freemap.find(addr);
	if (unlikely(it == freemap.end()))
		return;

	if (it->second.quarantined) {
		quarantine_size -= it->second.size;
		if (likely(real_free_fn != nullptr))
			real_free_fn(addr);
	}

	freemap.erase(it);
}

// Once an address leaves the history, dsan can no longer tell that it was
// freed before.
static void shrink_history(void)
{
	while (!free_order.empty() &&
	       (free_order.size() > opts.dsan_history || quarantine_size > opts.dsan_quarantine))
		release_oldest();
}

// Returns false when the --ignore rules cover the report.
static bool print_report(void *addr, const free_info_t &free_info, stack_trace_t &stack_trace,
			 int nptrs)
{
	const time_point_t current = std::chrono::steady_clock::now();
	std::stringstream ss;

	ss << std::setfill('0');

	ss << "=== allocated at ===\n";
	for (int i = 0; i < free_info.alloc_stack_depth; i++)
		utils::get_backtrace_string(i, free_info.alloc_stack_trace[i], ss);

	ss << std::dec << "=== freed at === [tid: " << free_info.tid
	   << "] [age: " << utils::get_delta_time_unit(current - free_info.free_time) << "]\n";
	for (int i = 0; i < free_info.free_stack_depth; i++)
		utils::get_backtrace_string(i, free_info.free_stack_trace[i], ss);

	ss << std::dec << "=== freed again at === [tid: " << utils::gettid() << "]\n";
	for (int i = 0; i < nptrs; i++)
		utils::get_backtrace_string(i, stack_trace[i], ss);

	if (utils::is_ignored(ss.str()))
		return false;

	pr_report("=================================================================\n");
	pr_report("[heaptrace] double free detected: %p (%s)\n", addr,
		  utils::get_byte_unit(free_info.size).c_str());
	pr_report("%s", ss.str().c_str());
	pr_report("=================================================================\n");
	fflush(opts.flamegraph ? stderr : outfp);

	return true;
}

bool dsan_is_freed(void *addr)
{
	std::lock_guard<std::recursive_mutex> lock(dsan_mutex);

	return freemap.find(addr) != freemap.end();
}

bool dsan_report_double_free(void *addr, stack_trace_t &stack_trace, int nptrs)
{
	std::lock_guard<std::recursive_mutex> lock(dsan_mutex);

	const auto &it = freemap.find(addr);
	// heaptrace doesn't track every allocation, so a missing record is no
	// evidence of a double free.
	if (likely(it == freemap.end()))
		return false;

	// Report each place once and count the repeats.  An ignored place is
	// counted apart so that the summary doesn't claim an unseen report.
	report_info_t &report = reportmap[stack_trace];
	if (report.count++ == 0)
		report.ignored = !print_report(addr, it->second, stack_trace, nptrs);

	if (report.ignored) {
		ignored_count++;
		return true;
	}

	double_free_count++;

	if (opts.dsan_abort)
		abort();

	return true;
}

free_action_t dsan_record_free(void *addr, const object_info_t &object_info, size_t alloc_depth,
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
	free_info.quarantined = opts.dsan_quarantine > 0;

	if (free_info.quarantined) {
		/*
		 * The allocator could hand the address out again through a
		 * path heaptrace doesn't hook, and the free of that new object
		 * would look like a double free of this one.
		 */
		memset(addr, DSAN_POISON_BYTE, free_info.size);
		quarantine_size += free_info.size;
	}

	freemap[addr] = free_info;
	free_order[free_info.serial] = addr;

	shrink_history();

	return free_info.quarantined ? free_action_t::skip : free_action_t::release;
}

void dsan_forget(void *addr)
{
	std::lock_guard<std::recursive_mutex> lock(dsan_mutex);

	const auto &it = freemap.find(addr);
	if (likely(it == freemap.end()))
		return;

	// Only reachable with the quarantine off, the one case where a freed
	// address is given back to the allocator.
	if (it->second.quarantined)
		quarantine_size -= it->second.size;

	free_order.erase(it->second.serial);
	freemap.erase(it);
}

void dsan_dump_summary(void)
{
	auto *tfs = &thread_flags;
	size_t unique = 0;

	std::lock_guard<std::recursive_mutex> lock(dsan_mutex);

	if (double_free_count == 0 && ignored_count == 0)
		return;

	// Printing can allocate, and the allocation hook takes the container
	// lock, which is taken before this one everywhere else.
	tfs->hook_guard = true;

	for (const auto &p : reportmap) {
		if (!p.second.ignored)
			unique++;
	}

	// the allocation dump above is skipped when nothing is left alive
	pr_report("=================================================================\n");
	if (double_free_count > 0)
		pr_report("[heaptrace] double free detected         : %zd (%zd unique)\n",
			  double_free_count, unique);
	if (ignored_count > 0)
		pr_report("[heaptrace] double free ignored          : %zd\n", ignored_count);
	pr_report("=================================================================\n");
	fflush(opts.flamegraph ? stderr : outfp);

	tfs->hook_guard = false;
}

void dsan_clear(void)
{
	std::lock_guard<std::recursive_mutex> lock(dsan_mutex);

	while (!free_order.empty())
		release_oldest();

	freemap.clear();
	reportmap.clear();
	quarantine_size = 0;
	double_free_count = 0;
	ignored_count = 0;
}
