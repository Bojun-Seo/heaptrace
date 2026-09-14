/* Copyright (c) 2022 LG Electronics Inc. */
/* SPDX-License-Identifier: GPL-2.0 */
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <cxxabi.h>
#include <dlfcn.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "heaptrace.h"
#include "utils.h"

#define SYMBOL_MAXLEN 128

namespace utils {

std::string asprintf(const char *fmt, ...)
{
	va_list args;
	std::string str;
	char *ptr;

	va_start(args, fmt);
	if (vasprintf(&ptr, fmt, args) < 0) {
		va_end(args);
		return {};
	}
	str = ptr;
	free(ptr);
	va_end(args);
	return str;
}

std::string get_comm_name(void)
{
	std::string comm;
	std::stringstream ss;

	ss << "/proc/" << utils::gettid() << "/comm";

	std::ifstream fs(ss.str());
	fs >> comm;

	return comm;
}

std::vector<std::string> string_split(const std::string &str, char delim)
{
	std::vector<std::string> vstr;
	std::stringstream ss(str);
	std::string s;

	while (getline(ss, s, delim))
		vstr.push_back(s);

	return vstr;
}

std::string get_delta_time_unit(std::chrono::nanoseconds delta)
{
	std::string str;

	auto h = std::chrono::duration_cast<std::chrono::hours>(delta);
	delta -= h;

	auto mins = std::chrono::duration_cast<std::chrono::minutes>(delta);
	delta -= mins;

	auto secs = std::chrono::duration_cast<std::chrono::seconds>(delta);
	delta -= secs;

	auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(delta);
	delta -= millis;

	auto micros = std::chrono::duration_cast<std::chrono::microseconds>(delta);
	delta -= micros;

	auto nanos = delta;

	if (h.count() > 0)
		str = utils::asprintf("%" PRId64 " hours %" PRId64 " mins", h.count(),
				      mins.count());
	else if (mins.count() > 0)
		str = utils::asprintf("%" PRId64 " mins %" PRId64 " secs", mins.count(),
				      secs.count());
	else if (secs.count() > 0)
		str = utils::asprintf("%" PRId64 ".%" PRId64 " secs", secs.count(), millis.count());
	else if (millis.count() > 0)
		str = utils::asprintf("%" PRId64 ".%" PRId64 " ms", millis.count(), micros.count());
	else if (micros.count() > 0)
		str = utils::asprintf("%" PRId64 ".%" PRId64 " us", micros.count(), nanos.count());
	else
		str = utils::asprintf("%" PRId64 " ns", nanos.count());

	return str;
}

std::string get_byte_unit(uint64_t size)
{
	std::string str;

	utils::bytes sz(size);

	auto mb = std::chrono::duration_cast<utils::megabytes>(sz);
	sz -= mb;

	auto kb = std::chrono::duration_cast<utils::kilobytes>(sz);
	sz -= kb;

	auto b = sz;

	if (mb.count() > 0)
		str = utils::asprintf("%" PRId64 ".%" PRId64 " MB", mb.count(), kb.count());
	else if (kb.count() > 0)
		str = utils::asprintf("%" PRId64 ".%" PRId64 " KB", kb.count(), b.count());
	else
		str = utils::asprintf("%" PRId64 " bytes", b.count());

	return str;
}

void get_backtrace_string(int count, void *addr, std::stringstream &ss_bt)
{
	Dl_info dlip;
	char *symbol;
	int offset;
	int status;
	int dl_ret;
	int len = SYMBOL_MAXLEN;

	ss_bt << std::dec << count << " [0x" << std::hex << std::setw(4 + __SIZEOF_LONG__)
	      << (unsigned long)addr << "] ";
	// dladdr() translates address to symbolic info.
	dl_ret = dladdr(addr, &dlip);
	if (dl_ret == 0) {
		ss_bt << "?\n";
		return;
	}

	if (dlip.dli_sname != nullptr && dlip.dli_saddr != nullptr) {
		symbol = abi::__cxa_demangle(dlip.dli_sname, nullptr, nullptr, &status);
		if (status != 0)
			symbol = strdup(dlip.dli_sname);

		if (strlen(symbol) > len) {
			symbol[len - 3] = '.';
			symbol[len - 2] = '.';
			symbol[len - 1] = '.';
			symbol[len] = '\0';
		}
		offset = static_cast<int>(static_cast<char *>(addr) -
					  static_cast<char *>(dlip.dli_saddr));
		ss_bt << symbol << " +0x" << offset << " ";
		free(symbol);
	}
	offset = (int)((char *)addr - (char *)(dlip.dli_fbase));
	ss_bt << "(" << dlip.dli_fname << " +0x" << offset << ")\n";
}

static std::vector<std::string> ignorevec;
static bool ignorevec_initialized = false;

static void lazyinit_ignorevec()
{
	if (ignorevec_initialized)
		return;

	opts.ignore = getenv("HEAPTRACE_IGNORE");
	if (opts.ignore) {
		std::ifstream file(opts.ignore);
		if (file.is_open()) {
			std::string line;
			while (std::getline(file, line)) {
				ignorevec.push_back(line);
			}
			file.close();
		}
		else {
			pr_out("Failed to open file %s\n", opts.ignore);
		}
	}
	ignorevec_initialized = true;
}

bool is_ignored(const std::string &report)
{
	lazyinit_ignorevec();
	return std::any_of(ignorevec.begin(), ignorevec.end(), [&report](const std::string &s) {
		return report.find(s) != std::string::npos;
	});
}

static enum_table ht_mmap_prot[] = {
	{ "PROT_NONE", 0 },
	{ "PROT_READ", 1 },
	{ "PROT_WRITE", 2 },
	{ "PROT_EXEC", 4 },
};

static enum_table ht_mmap_flags[] = {
	{ "MAP_SHARED", 0x1 },	      { "MAP_PRIVATE", 0x2 },	   { "MAP_FIXED", 0x10 },
	{ "MAP_ANON", 0x20 },	      { "MAP_GROWSDOWN", 0x100 },  { "MAP_DENYWRITE", 0x800 },
	{ "MAP_EXECUTABLE", 0x1000 }, { "MAP_LOCKED", 0x2000 },	   { "MAP_NORESERVE", 0x4000 },
	{ "MAP_POPULATE", 0x8000 },   { "MAP_NONBLOCK", 0x10000 }, { "MAP_STACK", 0x20000 },
	{ "MAP_HUGETLB", 0x40000 },
};

static std::string mmap_string(int val, const struct enum_table *et, int len)
{
	std::string str;

	/* exact match */
	for (int i = len - 1; i >= 0; i--) {
		if (val == et[i].val)
			return { et[i].str };
	}

	/* OR-ing bit flags */
	for (int i = len - 1; i >= 0; i--) {
		if (et[i].val <= val) {
			val -= et[i].val;
			if (!str.empty())
				str += "|";
			str += et[i].str;
		}
		if (val == 0)
			break;
	}

	return str;
}

std::string mmap_prot_string(int prot)
{
	constexpr int size = sizeof(ht_mmap_prot) / sizeof(struct enum_table);
	return mmap_string(prot, ht_mmap_prot, size);
}

std::string mmap_flags_string(int flags)
{
	constexpr int size = sizeof(ht_mmap_flags) / sizeof(struct enum_table);
	return mmap_string(flags, ht_mmap_flags, size);
}

} // namespace utils
