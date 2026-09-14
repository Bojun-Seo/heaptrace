/* Copyright (c) 2022 LG Electronics Inc. */
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HEAPTRACE_UTILS_H
#define HEAPTRACE_UTILS_H

#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sys/syscall.h>
#include <unistd.h>

#include <chrono>
#include <sstream>
#include <string>
#include <vector>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

namespace utils {

typedef std::chrono::duration<uint64_t> bytes;
typedef std::chrono::duration<uint64_t, std::kilo> kilobytes;
typedef std::chrono::duration<uint64_t, std::mega> megabytes;
typedef std::chrono::duration<uint64_t, std::giga> gigabytes;

static long gettid(void)
{
	return syscall(SYS_gettid);
}

// Convert a size string that optionally ends with a K, M or G unit suffix.
// It returns false and leaves *size alone when the string is not a size, so
// that a typo doesn't silently turn into 0.  It is defined here to be usable
// from the heaptrace binary, which doesn't link utils.cc.
static inline bool parse_size(const char *str, uint64_t *size)
{
	char *unit = nullptr;
	uint64_t mult = 1;
	uint64_t val;

	// strtoull() accepts a leading minus and wraps it around, so a
	// negative value has to be rejected before it is parsed
	while (isspace(*str))
		str++;
	if (*str == '-')
		return false;

	errno = 0;
	val = strtoull(str, &unit, 0);
	if (errno != 0 || unit == str)
		return false;

	switch (*unit) {
	case 'k':
	case 'K':
		mult = 1024;
		unit++;
		break;
	case 'm':
	case 'M':
		mult = 1024 * 1024;
		unit++;
		break;
	case 'g':
	case 'G':
		mult = 1024 * 1024 * 1024;
		unit++;
		break;
	default:
		break;
	}

	// reject trailing garbage and an overflowing unit conversion
	if (*unit != '\0' || val > UINT64_MAX / mult)
		return false;

	*size = val * mult;

	return true;
}

std::string asprintf(const char *fmt, ...);

std::string get_comm_name(void);

std::vector<std::string> string_split(const std::string &str, char delim);

std::string get_delta_time_unit(std::chrono::nanoseconds delta);

std::string get_byte_unit(uint64_t size);

// Translate the given address to symbolic info and append it to ss_bt.
void get_backtrace_string(int count, void *addr, std::stringstream &ss_bt);

// Tell whether the given report matches one of the rules given by --ignore.
bool is_ignored(const std::string &report);

struct enum_table {
	const char *str;
	int val;
};

std::string mmap_prot_string(int prot);
std::string mmap_flags_string(int flags);

} // namespace utils

#endif /* HEAPTRACE_UTILS_H */
