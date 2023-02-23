/* Copyright (c) 2022 LG Electronics Inc. */
/* SPDX-License-Identifier: GPL-2.0 */
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstring>

#include <string>
#include <sstream>
#include <fstream>
#include <vector>

#include "utils.h"

namespace utils {

static char comm[BUF_SZ] = {0, };

std::string asprintf(const char* fmt, ...)
{
	va_list args;
	std::string str;
	char *ptr;
	int ret;

	va_start(args, fmt);
	ret = vasprintf(&ptr, fmt, args);
	str = ptr;
	free(ptr);
	va_end(args);
	return str;
}

void get_comm_name(char* buf, int buf_size)
{
	FILE *fp = NULL;
	int tid;
	int len;

	if (comm[0] != '\0') {
		strncpy(buf, comm, buf_size);
		return;
	}

	tid = utils::gettid();
	memset(buf, 0, buf_size);
	snprintf(buf, buf_size, "/proc/%d/comm", tid);
	fp = fopen(buf, "r");
	if (fp == NULL) {
		printf("Failed to open %s\n", buf);
		return;
	}
	memset(buf, 0, buf_size);
	if (!fgets(buf, buf_size, fp)) {
		printf("Failed to read file %s\n", buf);
	}
	len = strlen(buf);
	if (len > 0) {
		buf[len - 1] = '\0';
	}
	strncpy(comm, buf, buf_size);
}

std::vector<std::string> string_split(std::string str, char delim)
{
	std::vector<std::string> vstr;
	std::stringstream ss(str);
	std::string s;

	while (getline(ss, s, delim))
		vstr.push_back(s);

	return vstr;
}

static enum_table ht_mmap_prot[] = {
	{ "PROT_NONE",  0 },
	{ "PROT_READ",  1 },
	{ "PROT_WRITE", 2 },
	{ "PROT_EXEC",  4 }
};

static enum_table ht_mmap_flags[] = {
	{ "MAP_SHARED",     0x1     },
	{ "MAP_PRIVATE",    0x2     },
	{ "MAP_FIXED",      0x10    },
	{ "MAP_ANON",       0x20    },
	{ "MAP_GROWSDOWN",  0x100   },
	{ "MAP_DENYWRITE",  0x800   },
	{ "MAP_EXECUTABLE", 0x1000  },
	{ "MAP_LOCKED",     0x2000  },
	{ "MAP_NORESERVE",  0x4000  },
	{ "MAP_POPULATE",   0x8000  },
	{ "MAP_NONBLOCK",   0x10000 },
	{ "MAP_STACK",      0x20000 },
	{ "MAP_HUGETLB",    0x40000 }
};

static std::string mmap_string(int val, const struct enum_table* et, int len)
{
	std::string str;

	/* exact match */
	for (int i = len - 1; i >= 0; i--) {
		if (val == et[i].val)
			return std::string(et[i].str);
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
