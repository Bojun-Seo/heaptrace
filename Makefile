# Copyright (c) 2022 LG Electronics Inc.
# SPDX-License-Identifier: GPL-2.0
prefix ?= /usr/local
bindir = $(prefix)/bin
libdir = $(prefix)/lib

srcdir = $(CURDIR)
# set objdir to $(O) by default (if any)
ifeq ($(objdir),)
    ifneq ($(O),)
        objdir = $(O)
    else
        objdir = $(CURDIR)
    endif
endif

ifneq ($(wildcard $(objdir)/.config),)
  include $(objdir)/.config
endif

export CC CXX LD srcdir objdir CXXFLAGS LDFLAGS

ifdef CROSS_COMPILE
  CC  := $(CROSS_COMPILE)gcc
  CXX := $(CROSS_COMPILE)g++
else
  CC  ?= gcc
  CXX ?= g++
endif

COMMON_CXXFLAGS = $(CXXFLAGS) -std=c++11 -Wno-psabi
ifeq ($(DEBUG), 1)
  COMMON_CXXFLAGS += -O0 -g
else
  COMMON_CXXFLAGS += -O2 -g
endif

LIB_CXXFLAGS := $(COMMON_CXXFLAGS) -fPIC -fno-omit-frame-pointer -fvisibility=hidden
LIB_LDFLAGS  := $(LDFLAGS) -ldl

# let the compiler record the headers each object depends on.  -MMD leaves the
# system headers out and -MP adds a phony target for each header so that
# removing one doesn't break the build with a missing prerequisite.
DEPFLAGS := -MMD -MP

ifndef $(DEPTH)
# default backtrace depth is 8
DEPTH := 8
endif
LIB_CXXFLAGS += -DDEPTH=$(DEPTH)

ifeq ($(M32), 1)
  COMMON_CXXFLAGS += -m32
  LIB_CXXFLAGS    += -m32
  LIB_LDFLAGS     += -m32
endif

TARGETS := heaptrace libheaptrace.so

# for libheaptrace.so
LIB_SRCS := src/libheaptrace.cc src/stacktrace.cc src/sighandler.cc src/utils.cc
LIB_OBJS := $(patsubst %.cc,$(objdir)/%.o,$(LIB_SRCS))
LIB_DEPS := $(LIB_OBJS:.o=.d)

# for heaptrace
HEAPTRACE_SRCS := src/heaptrace.cc
HEAPTRACE_OBJS := $(patsubst %.cc,$(objdir)/%.o,$(HEAPTRACE_SRCS))
HEAPTRACE_DEPS := $(HEAPTRACE_OBJS:.o=.d)

# build rule begin
all: $(TARGETS)
	$(MAKE) -C samples

heaptrace: $(HEAPTRACE_OBJS)
	$(QUIET_CXX)$(CXX) $(COMMON_CXXFLAGS) -o $(objdir)/$@ $(HEAPTRACE_OBJS)

$(LIB_OBJS): $(objdir)/%.o: $(srcdir)/%.cc
	$(QUIET_CXX)$(CXX) $(LIB_CXXFLAGS) $(DEPFLAGS) -c -o $@ $<

$(HEAPTRACE_OBJS): $(objdir)/%.o: $(srcdir)/%.cc
	$(QUIET_CXX)$(CXX) $(COMMON_CXXFLAGS) $(DEPFLAGS) -c -o $@ $<

libheaptrace.so: $(LIB_OBJS)
	$(QUIET_LINK)$(CXX) -shared -o $(objdir)/$@ $^ $(LIB_LDFLAGS)

install: all
	mkdir -p $(DESTDIR)$(bindir) $(DESTDIR)$(libdir)
	install -m 755 $(objdir)/heaptrace $(DESTDIR)$(bindir)/heaptrace
	install -m 755 $(objdir)/libheaptrace.so $(DESTDIR)$(libdir)/libheaptrace.so

uninstall:
	rm -f $(DESTDIR)$(bindir)/heaptrace
	rm -f $(DESTDIR)$(libdir)/libheaptrace.so

clean:
	rm -f $(objdir)/heaptrace $(objdir)/libheaptrace.so $(LIB_OBJS) $(HEAPTRACE_OBJS)
	rm -f $(LIB_DEPS) $(HEAPTRACE_DEPS)
	$(MAKE) -C samples clean

# Rebuild an object when one of the headers it includes has changed.  This is
# included at the end because the first rule of the first included file would
# become the default goal otherwise.
-include $(LIB_DEPS) $(HEAPTRACE_DEPS)
