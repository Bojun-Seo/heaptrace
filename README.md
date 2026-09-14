<!--
SPDX-FileCopyrightText: Copyright (c) 2022 LG Electronics Inc.
SPDX-License-Identifier: GPL-2.0
-->

heaptrace
=========
heaptrace is a tool that collects and reports heap allocated memory.

Approach
========
heaptrace uses widely used LD_PRELOAD technique to trace memory allocation of
the target program.

It doesn't explicitly detect memory leak, but it provides heap allocation status
information that might be a useful hint to find memory leaks.

It provides allocation info for each allocation point and it includes:
- `backtrace`   : allocation point and its backtrace (default depth is 8)
- `count`/`peak`: total allocation count and its peak count
- `size`/`peak` : total allocation size and its peak size
- `age`         : the duration time since the backtrace was created
- `summary`     : general memory allocation summary


Build and installation
======================
heaptrace can be simply compiled as follows:
```
$ make
```
The backtrace depth can be changed with a build flag `DEPTH` as follows:
```
# make DEPTH=30
```
Then heaptrace keeps maximum 30 of backtrace depth when tracing.


How to use heaptrace
====================
It provides a convenience wrapper program instread of using LD_PRELOAD
explicitly as follows:
```
$ heaptrace [<program>]
```

It traces memory allocation of the target program and dump the memory allocation
status when program is finished.  If every memory allocation is properly
deallocated, then it doesn't print anything.

There are some options as follows:
```
      --dsan                 Detect double free and report where it happened
      --dsan-abort           Abort on the first double free
      --dsan-history=NUM     Remember the last NUM freed objects (default 16384)
      --dsan-quarantine=SIZE Hold back SIZE bytes of freed memory to keep its
                             address from being reused (default 8M, 0 disables
                             it but may cause false reports)
      --flame-graph          Print heap trace info in flamegraph format
      --ignore=FILE          Apply ignore rules from this file
      --outfile=FILE         Save log messages to this file
  -s, --sort=KEY             Sort backtraces based on KEY (size or count)
      --top=NUM              Set number of top backtraces to show (default 10)
```

Here is an example usage of heaptrace.  It traces memory allocation of the
target program `node`, then prints currently live allocation info based on
each backtrace of allocation.  It shows that some of the allocated objects are
not deallocated until the program is finished.
```
$ heaptrace --top 3 --sort count /usr/bin/node --expose-gc -e 'gc()'
[heaptrace] initialized for /proc/5879/maps
[heaptrace] finalized for /proc/5879/maps
=================================================================
[heaptrace] dump allocation status for /proc/5879/maps (node)
=== backtrace #1 === [count/peak: 43/60] [size/peak: 22.704 KB/31.680 KB] [age: 6.236 ms]
 0 [0x7fe72e46476c] malloc +0x1b
 1 [0x7fe72dd61e78] operator new(unsigned long) +0x6
 2 [      0xf27811] /usr/bin/node (+0xf27811)
 3 [      0xf2e57d] v8::internal::MarkCompactCollector::RootMarkingVisitor::VisitRootPointer(v8::internal::Root, char const*, v8::internal::Objec... +0x1b
 4 [     0x121c32d] v8::internal::SerializerDeserializer::Iterate(v8::internal::Isolate*, v8::internal::RootVisitor*) +0x47
 5 [      0xf07e45] v8::internal::Heap::IterateStrongRoots(v8::internal::RootVisitor*, v8::internal::VisitMode) +0x91
 6 [      0xf40b6b] v8::internal::MarkCompactCollector::MarkLiveObjects() +0x72
 7 [      0xf42071] v8::internal::MarkCompactCollector::CollectGarbage() +0x4

=== backtrace #2 === [count/peak: 12/13] [size/peak: 6.336 KB/6.864 KB] [age: 6.400 ms]
 0 [0x7fe72e46476c] malloc +0x1b
 1 [0x7fe72dd61e78] operator new(unsigned long) +0x6
 2 [      0xf27811] /usr/bin/node (+0xf27811)
 3 [      0xf29dd4] v8::internal::MarkCompactCollector::RootMarkingVisitor::VisitRootPointers(v8::internal::Root, char const*, v8::internal::Obje... +0x29
 4 [      0xb27068] v8::internal::HandleScopeImplementer::IterateThis(v8::internal::RootVisitor*) +0x1e
 5 [      0xf07d33] v8::internal::Heap::IterateStrongRoots(v8::internal::RootVisitor*, v8::internal::VisitMode) +0x4c
 6 [      0xf40b6b] v8::internal::MarkCompactCollector::MarkLiveObjects() +0x72
 7 [      0xf42071] v8::internal::MarkCompactCollector::CollectGarbage() +0x4

=== backtrace #3 === [count/peak: 10/10] [size/peak: 5.280 KB/5.280 KB] [age: 6.322 ms]
 0 [0x7fe72e46476c] malloc +0x1b
 1 [0x7fe72dd61e78] operator new(unsigned long) +0x6
 2 [      0xf27811] /usr/bin/node (+0xf27811)
 3 [      0xf2e57d] v8::internal::MarkCompactCollector::RootMarkingVisitor::VisitRootPointer(v8::internal::Root, char const*, v8::internal::Objec... +0x1b
 4 [      0xf07f08] v8::internal::Heap::IterateStrongRoots(v8::internal::RootVisitor*, v8::internal::VisitMode) +0xc2
 5 [      0xf40b6b] v8::internal::MarkCompactCollector::MarkLiveObjects() +0x72
 6 [      0xf42071] v8::internal::MarkCompactCollector::CollectGarbage() +0x4
 7 [      0xf15621] v8::internal::Heap::MarkCompact() +0x28

[heaptrace] heap traced num of backtrace : 64
[heaptrace] heap traced allocation size  : 59.215 KB
[heaptrace] allocator info (virtual)     : 2.121 MB
[heaptrace] allocator info (resident)    : 414.288 KB
[heaptrace] statm info (VSS/RSS/shared)  : 134.201 MB / 40.960 KB / 0 bytes
=================================================================
```

It can also dump allocation status when it receives a signal as follows:
- `SIGUSR1`: dump the current allocation status with sort order by "size"
- `SIGUSR2`: dump the current allocation status with sort order by "count"

It can be useful for long running programs.


Detecting double free
=====================
The `--dsan` option enables the double free sanitizer.  Without it, a second
free of the same object is handed over to the allocator, which aborts the
program with a message that says nothing about where the object came from.
With it, heaptrace reports where the object was allocated, where it was freed
and where it was freed again:
```
$ heaptrace --dsan ./samples/sample_double_free.out
[heaptrace] initialized for /proc/4021/maps (sample_double_f)
=================================================================
[heaptrace] double free detected: 0x5618a8e714a0 (128 bytes)
=== allocated at ===
0 [0x7febe0efa246] malloc +0x86 (./libheaptrace.so +0x6246)
1 [0x56189d6281a5] alloc_buffer +0x1c (./samples/sample_double_free.out +0x11a5)
2 [0x56189d6281dc] main +0x16 (./samples/sample_double_free.out +0x11dc)
=== freed at === [tid: 4021] [age: 2.819 us]
0 [0x7febe0efa38d] free +0xcd (./libheaptrace.so +0x638d)
1 [0x56189d6281c3] free_buffer +0x1c (./samples/sample_double_free.out +0x11c3)
2 [0x56189d628202] main +0x3c (./samples/sample_double_free.out +0x1202)
=== freed again at === [tid: 4021]
0 [0x7febe0efa38d] free +0xcd (./libheaptrace.so +0x638d)
1 [0x56189d6281c3] free_buffer +0x1c (./samples/sample_double_free.out +0x11c3)
2 [0x56189d62820e] main +0x48 (./samples/sample_double_free.out +0x120e)
=================================================================
...
[heaptrace] double free detected         : 1 (1 unique)
```

The second free is not passed down to the allocator, so the program keeps
running and a single run can find more than one bug.  Use `--dsan-abort` to
stop at the first report instead.  Each place is reported only once and the
repeats are counted, so a double free inside a loop doesn't flood the log.

To be able to tell a double free from a normal free, heaptrace has to keep the
freed object out of the allocator.  Otherwise the address is handed out again
right away and the free of the new object looks like a double free of the old
one.  `--dsan-quarantine` is the amount of freed memory held back for that
reason, and `--dsan-history` is the number of freed objects remembered.  Once
an object leaves the quarantine, its memory is released and heaptrace forgets
that the address was ever freed.  Raise the two values to find a double free
that happens long after the first free, at the cost of memory.

`--dsan-quarantine=0` releases the memory immediately.  It keeps the memory
footprint unchanged, but the allocator can then hand the address out through a
path that heaptrace doesn't trace, which may be reported as a double free even
though it is not one.

`--dsan` is not free, so enable it while looking for a bug rather than leaving
it on.  The free path has to unwind the stack, which it doesn't do otherwise,
and `realloc()` is carried out as a `malloc()`, a copy and a `free()` so that
the old object can be quarantined like any other freed object.  On a loop that
allocates and frees 200000 objects of 256 bytes:

| | run time | RSS |
| --- | --- | --- |
| without `--dsan` | 185 ms | 4.6 MB |
| with `--dsan`    | 507 ms | 14.5 MB |

The memory comes from the quarantine and from the free history, which costs
about 340 bytes per remembered object.  With the default values that is up to
8 MB of quarantined memory plus about 5.5 MB of records, so lower both on a
memory constrained target.

In flamegraph mode the reports are written to stderr instead, because the
normal output carries the folded stacks and must not be mixed with anything
else.
