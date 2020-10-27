/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */

#ifndef __UTIL_HH__
#define __UTIL_HH__

#include <cstdio>
#include <string>
#include <zlib.h>
#include "types.hh"
#include "helper.hh"

#define BUFSIZE (10 << 20)

using namespace std;

FILE *dieopenr(int fd);
FILE *dieopenw();
gzFile compressed_read_stream(FILE *fp);
gzFile compressed_write_stream(FILE *fp);
int varint_encode(u32 value, u8 *target);
u32 varint_decode(int len, u8 *src);

#endif //__UTIL_HH__
