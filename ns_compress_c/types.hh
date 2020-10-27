/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */

#ifndef __TYPES_HH__
#define __TYPES_HH__

#include "picojson.h"

using namespace std;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned long long ull;
typedef u32 *HVArray;
typedef picojson::object JSON;

struct proto_stats {
	u32 count;
	u64 bytes;
};

#endif /* __TYPES_HH__ */
