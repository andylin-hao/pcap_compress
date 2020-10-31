/*
 * Copyright 2020, Tsinghua University. This file is licensed under BSD 3.0,
 * as described in included LICENSE.txt.
 *
 * Author: linh20@mails.tsinghua.eud.cn
 */

#ifndef NS_COMPRESS_CPZ_NS_H
#define NS_COMPRESS_CPZ_NS_H

#include <cstdio>
#include <iostream>
#include <ctime>
#include <vector>
#include <string>
#include <fstream>

#include "compress.hh"
#include "packet.hh"
#include "helper.hh"
#include "cpz_gzip.h"
#include "cpz_zstd.h"

using namespace std;

int cpz_ns_gzip(const vector<string>& packets);
int cpz_ns_zstd(const vector<string>& packets);

#endif //NS_COMPRESS_CPZ_NS_H
