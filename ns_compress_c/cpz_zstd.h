/*
 * Copyright 2020, Tsinghua University. This file is licensed under BSD 3.0,
 * as described in included LICENSE.txt.
 *
 * Author: linh20@mails.tsinghua.eud.cn
 */

#ifndef NS_COMPRESS_CPZ_ZSTD_H
#define NS_COMPRESS_CPZ_ZSTD_H

#include <zstd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cstring>
#include <ctime>
#include <sys/time.h>
#include <unistd.h>
#include "types.hh"

using namespace std;

int cpz_zstd(const char* file_name);
int cpz_zstd_file(FILE* file);

#endif //NS_COMPRESS_CPZ_ZSTD_H
