//
// Created by yoda on 2020/10/31.
//

#ifndef NS_COMPRESS_CPZ_GZIP_H
#define NS_COMPRESS_CPZ_GZIP_H

#include <zlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cstring>
#include <ctime>
#include <sys/time.h>
#include "types.hh"
using namespace std;

int cpz_gzip(const char* file_name);

#endif //NS_COMPRESS_CPZ_GZIP_H
