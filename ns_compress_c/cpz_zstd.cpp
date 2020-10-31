/*
 * Copyright 2020, Tsinghua University. This file is licensed under BSD 3.0,
 * as described in included LICENSE.txt.
 *
 * Author: linh20@mails.tsinghua.eud.cn
 */

#include "cpz_zstd.h"


int cpz_zstd(const char* file_name)
{
    string tmp;
    char *dest, *src;
    struct timeval start{}, end{};
    struct timezone tz{};
    ull time = 0, start_time;

    ifstream in(file_name, ios::in | ios::binary);
    if (!in.is_open()) {
        cout << "Error opening file";
        exit(1);
    }
    stringstream ss;
    ss << in.rdbuf();
    tmp = ss.str();
    int len = tmp.length();
    src = new char[len];
    memcpy(src, tmp.c_str(), len * sizeof(char));
    dest = new char[len];

    gettimeofday(&start, &tz);
    start_time = start.tv_sec * 1000000 + start.tv_usec;
    size_t const c_size = ZSTD_compress(dest, len, src, len, 15);
    gettimeofday(&end, &tz);
    time += (end.tv_sec * 1000000 + end.tv_usec - start_time);
    cout << "zstandard compression rate: " << ((double) len - c_size) / len * 100 << "%" << endl;
    cout << "zstandard time consumption: " << time << " μs" << endl;
    return 1;
}

int cpz_zstd_file(FILE* file)
{
    char *dest, *src;

    fseek(file, 0L, SEEK_END);
    size_t len = ftell(file);
    rewind(file);
    src = new char[len];
    dest = new char[len];

    if (fread(src, 1, len, file) != len) {
        cout << "ERROR READ" << endl;
    }

    size_t const c_size = ZSTD_compress(dest, len, src, len, 5);

    ftruncate(fileno(file), 0);
    fseek(file, 0L, SEEK_SET);
    fwrite(dest, 1, c_size, file);
    return 1;
}