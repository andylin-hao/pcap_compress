/*
 * Copyright 2020, Tsinghua University. This file is licensed under BSD 3.0,
 * as described in included LICENSE.txt.
 *
 * Author: linh20@mails.tsinghua.eud.cn
 */

#include "cpz_gzip.h"

// gzCompress: do the compressing
int cpz_gzip(const char *file_name) {
    z_stream c_stream;
    int err = 0;
    int windowBits = 15;
    int GZIP_ENCODING = 16;
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

    c_stream.zalloc = (alloc_func) nullptr;
    c_stream.zfree = (free_func) nullptr;
    c_stream.opaque = (voidpf) nullptr;
    if (deflateInit2(&c_stream, 6, Z_DEFLATED,
                     windowBits | GZIP_ENCODING, 9, Z_DEFAULT_STRATEGY) != Z_OK)
        return -1;
    c_stream.next_in = (Bytef *) src;
    c_stream.avail_in = len;
    c_stream.next_out = (Bytef *) dest;
    c_stream.avail_out = len;

    gettimeofday(&start, &tz);
    start_time = start.tv_sec * 1000000 + start.tv_usec;
    while (c_stream.avail_in != 0 && c_stream.total_out < len) {
        if (deflate(&c_stream, Z_NO_FLUSH) != Z_OK) return -1;
    }
    if (c_stream.avail_in != 0) return c_stream.avail_in;
    for (;;) {
        if ((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END) break;
        if (err != Z_OK) {
            cout << err;
            return -1;
        }
    }
    gettimeofday(&end, &tz);
    time += (end.tv_sec * 1000000 + end.tv_usec - start_time);
    if (deflateEnd(&c_stream) != Z_OK) return -1;
    cout << "gzip compression rate: " << ((double) c_stream.total_in - c_stream.total_out) / c_stream.total_in * 100 << "%" << endl;
    cout << "gzip time consumption: " << time << " μs" << endl;
    return 1;
}