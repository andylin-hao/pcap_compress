/*
 * Copyright 2020, Tsinghua University. This file is licensed under BSD 3.0,
 * as described in included LICENSE.txt.
 *
 * Author: linh20@mails.tsinghua.eud.cn
 */

#include "cpz_ns.h"

int cpz_ns_gzip(const vector<string> &packets) {
    Compressor c;
    int packet_number = 0;
    size_t uncomp_size = 0;
    struct timeval start{}, end{};
    ull time = 0, start_time;
    struct timezone tz{};

    int k = 0;

    for (auto &i : packets) {
        PACKET_BUFF_SIZE = i.size() + 1;
        MAX_PKT_SIZE = PACKET_BUFF_SIZE + 4096;
        u8 *buf = new u8[PACKET_BUFF_SIZE];
        bzero(buf, PACKET_BUFF_SIZE);
        size_t buflen;
        byteify_packet(i.c_str(), buf, &buflen);
        Packet p(buf, buflen, 0, packet_number++, buflen);

        gettimeofday(&start, &tz);
        start_time = start.tv_sec * 1000000 + start.tv_usec;
        c.write_pkt(p);
        gettimeofday(&end, &tz);
        time += (end.tv_sec * 1000000 + end.tv_usec - start_time);

        uncomp_size += buflen;
        k++;
        delete[] buf;
    }
    gettimeofday(&start, &tz);
    start_time = start.tv_sec * 1000000 + start.tv_usec;
    c.flush();
    gettimeofday(&end, &tz);
    time += (end.tv_sec * 1000000 + end.tv_usec - start_time);

    size_t comp_size = c.diff_csize + c.ts_delta_csize + c.firstpkt_csize;
    cout << "netsight_gzip compression rate: " << ((double) uncomp_size - comp_size) / uncomp_size * 100 << "%" << endl;
    cout << "netsight_gzip time consumption: " << time << " μs" << endl;

    return 1;
}

int cpz_ns_zstd(const vector<string> &packets) {
    Compressor c(true);
    int packet_number = 0;
    size_t uncomp_size = 0;
    struct timeval start{}, end{};
    ull time = 0, start_time;
    struct timezone tz{};

    int k = 0;

    for (auto &i : packets) {
        PACKET_BUFF_SIZE = i.size() + 1;
        MAX_PKT_SIZE = PACKET_BUFF_SIZE + 4096;
        u8 *buf = new u8[PACKET_BUFF_SIZE];
        bzero(buf, PACKET_BUFF_SIZE);
        size_t buflen;
        byteify_packet(i.c_str(), buf, &buflen);
        Packet p(buf, buflen, 0, packet_number++, buflen);
        c.write_pkt(p);

        uncomp_size += buflen;
        k++;
        delete[] buf;
    }
    gettimeofday(&start, &tz);
    start_time = start.tv_sec * 1000000 + start.tv_usec;
    c.flush(true);
    gettimeofday(&end, &tz);
    time += (end.tv_sec * 1000000 + end.tv_usec - start_time);

    size_t comp_size = c.diff_csize + c.ts_delta_csize + c.firstpkt_csize;
    cout << "netsight_zstd compression rate: " << ((double) uncomp_size - comp_size) / uncomp_size * 100 << "%" << endl;
    cout << "netsight_zstd time consumption: " << time << " μs" << endl;

    return 1;
}