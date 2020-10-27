/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */
#include <cstdio>
#include <iostream>
#include <ctime>
#include <vector>
#include <string>
#include <fstream>

#include "compress.hh"
#include "packet.hh"
#include "helper.hh"


using namespace std;

ulong PACKET_BUFF_SIZE;
ulong MAX_PKT_SIZE;

void read_file(const char *file_name, vector<string> &packets) {
    ifstream in(file_name);
    if (!in.is_open()) {
        cout << "Error opening file";
        exit(1);
    }

    string tmp;
    while (getline(in, tmp)) {
        packets.push_back(tmp);
    }
}

int main(int argc, char *argv[]) {
    Compressor c;
    int packet_number = 0;
    size_t uncomp_size = 0;
    struct timeval start{}, end{};
    struct timezone tz{};
    int k = 0;
    vector<string> packets;

    if (argc != 2) {
        cout << "There should be one and only one file name in the given args.";
        exit(1);
    } else {
        read_file(argv[1], packets);
    }

    for (auto &i : packets) {
        PACKET_BUFF_SIZE = i.size() + 1;
        MAX_PKT_SIZE = PACKET_BUFF_SIZE + 4096;
        u8* buf = new u8[PACKET_BUFF_SIZE];
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
    c.flush();
    gettimeofday(&end, &tz);
    size_t comp_size = c.diff_csize + c.ts_delta_csize + c.firstpkt_csize;
    cout << "netsight compression rate: " << ((double) uncomp_size - comp_size) / uncomp_size * 100 << "%" << endl;
    cout << "netsight time consumption: " << ((double) end.tv_usec - start.tv_usec) << " μs" << endl;
}