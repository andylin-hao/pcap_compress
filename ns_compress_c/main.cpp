/*
 * Copyright 2020, Tsinghua University. This file is licensed under BSD 3.0,
 * as described in included LICENSE.txt.
 *
 * Author: linh20@mails.tsinghua.eud.cn
 */
#include <iostream>
#include <vector>
#include <string>
#include "cpz_gzip.h"
#include "cpz_zstd.h"
#include "cpz_ns.h"


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
    vector<string> packets;

    if (argc != 2) {
        cout << "There should be one and only one file name in the given args.";
        exit(1);
    } else {
        string file_name(argv[1]);
        read_file((file_name + ".ns").c_str(), packets);
    }

    cpz_ns_gzip(packets);
    cpz_ns_zstd(packets);
    cpz_gzip(argv[1]);
    cpz_zstd(argv[1]);
}