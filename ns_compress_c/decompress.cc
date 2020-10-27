/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */

#include <map>
#include <unordered_map>
#include <functional>
#include <string>
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <limits.h>
#include <zlib.h>
#include <pcap.h>

/* Simple json: just a header file
 * Github: https://github.com/kazuho/picojson
 * Examples: http://mbed.org/users/mimil/code/PicoJSONSample/docs/81c978de0e2b/main_8cpp_source.html
 */
#include "picojson.h"

#include "types.hh"
#include "flow.hh"
#include "packet.hh"
#include "helper.hh"
#include "compress.hh"
#include "util.hh"

#define MAX_DIFF_SIZE (100)

using namespace std;

u64 MAX_PACKETS = ~0;

extern map<u16, string> ETHERTYPE_TO_STRING;
extern map<u16, string> IPPROTO_TO_STRING;

/* Decompressor functions */

Decompressor::Decompressor(int fd_ts, int fd_firstpkt, int fd_diff) 
{

    fp_ts = dieopenr(fd_ts);
    fp_ts_comp = compressed_read_stream(fp_ts);

    fp_firstpkt = dieopenr(fd_firstpkt);
    fp_firstpkt_comp = compressed_read_stream(fp_firstpkt);

    fp_diff = dieopenr(fd_diff);
    fp_diff_comp = compressed_read_stream(fp_diff);
    printf("Opened compressed_read_streams\n");

    seq = 0;
    setup();
}

void 
Decompressor::close() 
{
    if (fp_ts) fclose(fp_ts);
    if (fp_firstpkt) fclose(fp_firstpkt);
    if (fp_diff) fclose(fp_diff);
    fp_ts = NULL;
    fp_firstpkt = NULL;
    fp_diff = NULL;

}

void 
Decompressor::setup() 
{
    read_first_timestamp();
    printf("read_first_timestamp\n");
    read_all_ts();
    printf("read_all_ts\n");
    read_all_first_packets();
    printf("read_all_first_packets\n");
}

Packet *
Decompressor::read_pkt(struct pcap_pkthdr *hdr)
{
    return read_one_diff(hdr);
}

void 
Decompressor::read_first_timestamp() 
{
    int bytes_read;
    bytes_read = gzread (fp_ts_comp, &ts_first, sizeof ts_first);
    ts_prev = ts_first;
    assert (bytes_read == sizeof ts_first);
    ts.push_back(ts_first);
    printf("first_ts: ");
    print_timestamp(ts_first);
}

void
Decompressor::read_ts_deltas() 
{
    // Code derives from:
    //http://www.lemoda.net/c/gzfile-read/index.html
    if (!fp_ts_comp) {
        ERR("gzopen of ts memstream failed: %s.\n", 
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    int counter = 0;
    while (true) {
        int err;
        int bytes_read;
        u32 delta;
        bytes_read = gzread(fp_ts_comp, &delta, sizeof delta);
        counter++;
        if (bytes_read < (int) (sizeof delta)) {
            if (gzeof(fp_ts_comp)) {
                break;
            } 
            else {
                const char * error_string;
                error_string = gzerror(fp_ts_comp, &err);
                if (err) {
                    ERR("Error: %s.\n", error_string);
                    exit (EXIT_FAILURE);
                }
            }
        }
        assert(bytes_read == sizeof delta);
        ts_prev.tv_usec += delta;
        while (ts_prev.tv_usec >= USEC_PER_SEC) {
            ts_prev.tv_usec -= USEC_PER_SEC;
            ts_prev.tv_sec += 1;
        }
        ts.push_back(ts_prev);
    }
    printf("\n");
}

inline u8 
Decompressor::read_caplen() 
{
    u8 caplen;
    int bytes_read;
    bytes_read = gzread(fp_firstpkt_comp, &caplen, sizeof caplen);

    if (!gzeof(fp_firstpkt_comp)) {
        assert(bytes_read == sizeof caplen);
        return caplen;
    } else {
        return -1;
    }
}

void 
Decompressor::read_one_packet() 
{
    static int nr = 0;
    int caplen = read_caplen();
    if (caplen == 255)
        return;

    u8* buf = new u8[MAX_PKT_SIZE];
    int bytes_read;
    bytes_read = gzread(fp_firstpkt_comp, buf, caplen);
    assert(bytes_read == caplen);
    int SKIP_ETHERNET = 0;
    Packet *pkt = new Packet(buf, caplen, SKIP_ETHERNET, nr++, caplen);
    first_packets.push_back(pkt);
    delete [] buf;
}

void 
Decompressor::read_all_first_packets() 
{
    while (!gzeof(fp_firstpkt_comp)) {
        read_one_packet();
    }
    printf("%u first packets\n", (u32)first_packets.size());
}

u64 
Decompressor::read_nbytes(int len) 
{
    u64 ret = 0;
    if (len == 0)
        return 0;
    int bytes_read;
    bytes_read = gzread(fp_diff_comp, &ret, len);

    if (bytes_read != len) {
        printf("Failed after reading %d (bits=%d) field records\n",
                seq, len * 8);
    }
    assert(bytes_read == len);
    return ret;
}

Packet *
Decompressor::read_one_diff(struct pcap_pkthdr* hdr) 
{
    Packet *p = NULL;
    char buf[MAX_DIFF_SIZE];
    DiffRecord *diff = (DiffRecord *)(&buf[0]);
    FieldRecord *field = diff->records;
    int bytes_read;
    bytes_read = gzread(fp_diff_comp, buf, sizeof(struct DiffRecord));
    int offset = 0;

    if (gzeof(fp_diff_comp))
        return p;

    assert(bytes_read == sizeof(struct DiffRecord));

    /* First packet of flow */
    if (diff->num_changes == FIRST_PACKET_ENCODE)
        goto done;

    for(int i = 0; i < diff->num_changes; i++) {
        FieldRecord *field = (FieldRecord *)((u8 *)diff->records + offset);
        u8 *byte = (u8 *)field;
        *byte = read_nbytes(1);
        int len;
        u32 value;

        /* We use varint encoding with length packed
         * in field->value_len
         * len 1 -> 00 - binary
         * len 2 -> 01
         * len 3 -> 10
         * len 4 -> 11
         */
        len = (field->value_len + 1);
        Header key = static_cast<Header>(field->field_nr);
        value = read_nbytes(len);
        offset += 1 + len;
        assert (0 <= field->value_len and field->value_len <= 3);
        memcpy(field->field_value, &value, len);
    }

done:

    p = reconstruct_pcap(diff, seq, hdr);
    seq++;
    return p;
}

Packet *
Decompressor::reconstruct_pcap(DiffRecord* diff, uint packet_index, struct pcap_pkthdr* hdr) 
{
    Packet *p;
    timeval t;
    uint16_t packet_len; // original len - make this up?

    assert(diff->packet_ref < ts.size());

    t = ts[packet_index];

    if (diff->num_changes == FIRST_PACKET_ENCODE) {
        // If there are no diffs, the packet_ref refers to a first_pkt.
        p = first_packets[diff->packet_ref];
    }
    else {
        // iterate through each change, modifying packet.
        int offset = 0;

        // If there are diffs, they are relative to a previously seen
        // (and stored) packet in the recent_packets table.
        printf("first_packets: %d\n", diff->packet_ref);
        Packet *pkt_ref = first_packets[diff->packet_ref];
        p = new Packet(pkt_ref->buff, pkt_ref->skip_ethernet, 
                pkt_ref->caplen, packet_index);

        for (int i = 0; i < diff->num_changes; i++) {
            FieldRecord *field = (FieldRecord*)(((u8 *)diff->records) + offset);
            int field_nr = field->field_nr;
            Header key = static_cast<Header>(field_nr);
            u32 value = 0;
            int len;

            len = field->value_len + 1;
            printf("varint_decode\n");
            value = varint_decode(len, field->field_value);
            offset += 1 + len;

            printf("apply_diff\n");
            p->apply_diff(key, value);
        }
    }

    printf("recent_packets.insert\n");
    recent_packets.insert(make_pair(seq, p));

    // Remove previous packet in this flow, which should never be
    // referenced again if the compressor is correctly implemented
    if (diff->num_changes != FIRST_PACKET_ENCODE) {
        printf("recent_packets.erase\n");
        recent_packets.erase(diff->packet_ref);
    }

    if(hdr) {
        hdr->ts = t;
        hdr->caplen = p->hdr_size();
        hdr->len = p->infer_len();
    }

    return p;
}

void 
Decompressor::stats(JSON &json) 
{
}

