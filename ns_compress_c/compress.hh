/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */
#ifndef COMPRESS_H
#define COMPRESS_H

#include <cstdio>
#include <unordered_map>
#include <zlib.h>
#include <pcap.h>
#include "types.hh"
#include "packet.hh"
#include "flow.hh"
#include "helper.hh"
#include "picojson.h"
#include "cpz_zstd.h"

using namespace std;

typedef unordered_map<FlowKey, Flow, HashFlowKey> FlowHashTable;

extern u8 HEADER_WRITE_BITS[NUM_FIELDS];
extern map<Header, string> HEADER_NAMES;

struct FieldRecord {
	/* TODO: ensure endian-ness is correct. */
	u8 field_nr : 6;
	u8 value_len : 2;
	u8 field_value[0];
} __attribute__((packed));

struct DiffRecord {
	u32 packet_ref : 28;
	u32 num_changes : 4;
	FieldRecord records[0];
        void print(u32 seq);

} __attribute__((packed));


struct Compressor {
    FILE *fp_ts;
    FILE *fp_firstpkt;
    FILE *fp_diff;

    gzFile fp_ts_comp;
    gzFile fp_firstpkt_comp;
    gzFile fp_diff_comp;

    struct timeval ts_prev;
    u32 first_packet_id;

    size_t diff_size, diff_csize;
    size_t firstpkt_size, firstpkt_csize;
    size_t ts_delta_size, ts_delta_csize;

    u64 num_packets;
    u64 desc_size;

    u32 NumFieldChanged[NUM_FIELDS];
    u32 NumChangePerPacket[20];
    u64 TotalFieldBytes[NUM_FIELDS];
    u64 NumNonOneIPID;

    FlowHashTable flows;
    FlowStats flow_stats;

    Compressor();
    ~Compressor();
    void seek_end();
    void flush_compress(bool zstd=false);
    void flush(bool zstd=false);
    void close();
    double bpp_normal();
    double bpp_compress();
    void stats(JSON &j);
    template<class T> int EmitTimestamp(T *obj);
    int EmitFirstpacket(const u8 *payload, u8 caplen);
    int EmitDiffRecord(u8 *buff, int diffsize);
    FieldRecord *encode(FieldRecord *curr, Header key, u32 value, int &diffsize);
    u32 write_first_header(Packet &pkt);
    void write_time_stamp(struct timeval &ts);
    void write_diff_packet(Flow &flow, Packet &curr, int first_packet_id);
    void write_pkt(Packet &pkt);
};

struct Decompressor {

    FILE *fp_ts;
    FILE *fp_firstpkt;
    FILE *fp_diff;

    gzFile fp_ts_comp;
    gzFile fp_firstpkt_comp;
    gzFile fp_diff_comp;
    gzFile fp_out_comp;

    // Data initialized from the files.
    vector<struct timeval> ts;
    vector<Packet*> first_packets;
    struct timeval ts_first;

    // Intermediate data structures used during decompression:
    struct timeval ts_prev;
    // recent_packets stores the most recently-seen packet for each flow.
    // Required because the compressor output format gives a reference to
    // either:
    //    (1) the first packet of a flow, if nchanges is zero
    // or (2) the last-seen packet of a flow
    unordered_map<uint, Packet*> recent_packets;

    // Total no. of packets in the system (inferred from reading the timestamps)
    int num_packets;
    // Sequence no. of the next packet to be decoded
    u32 seq;

    Decompressor(int fd_ts, int fd_firstpkt, int fd_diff);
    ~Decompressor() 
    {
        close();
    }
    void close();
    void setup();
    void read_first_timestamp();
    void read_ts_deltas();
    void read_all_ts() 
    {
        read_ts_deltas();
        num_packets = ts.size();
    }
    void print_all_ts() 
    {
        EACH(it, ts) {
            print_timestamp((struct timeval) *it);
        }
    }
    inline u8 read_caplen();
    void read_one_packet();
    void read_all_first_packets();
    u64 read_nbytes(int len);
    Packet *read_one_diff(struct pcap_pkthdr* hdr);
    Packet *reconstruct_pcap(DiffRecord* diff, uint packet_index, struct pcap_pkthdr* hdr);
    Packet *read_pkt(struct pcap_pkthdr *hdr);
    void stats(JSON &json);
};

#endif