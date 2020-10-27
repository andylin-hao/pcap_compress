/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */

#include <map>
#include "helper.hh"
#include "flow.hh"

using namespace std;

Header diff_headers[] = {
	IP_TOS_F,
	IP_LEN,
	IP_ID,
	IP_OFF,
	IP_TTL_F,
	IP_PROTO,
	TCP_OFF,
	TCP_FLAGS,
	TCP_WIN,
	TCP_URP,
	UDP_LEN,
};

Header delta_headers[] = {
	TS_SEC,
	TCP_SEQ,
	TCP_ACK,
};

/* FlowStats functions */
FlowStats::FlowStats() 
{
    total_compressed_bits = 0;
    total_compressed_bytes = 0;
    total_bytes = 0;
    num_packets = 0;
    max_duration_sec = 0;
}

void 
FlowStats::update(FlowStats *other) 
{
    total_compressed_bits += other->total_compressed_bits;
    total_compressed_bytes += other->total_compressed_bytes;
    total_bytes += other->total_bytes;
    num_packets += other->num_packets;
    max_duration_sec = max(max_duration_sec, other->max_duration_sec);

    add_maps(FieldsChanged, other->FieldsChanged);
    add_maps(NumCompressedFields, other->NumCompressedFields);
    add_maps(TCPSeqDeltas, other->TCPSeqDeltas);
    add_maps(TCPAckDeltas, other->TCPAckDeltas);
    add_maps(PacketsPerFlow, other->PacketsPerFlow);
}

/* Flow functions */

Flow::Flow() 
{
    first_packet_size = 0;
    compressed_size_bits = 0;
    other_packets_size = 0;
    packets = 0;
    bytes = 0;
    stats = NULL;
    memset(haprev, -1, sizeof(haprev));
    memset(hacurr, -1, sizeof(hacurr));
}

int 
Flow::add_packet(Packet &pkt, FlowStats *s) 
{
    int ret = 0;
    packets += 1;
    bytes += pkt.size;

    if (packets == 1) {
        stats = s;
        first_packet_size = pkt.size;
        first = pkt;
        prev = pkt;
        curr = pkt;
        pkt.get_headers_opt(haprev);
        ret = 1;
    } else {
        other_packets_size += pkt.size;
        prev = curr;
        memcpy(haprev, hacurr, sizeof(haprev));
        curr = pkt;
    }

    pkt.get_headers_opt(hacurr);
    return ret;
}

/* FlowKey functions */

FlowKey::FlowKey(Packet &pkt) 
{
    bzero(key, sizeof(key));
    match = (struct ofp_match *)key;
    match->nw_proto = pkt.nw_proto();

    match->nw_src = pkt.nw_src();
    match->nw_dst = pkt.nw_dst();

    match->tp_src = pkt.tp_src();
    match->tp_dst = pkt.tp_dst();

    hash();
};

void 
FlowKey::hash() 
{
    u64 *data = (u64 *)&key[0];
    hsh = data[0] ^ data[1];
}

bool 
FlowKey::operator<(const FlowKey &other) const 
{
    u64 *data0 = (u64 *)&key[0];
    u64 *data1 = (u64 *)&other.key[0];
    return data0[0] < data1[0] or (data0[0] == data1[0] and data0[1] < data1[1]);
}

bool 
FlowKey::operator==(const FlowKey &other) const 
{
    u64 *data0 = (u64 *)&key[0];
    u64 *data1 = (u64 *)&other.key[0];
    return data0[0] == data1[0] and data0[1] == data1[1];
}

void 
FlowKey::print() const 
{
    for(int i = 0; i < sizeof(key); i++) {
        printf("%02x.", key[i]);
        if ((i + 1) % 8 == 0)
            printf("  ");
    }
    printf("\n");
}

