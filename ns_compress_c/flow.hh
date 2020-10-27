/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */

#ifndef FLOW_HH
#define FLOW_HH

#include <map>
#include "types.hh"
#include "helper.hh"
#include "packet.hh"
#include "picojson.h"

#define FLOW_EXP_SEC 10
#define MAX_STATS 8

using namespace std;

/* These std::maps might be costly to update per-packet */
struct FlowStats {
	map<Header, u64> FieldsChanged;
	map<u16, u64> NumCompressedFields;
	map<u32, u64> TCPSeqDeltas;
	map<u32, u64> TCPAckDeltas;
	map<u32, u64> PacketsPerFlow;

	u64 total_compressed_bits;
	u64 total_compressed_bytes;
	u64 total_bytes;
	u64 num_packets;
	u64 max_duration_sec;

        FlowStats();
        void update(FlowStats *other);

};

struct Flow {
	u32 first_packet_size;
	u32 packets;
	u64 bytes;
	u64 other_packets_size;
	u64 compressed_size_bits;

	Packet first;
	Packet prev, curr;
	HeaderValues hprev, hcurr;
	u32 haprev[NUM_FIELDS], hacurr[NUM_FIELDS];

	FlowStats *stats;


        Flow();
	int add_packet(Packet &pkt, FlowStats *s = NULL);
	bool expired() 
        {
            return (u64)(prev.ts.tv_sec - first.ts.tv_sec) > FLOW_EXP_SEC;
	}
        u32 *get_prev_harray() 
        {
            return haprev;
        }
};

struct ofp_match {
    uint32_t nw_src;           /* IP source address. */
    uint32_t nw_dst;           /* IP destination address. */

    uint16_t tp_src;           /* TCP/UDP source port. */
    uint16_t tp_dst;           /* TCP/UDP destination port. */
    uint32_t nw_proto;          /* IP protocol or lower 8 bits of
                                 * ARP opcode. */
} __attribute__((packed));

/*
 * Ref: http://www.noxrepo.org/_/nox-doxygen/openflow-inl-1_80_8hh_source.html#l01099
 */
struct FlowKey {
    u8 key[sizeof(struct ofp_match)];
    struct ofp_match *match;
    u64 hsh;

    FlowKey() {}
    FlowKey(Packet &pkt);
    void hash();
    bool operator<(const FlowKey &other) const;
    bool operator==(const FlowKey &other) const;
    void print() const;
};

struct HashFlowKey {
    size_t operator()(const FlowKey &fkey) const {
        return fkey.hsh;
    }
};

#endif
