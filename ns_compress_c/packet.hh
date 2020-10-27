/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */

#ifndef PACKET_HH
#define PACKET_HH

#include <string>
#include <map>
#include <vector>
#include <string.h>

// IMPORTANT: This macro needs to be defined before including the netinet
// headers 
#define __FAVOR_BSD 1

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/ip_icmp.h>

#include "types.hh"

extern ulong MAX_PKT_SIZE;
extern ulong PACKET_BUFF_SIZE;
#define MORE_FRAGMENTS 0x2000
#define FRAG_OFF_MASK 0x1fff

using namespace std;

struct arp_eth_header {
    u16      ar_hrd;     /* format of hardware address   */
    u16      ar_pro;     /* format of protocol address   */
    unsigned char   ar_hln; /* length of hardware address   */
    unsigned char   ar_pln; /* length of protocol address   */
    u16      ar_op;      /* ARP opcode (command)     */

    /* Ethernet+IPv4 specific members. */
    unsigned char       ar_sha[ETHER_ADDR_LEN];   /* sender hardware address  */
    u32 sip;
    unsigned char       ar_tha[ETHER_ADDR_LEN];   /* target hardware address  */
    u32 tip;
} __attribute__((packed));

enum Header {
    TS_SEC,
    PCAP_SEQ,
    IP_PROTO,
    IP_SRC,
    IP_DST,

    TCP_SRC,
    TCP_DST,
    UDP_SRC,
    UDP_DST,

    IP_HL,

    IP_TOS_F,
    IP_LEN,
    IP_ID,
    IP_OFF,
    IP_TTL_F,
    IP_CSUM,
    TCP_SEQ,
    TCP_ACK,
    TCP_OFF,
    TCP_FLAGS,
    TCP_WIN,
    TCP_CSUM,
    TCP_URP,

    UDP_CSUM,
    UDP_LEN,

    /* This should always be at the end */
    NUM_FIELDS,
};

typedef map<Header, u64> HeaderValues;

struct Ethernet {
    u8 *dst;
    u8 *src;
    u16 vlan;
    u8 pcp;
    u16 tpid;
    u16 proto;
    const u8 *payload;

    Ethernet();
    Ethernet(const u8 *pkt);
    void update(const u8 *pkt);
    void print();
    vector<u8> pack();
    u8 pack_buf(u8* buf);
};

struct ARP {
    u16 op;
    u32 nw_src, nw_dst;

    ARP() {}
    ARP(const u8 *pkt);
};

struct IP {
    u8 v, hl, tos;
    u16 len, id, off;
    u8 ttl, proto;
    u16 csum;
    u32 src, dst;
    const u8 *payload;

    IP() {}
    IP(const u8 *pkt);
    vector<u8> pack();
    u8 pack_buf(u8* buf);
    bool is_fragment() 
    {
        return off & htons(MORE_FRAGMENTS | FRAG_OFF_MASK);
    }
    HeaderValues get_headers();
    void get_headers_opt(HVArray ret);
};

struct ICMP {
    u8 type, code;
    ICMP(){}
    ICMP(const u8* pkt);
};

struct TCP {
    u16 src, dst;
    u32 seq, ack;
    u8 off;
    u8 x2; // 4 extra reserved bits next to the offset
    u8 flags;
    u16 win;
    u16 csum;
    u16 urp;

    TCP(){}
    TCP(const u8 *pkt);
    vector<u8> pack();
    u8 pack_buf(u8* buf);
    HeaderValues get_headers();
    void get_headers_opt(HVArray ret);
};

struct UDP {
    u16 src, dst;
    u16 len, csum;

    UDP(){}
    UDP(const u8 *pkt);
    vector<u8> pack();
    u8 pack_buf(u8* buf);
    HeaderValues get_headers();
    void get_headers_opt(HVArray ret);
};

struct Packet {
    const u8 *payload;
    u8* buff = new u8[PACKET_BUFF_SIZE];
    struct timeval ts;
    Ethernet eth;
    ARP arp;
    IP ip;
    TCP tcp;
    UDP udp;
    ICMP icmp;
    u32 size;
    int seq;
    int caplen;
    int skip_ethernet;

    Packet() 
    {
        payload = buff;
    }
    Packet(const u8 *pkt, u32 sz, int skip_ethernet = 0, u32 packet_number = 0, int caplen = 0, bool do_unpack=true);
//    ~Packet() {
//        delete [] buff;
//    }

    void unpack();
    string str_hex();
    void apply_diff(Header h, u64 v);
    HeaderValues get_headers();
    uint pack(u8* buf);
    uint pack_buf(u8* buf) 
    {
        return pack_eth_buf(buf);
    }
    vector<u8> pack_eth();
    u8 pack_eth_buf(u8* buf);
    vector<u8> pack_ip();
    u8 pack_ip_buf(u8* buf);
    void unimplemented(const char* s) 
    {
        printf("Exiting; %s unimplemented", s);
        exit(EXIT_FAILURE);
    }
    vector<u8> pack_arp() 
    {
        vector<u8> packed;
        unimplemented("arp");
        return packed;
    }
    u8 pack_arp_buf(u8* buf) 
    {
        unimplemented("arp");
    }
    vector<u8> pack_udp() 
    {
        return udp.pack();
    }
    u8 pack_udp_buf(u8* buf) 
    {
        return udp.pack_buf(buf);
    }
    vector<u8> pack_tcp() 
    {
        return tcp.pack();
    }
    u8 pack_tcp_buf(u8* buf) 
    {
        return tcp.pack_buf(buf);
    }
    void get_headers_opt(HVArray ret);
    void parse_arp(const u8 *pkt) 
    {
        arp = ARP(pkt);
    }
    void parse_ip(const u8 *pkt);
    void parse_tcp(const u8 *pkt) 
    {
        tcp = TCP(pkt);
    }
    void parse_udp(const u8 *pkt) 
    {
        udp = UDP(pkt);
    }
    void parse_icmp(const u8 *pkt) 
    {
        icmp = ICMP(pkt);
    }
    u8 nw_proto();
    u32 nw_src();
    u32 nw_dst();
    u16 tp_src();
    u16 tp_dst();
    u16 infer_len();
    u16 hdr_size();
    JSON json();
};

void packet_init(); 
void update_headers(HeaderValues &a, HeaderValues &b);
void print_headers(HeaderValues &a);
void print_eth(u8* e);
void bytes_to_vector(vector<u8>* packed, u8* header, uint size);

#endif //PACKET_HH
