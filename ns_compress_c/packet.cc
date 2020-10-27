/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */

#include "packet.hh"
#include "helper.hh"
#include "types.hh"

/* Local variables */
map<u16, string> ETHERTYPE_TO_STRING;
map<u16, string> IPPROTO_TO_STRING;
map<Header, u16> HEADER_SIZE_BITS;
map<Header, string> HEADER_NAMES;
u8 HEADER_WRITE_BITS[NUM_FIELDS];


/* Ethernet functions */

Ethernet::Ethernet() 
{
    dst = (u8 *)"\x00\x00\x00\x00\x00\x00";
    src = dst;
    vlan = 0;
    pcp = 0;
    tpid = 0;
}

Ethernet::Ethernet(const u8 *pkt) 
{
    update(pkt);
    vlan = pcp = 0;
    u32 offset = sizeof(ether_header);

    if (proto == ETHERTYPE_VLAN) {
        tpid = proto;
        vlan = ntohs(*(const u16 *) (pkt + offset));
        pcp = (vlan & 0xf000) >> 12;
        vlan = (vlan & 0x0fff);
        offset += 2;
        proto = ntohs(*(const u16 *) (pkt + offset));
        offset += 2;
    }

    payload = pkt + offset;
    //print();
}

void 
Ethernet::update(const u8 *pkt) 
{
    struct ether_header *eth = (struct ether_header *)pkt;
    dst = eth->ether_dhost;
    src = eth->ether_shost;
    proto = ntohs(eth->ether_type);
}

void 
Ethernet::print() 
{
    printf("Eth: ");
    print_eth(dst);
    printf(" ");
    print_eth(src);
    printf(" ");
    printf("0x%x\n", proto);
}

vector<u8> 
Ethernet::pack() 
{
    ether_header eh;
    memcpy(&eh.ether_dhost, dst, sizeof eh.ether_dhost);
    memcpy(&eh.ether_shost, src, sizeof eh.ether_shost);
    eh.ether_type = htons(proto);

    vector<u8> packed;
    for (int i = 0; i < sizeof(ether_header); i++) {
        packed.push_back(*((const u8*) &eh + i));
    }

    assert(packed.size() == sizeof(ether_header));
    return packed;
}

u8 
Ethernet::pack_buf(u8* buf) 
{
    ether_header eh;
    memcpy(&eh.ether_dhost, dst, sizeof eh.ether_dhost);
    memcpy(&eh.ether_shost, src, sizeof eh.ether_shost);
    eh.ether_type = htons(proto);
    memcpy(buf, &eh, sizeof(ether_header));
    return sizeof(eh);
}

/* ARP functions */

ARP::ARP(const u8 *pkt) 
{
    struct arp_eth_header *arp = (struct arp_eth_header *)pkt;
    op = ntohs(arp->ar_op);

    if (ntohs(arp->ar_pro) == ETHERTYPE_IP
            && arp->ar_pln == 4) { /* ipv4 */
        nw_src = ntohl(arp->sip);
        nw_dst = ntohl(arp->tip);
    }
}

/* IP functions */

IP::IP(const u8 *pkt) 
{
    const struct ip *ip = (const struct ip *)pkt;
    v = ip->ip_v;
    hl = ip->ip_hl;
    tos = ip->ip_tos;
    len = ntohs(ip->ip_len);
    id = ntohs(ip->ip_id);
    off = ntohs(ip->ip_off);
    ttl = ip->ip_ttl;
    proto = ip->ip_p;
    csum = ntohs(ip->ip_sum);
    src = ntohl(ip->ip_src.s_addr);
    dst = ntohl(ip->ip_dst.s_addr);
    payload = pkt + (ip->ip_hl * 4);
}

vector<u8> 
IP::pack() 
{
    struct ip ih;
    ih.ip_v = v;
    ih.ip_hl = hl;
    ih.ip_tos = tos;
    ih.ip_len = htons(len);
    ih.ip_id = htons(id);
    ih.ip_off = htons(off);
    ih.ip_ttl = ttl;
    ih.ip_p = proto;
    ih.ip_sum = htons(csum);
    ih.ip_src.s_addr = htonl(src);
    ih.ip_dst.s_addr = htonl(dst);

    vector<u8> packed;
    bytes_to_vector(&packed, (u8*) &ih, sizeof(ih));
    return packed;
}

u8 
IP::pack_buf(u8* buf) 
{
    struct ip ih;
    ih.ip_v = v;
    ih.ip_hl = hl;
    ih.ip_tos = tos;
    ih.ip_len = htons(len);
    ih.ip_id = htons(id);
    ih.ip_off = htons(off);
    ih.ip_ttl = ttl;
    ih.ip_p = proto;
    ih.ip_sum = htons(csum);
    ih.ip_src.s_addr = htonl(src);
    ih.ip_dst.s_addr = htonl(dst);

    memcpy(buf, &ih, sizeof(ip));
    return sizeof(ip);
}

HeaderValues 
IP::get_headers() 
{
    HeaderValues ret;
    ret[IP_HL] = hl;
    ret[IP_TOS_F] = tos;
    ret[IP_LEN] = len;
    ret[IP_ID] = id;
    ret[IP_OFF] = off;
    ret[IP_TTL_F] = ttl;
    ret[IP_PROTO] = proto;
    ret[IP_CSUM] = csum;
    ret[IP_SRC] = src;
    ret[IP_DST] = dst;
    return ret;
}

void 
IP::get_headers_opt(HVArray ret) 
{
    ret[IP_HL] = hl;
    ret[IP_TOS_F] = tos;
    ret[IP_LEN] = len;
    ret[IP_ID] = id;
    ret[IP_OFF] = off;
    ret[IP_TTL_F] = ttl;
    ret[IP_PROTO] = proto;
    ret[IP_CSUM] = csum;
    ret[IP_SRC] = src;
    ret[IP_DST] = dst;
}

/* ICMP functions */
ICMP::ICMP(const u8* pkt) 
{
    struct icmphdr *icmp = (struct icmphdr *)pkt;
    type = icmp->type;
    code = icmp->code;
}

/* TCP functions */
TCP::TCP(const u8 *pkt) 
{
    const struct tcphdr *tcp = (const struct tcphdr *)pkt;
    src = ntohs(tcp->th_sport);
    dst = ntohs(tcp->th_dport);
    seq = ntohl(tcp->th_seq);
    ack = ntohl(tcp->th_ack);
    off = tcp->th_off;
    x2 = tcp->th_x2;
    flags = tcp->th_flags;
    win = ntohs(tcp->th_win);
    csum = ntohs(tcp->th_sum);
    urp = ntohs(tcp->th_urp);
}

vector<u8> 
TCP::pack() 
{
    struct tcphdr th;
    th.th_sport = htons(src);
    th.th_dport = htons(dst);
    th.th_seq = htonl(seq);
    th.th_ack = htonl(ack);
    th.th_off = off;
    th.th_x2 = x2;
    th.th_flags = flags;
    th.th_win = htons(win);
    th.th_sum = htons(csum);
    th.th_urp = htons(urp);

    vector<u8> packed;
    bytes_to_vector(&packed, (u8*) &th, sizeof(th));
    return packed;
}

u8 
TCP::pack_buf(u8* buf) 
{
    struct tcphdr th;
    th.th_sport = htons(src);
    th.th_dport = htons(dst);
    th.th_seq = htonl(seq);
    th.th_ack = htonl(ack);
    th.th_off = off;
    th.th_x2 = x2;
    th.th_flags = flags;
    th.th_win = htons(win);
    th.th_sum = htons(csum);
    th.th_urp = htons(urp);

    memcpy(buf, &th, sizeof(tcphdr));
    return sizeof(tcphdr);
}

HeaderValues 
TCP::get_headers() 
{
    HeaderValues ret;
    ret[TCP_SRC] = src;
    ret[TCP_DST] = dst;
    ret[TCP_SEQ] = seq;
    ret[TCP_ACK] = ack;
    ret[TCP_OFF] = off;
    ret[TCP_FLAGS] = flags;
    ret[TCP_WIN] = win;
    ret[TCP_CSUM] = csum;
    ret[TCP_URP] = urp;
    return ret;
}

void 
TCP::get_headers_opt(HVArray ret) 
{
    ret[TCP_SRC] = src;
    ret[TCP_DST] = dst;
    ret[TCP_SEQ] = seq;
    ret[TCP_ACK] = ack;
    ret[TCP_OFF] = off;
    ret[TCP_FLAGS] = flags;
    ret[TCP_WIN] = win;
    ret[TCP_CSUM] = csum;
    ret[TCP_URP] = urp;
}

/* UDP functions */

UDP::UDP(const u8 *pkt) 
{
    const struct udphdr *udp = (const struct udphdr *)pkt;
    src = ntohs(udp->uh_sport);
    dst = ntohs(udp->uh_dport);
    len = ntohs(udp->uh_ulen);
    csum = ntohs(udp->uh_sum);
}

vector<u8> 
UDP::pack() 
{
    struct udphdr uh;
    uh.uh_sport = htons(src);
    uh.uh_dport = htons(dst);
    uh.uh_ulen = htons(len);
    uh.uh_sum = htons(csum);

    vector<u8> packed;
    bytes_to_vector(&packed, (u8*) &uh, sizeof(uh));
    return packed;
}

u8 
UDP::pack_buf(u8* buf) 
{
    struct udphdr uh;
    uh.uh_sport = htons(src);
    uh.uh_dport = htons(dst);
    uh.uh_ulen = htons(len);
    uh.uh_sum = htons(csum);
    memcpy(buf, &uh, sizeof(uh));
    return sizeof(udphdr);
}

HeaderValues 
UDP::get_headers() 
{
    HeaderValues ret;
    ret[UDP_SRC] = src;
    ret[UDP_DST] = dst;
    ret[UDP_CSUM] = csum;
    ret[UDP_LEN] = len;
    return ret;
}

void 
UDP::get_headers_opt(HVArray ret) 
{
    ret[UDP_SRC] = src;
    ret[UDP_DST] = dst;
    ret[UDP_CSUM] = csum;
    ret[UDP_LEN] = len;
}

/* Packet functions */

Packet::Packet(const u8 *pkt, u32 sz, int skip_ethernet, u32 packet_number, int caplen, bool do_unpack)
{
    memcpy(buff, pkt, caplen);

    this->size = sz;
    this->caplen = caplen;
    this->payload = buff;
    this->seq = packet_number;
    this->skip_ethernet = skip_ethernet;
    this->ts.tv_sec = 0;
    this->ts.tv_usec = 0;

    if(do_unpack)
        unpack();
}

string
Packet::str_hex() 
{
    char *pkt_hex = (char *) malloc(size*2 + 1);
    hexify_packet(buff, pkt_hex, size);
    return string(pkt_hex);
}

/* NOTE:
 * Most diffs are full replacement, but a few actually represent
 * deltas: [TCP_SEQ, TCP_ACK, IP_ID] */
void 
Packet::apply_diff(Header h, u64 v) 
{
    switch (h) {
        //TS_SEC
        //PCAP_SEQ
        case IP_HL:
            ip.hl = v;
            break;
        case IP_TOS_F:
            ip.tos = v;
            break;
        case IP_LEN:
            ip.len = v;
            break;
        case IP_ID: // DELTA
            ip.id += v;
            break;
        case IP_OFF:
            ip.off = v;
            break;
        case IP_TTL_F:
            ip.ttl = v;
            break;
        case IP_PROTO:
            ip.proto = v;
            break;
        case IP_CSUM:
            ip.csum = v;
            break;
        case IP_SRC:
            ip.src = v;
            break;
        case IP_DST:
            ip.dst = v;
            break;

        case TCP_SRC:
            tcp.src = v;
            break;
        case TCP_DST:
            tcp.dst = v;
            break;
        case TCP_SEQ: // DELTA
            tcp.seq += v;
            break;
        case TCP_ACK: // DELTA
            tcp.ack += v;
            break;
        case TCP_OFF:
            tcp.off = v;
            break;
        case TCP_FLAGS:
            tcp.flags = v;
            break;
        case TCP_WIN:
            tcp.win = v;
            break;
        case TCP_CSUM:
            tcp.csum = v;
            break;
        case TCP_URP:
            tcp.urp = v;
            break;

        case UDP_SRC:
            udp.src = v;
            break;
        case UDP_DST:
            udp.dst = v;
            break;
        case UDP_CSUM:
            udp.csum = v;
            break;
        case UDP_LEN:
            udp.len = v;
            break;
    }

}

HeaderValues 
Packet::get_headers() 
{
    u64 tstamp = ts.tv_sec;
    HeaderValues ret;
    //ret[TS_SEC] = tstamp;
    //ret[PCAP_SEQ] = seq;

    switch (eth.proto) {
        case ETHERTYPE_IP:
            HeaderValues retip = ip.get_headers();
            HeaderValues retp;

            switch (ip.proto) {
                case IPPROTO_TCP:
                    retp = tcp.get_headers();
                    break;

                case IPPROTO_UDP:
                    retp = udp.get_headers();
                    break;
            }

            update_headers(retip, retp);
            update_headers(ret, retip);
            break;
    }

    return ret;
}

void
Packet::unpack()
{
    if (likely(!skip_ethernet)) {
        eth = Ethernet(buff); // now (buff) was: pkt
    } 
    else {
        eth.proto = ETHERTYPE_IP;
        eth.payload = payload;
    }

    switch (eth.proto) {
        case ETHERTYPE_IP:
            parse_ip(eth.payload);
            break;

        case ETHERTYPE_ARP:
            parse_arp(eth.payload);
            break;
    }
}

// Writes from an STL vector into the provided buffer.
// returns number of bytes written to buf
uint 
Packet::pack(u8* buf) 
{
    vector<u8> p = pack_eth();
    int i;
    for (i = 0; i < p.size(); i++) {
        buf[i] = p[i];
    }
    return p.size();
}

vector<u8> 
Packet::pack_eth() 
{
    vector<u8> rest;
    switch (eth.proto) {
        case ETHERTYPE_IP:
            rest = pack_ip();
            break;

        case ETHERTYPE_ARP:
            rest = pack_arp();
            break;
    }
    vector<u8> eth_packed = eth.pack();
    eth_packed.insert(eth_packed.end(), rest.begin(), rest.end());
    return eth_packed;
}

u8 
Packet::pack_eth_buf(u8* buf) 
{
    u8 rest;
    switch (eth.proto) {
        case ETHERTYPE_IP:
            rest = pack_ip_buf(buf + sizeof(ether_header));
            break;

        case ETHERTYPE_ARP:
            rest = pack_arp_buf(buf + sizeof(ether_header));
            break;
    }
    return this->eth.pack_buf(buf) + rest;
}

vector<u8> 
Packet::pack_ip() 
{
    vector<u8> rest;
    switch (ip.proto) {
        case IPPROTO_TCP:
            rest = pack_tcp();
            break;

        case IPPROTO_UDP:
            rest = pack_udp();
            break;
    }
    vector<u8> ip_packed = ip.pack();
    ip_packed.insert(ip_packed.end(), rest.begin(), rest.end());
    return ip_packed;
}

u8 
Packet::pack_ip_buf(u8* buf) 
{
    u8 rest;
    switch (ip.proto) {
        case IPPROTO_TCP:
            rest = pack_tcp_buf(buf + sizeof(struct ip));
            break;

        case IPPROTO_UDP:
            rest = pack_udp_buf(buf + sizeof(struct ip));
            break;
    }
    return this->ip.pack_buf(buf) + rest;
}

void 
Packet::get_headers_opt(HVArray ret) 
{
    if (unlikely(eth.proto != ETHERTYPE_IP))
        return;

    ip.get_headers_opt(ret);
    switch (ip.proto) {
        case IPPROTO_TCP:
            tcp.get_headers_opt(ret);
            break;

        case IPPROTO_UDP:
            udp.get_headers_opt(ret);
            break;
    }
}

void 
Packet::parse_ip(const u8 *pkt) 
{
    ip = IP(pkt);
    switch (ip.proto) {
        case IPPROTO_TCP:
            parse_tcp(ip.payload);
            break;
        case IPPROTO_UDP:
            parse_udp(ip.payload);
            break;
        case IPPROTO_ICMP:
            parse_icmp(ip.payload);
            break;
    }
}

u8 
Packet::nw_proto() 
{
    switch(eth.proto) {
        case ETHERTYPE_ARP:
            return arp.op & 0xff;

        case ETHERTYPE_IP:
            return ip.proto;
    }
}

u32 
Packet::nw_src() 
{
    switch(eth.proto) {
        case ETHERTYPE_ARP:
            return arp.nw_src;

        case ETHERTYPE_IP:
            return ip.src;
    }
}

u32 
Packet::nw_dst() 
{
    switch(eth.proto) {
        case ETHERTYPE_ARP:
            return arp.nw_dst;

        case ETHERTYPE_IP:
            return ip.dst;
    }
}

u16 
Packet::tp_src() 
{
    switch(ip.proto) {
        case IPPROTO_TCP:
            return tcp.src;

        case IPPROTO_UDP:
            return udp.src;

        case IPPROTO_ICMP:
            return icmp.type;
    }
}

u16 
Packet::tp_dst() 
{
    switch(ip.proto) {
        case IPPROTO_TCP:
            return tcp.dst;

        case IPPROTO_UDP:
            return udp.dst;

        case IPPROTO_ICMP:
            return icmp.code;
    }
}

u16 
Packet::infer_len() 
{
    int inferred_len = 0;
    if (!skip_ethernet) {
        assert (eth.proto == ETHERTYPE_IP);
        inferred_len += 14;
    }
    inferred_len += ip.len;
    return inferred_len;
}

u16 
Packet::hdr_size() 
{
    int size = 0;
    if (likely(!skip_ethernet)) {
        size += sizeof(ether_header);
    }

    size += sizeof(iphdr);
    switch (ip.proto) {
        case IPPROTO_TCP:
            size += sizeof(struct tcphdr);
            break;

        case IPPROTO_UDP:
            size += sizeof(struct udphdr);
            break;
    }
    return size;
}

JSON
Packet::json()
{
    char *hex = (char *) malloc(2*PACKET_BUFF_SIZE + 1);
    hexify_packet(buff, hex, PACKET_BUFF_SIZE);

    JSON ts_j;
    ts_j["tv_sec"] = V((u64)ts.tv_sec);
    ts_j["tv_usec"] = V((u64)ts.tv_usec);

    JSON j;
    j["buff"] = V(hex);
    j["timestamp"] = V(ts_j);
    return j;
}

/* Other functions */

void 
packet_init() 
{
#define a ETHERTYPE_TO_STRING
    a[ETHERTYPE_IP] = "IP";
    a[ETHERTYPE_ARP] = "ARP";
    a[ETHERTYPE_VLAN] = "VLAN";
    a[ETHERTYPE_IPV6] = "IPv6";
#undef a

#define a IPPROTO_TO_STRING
    a[IPPROTO_TCP] = "TCP";
    a[IPPROTO_UDP] = "UDP";
    a[IPPROTO_ICMP] = "ICMP";
#undef a

#define a HEADER_SIZE_BITS
    a[TS_SEC] = 64;
    a[PCAP_SEQ] = 64;
    a[IP_HL] = 8; // 4??
    a[IP_TOS_F] = 8;
    a[IP_LEN] = 16;
    a[IP_ID] = 16;
    a[IP_OFF] = 16;
    a[IP_TTL_F] = 8;
    a[IP_PROTO] = 8;
    a[IP_CSUM] = 16;
    a[IP_SRC] = 32;
    a[IP_DST] = 32;

    a[TCP_SRC] = 16;
    a[TCP_DST] = 16;
    a[TCP_SEQ] = 32;
    a[TCP_ACK] = 32;
    a[TCP_OFF] = 8; // 4??
    a[TCP_FLAGS] = 8; // 6??
    a[TCP_WIN] = 16;
    a[TCP_CSUM] = 16;
    a[TCP_URP] = 16;

    a[UDP_SRC] = 16;
    a[UDP_DST] = 16;
    a[UDP_CSUM] = 16;
    a[UDP_LEN] = 16;
#undef a

#define a HEADER_WRITE_BITS
    //a[TS_SEC] = 64;
    //a[PCAP_SEQ] = 64;
    a[IP_HL] = 8; // 4??
    a[IP_TOS_F] = 8;
    a[IP_LEN] = 16;
    a[IP_ID] = 16;
    a[IP_OFF] = 16;
    a[IP_TTL_F] = 8;
    a[IP_PROTO] = 8;
    a[IP_CSUM] = 16;
    a[IP_SRC] = 32;
    a[IP_DST] = 32;

    a[TCP_SRC] = 16;
    a[TCP_DST] = 16;
    a[TCP_SEQ] = 32;
    a[TCP_ACK] = 32;
    a[TCP_OFF] = 8; // 4??
    a[TCP_FLAGS] = 8; // 6??
    a[TCP_WIN] = 16;
    a[TCP_CSUM] = 16;
    a[TCP_URP] = 16;

    a[UDP_SRC] = 16;
    a[UDP_DST] = 16;
    a[UDP_CSUM] = 16;
    a[UDP_LEN] = 16;
#undef a

#define a HEADER_NAMES
    a[TS_SEC] = "TS_SEC";
    a[PCAP_SEQ] = "PCAP_SEQ";
    a[IP_HL] = "IP_HL";
    a[IP_TOS_F] = "IP_TOS";
    a[IP_LEN] = "IP_LEN";
    a[IP_ID] = "IP_ID";
    a[IP_OFF] = "IP_OFF";
    a[IP_TTL_F] = "IP_TTL";
    a[IP_PROTO] = "IP_PROTO";
    a[IP_CSUM] = "IP_CSUM";
    a[IP_SRC] = "IP_SRC";
    a[IP_DST] = "IP_DST";

    a[TCP_SRC] = "TCP_SRC";
    a[TCP_DST] = "TCP_DST";
    a[TCP_SEQ] = "TCP_SEQ";
    a[TCP_ACK] = "TCP_ACK";
    a[TCP_OFF] = "TCP_OFF";
    a[TCP_FLAGS] = "TCP_FLAGS";
    a[TCP_WIN] = "TCP_WIN";
    a[TCP_CSUM] = "TCP_CSUM";
    a[TCP_URP] = "TCP_URP";

    a[UDP_SRC] = "UDP_SRC";
    a[UDP_DST] = "UDP_DST";
    a[UDP_CSUM] = "UDP_CSUM";
    a[UDP_LEN] = "UDP_LEN";
#undef a
}

void 
update_headers(HeaderValues &a, HeaderValues &b) 
{
    EACH(it, b) {
        a[it->first] = it->second;
    }
}

void 
print_headers(HeaderValues &a) 
{
    EACH(it, a) {
        printf("%s: %llu (0x%llx)\n",
                HEADER_NAMES[it->first].c_str(),
                it->second, it->second);
    }
}

// Print as colon-hex string
void 
print_eth(u8* e) 
{
    int i;
    for (i = 0; i < 6; i++) {
        if (e[i] < 16)
            printf("0%0x:", (u8) e[i]);
        else
            printf("%0x:", (u8) e[i]);
    }
}

void 
bytes_to_vector(vector<u8>* packed, u8* header, uint size) 
{
    for (int i = 0; i < size; i++) {
        packed->push_back(*((const u8*) header + i));
    }
    assert(packed->size() == size);
}