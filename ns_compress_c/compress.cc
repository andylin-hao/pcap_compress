/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */

#include <cassert>
#include <climits>

#include "compress.hh"
#include "util.hh"
#include "helper.hh"
#include "types.hh"

using namespace std;
/* DiffRecord functions */

void 
DiffRecord::print(u32 seq) 
{
    int offset = 0;
    printf("%u: DiffRecord <ref: %d, nchg: %d> {\n",
            seq, packet_ref, num_changes);

    if (num_changes == FIRST_PACKET_ENCODE)
        goto done;

    for (int i = 0; i < num_changes; i++) {
        FieldRecord *field = (FieldRecord*)(((u8 *)this->records) + offset);
        int field_nr = field->field_nr;
        Header key = static_cast<Header>(field_nr);
        u32 value = 0;
        int len;

        len = field->value_len + 1;
        value = varint_decode(len, field->field_value);
        offset += 1 + len;
        /* Finish decoding */
        printf("\t%s: 0x%llx,\n", HEADER_NAMES[key].c_str(), (u64)value);
    }

done:
    printf("};\n");
}
/*
 * Use this: www.stanford.edu/class/cs276/Jeff-Dean-compression-slides.pdf
 * Group Varint Encoding snippet: http://www.oschina.net/code/snippet_12_5083
 * http://videolectures.net/wsdm09_dean_cblirs/
 */

Compressor::Compressor() 
{
    fp_ts = dieopenw();
    fp_ts_comp = compressed_write_stream(fp_ts);

    fp_firstpkt = dieopenw();
    fp_firstpkt_comp = compressed_write_stream(fp_firstpkt);

    fp_diff = dieopenw();
    fp_diff_comp = compressed_write_stream(fp_diff);

    ts_prev.tv_sec = ~0;
    first_packet_id = 0;

    diff_size = 0, diff_csize = 0;
    firstpkt_size = 0, firstpkt_csize = 0;
    ts_delta_size = 0, ts_delta_csize = 0;
    desc_size = 0;
    num_packets = 0;

    bzero(NumFieldChanged, sizeof NumFieldChanged);
    bzero(NumChangePerPacket, sizeof NumChangePerPacket);
    bzero(TotalFieldBytes, sizeof TotalFieldBytes);
    NumNonOneIPID = 0;
}

Compressor::~Compressor()
{
    close();
}

void 
Compressor::seek_end() 
{
    fseek(fp_ts, 0, SEEK_END);
    fseek(fp_firstpkt, 0, SEEK_END);
    fseek(fp_diff, 0, SEEK_END);

    ts_delta_csize = ftell(fp_ts);
    firstpkt_csize = ftell(fp_firstpkt);
    diff_csize = ftell(fp_diff);


}

void 
Compressor::flush(bool zstd)
{
    flush_compress(zstd);
    seek_end();
}

void 
Compressor::flush_compress(bool zstd)
{
    if (zstd) {
        cpz_zstd_file(fp_ts);
        cpz_zstd_file(fp_firstpkt);
        cpz_zstd_file(fp_diff);
    } else {
        gzflush(fp_ts_comp, Z_FINISH);
        gzflush(fp_firstpkt_comp, Z_FINISH);
        gzflush(fp_diff_comp, Z_FINISH);
    }
}

void 
Compressor::close() 
{
    if (!fp_ts) return;
    flush();

    fclose(fp_ts);
    fclose(fp_firstpkt);
    fclose(fp_diff);

    fp_ts = NULL;
    fp_firstpkt = NULL;
    fp_diff = NULL;
}

double 
Compressor::bpp_normal() 
{
    flush();
    u64 total_size = diff_size + firstpkt_size + ts_delta_size;
    return total_size * 1.0 / num_packets;
}

double 
Compressor::bpp_compress() 
{
    flush();
    u64 total_csize = diff_csize + firstpkt_csize + ts_delta_csize;
    return total_csize * 1.0 / num_packets;
}

void 
Compressor::stats(JSON &j) 
{
    u64 total_size = diff_size + firstpkt_size + ts_delta_size;
    u64 total_csize = diff_csize + firstpkt_csize + ts_delta_csize;
    float avg, total;
    JSON jstat;

    flush();

    printf("Compressor: diff %lu, first %lu, ts %lu, desc %llu, total %llu\n",
            diff_size, firstpkt_size, ts_delta_size, desc_size,
            total_size);

    j["num_packets"] = V(num_packets);
    j["diff_size"] = V((u64)diff_size);
    j["firstpkt_size"] = V((u64)firstpkt_size);
    j["ts_delta_size"] = V((u64)ts_delta_size);
    j["desc_size"] = V(desc_size);
    j["total_size"] = V((u64)total_size);
    j["bpp"] = V(bpp_normal());

    printf("bpp: diff %.3lf, first %.3f, ts %.3f, desc %.3f, total %.3f\n",
            diff_size * 1.0 / num_packets,
            firstpkt_size * 1.0 / num_packets,
            ts_delta_size * 1.0 / num_packets,
            desc_size * 1.0 / num_packets,
            total_size * 1.0 / num_packets);

    printf("bpp: diff %.3lf, first %.3f, ts %.3f, total %.3f\n",
            diff_csize * 1.0 / num_packets,
            firstpkt_csize * 1.0 / num_packets,
            ts_delta_csize * 1.0 / num_packets,
            total_csize * 1.0 / num_packets);

    j["diff_csize"] = V((u64)diff_csize);
    j["firstpkt_csize"] = V((u64)firstpkt_csize);
    j["ts_delta_csize"] = V((u64)ts_delta_csize);
    j["total_csize"] = V((u64)total_csize);
    j["gzbpp"] = V(bpp_compress());

    j["non_one_ipid_changes"] = V(NumNonOneIPID);

    printf("\nNumber of times a particular field changed per packet\n");
    total = 0;
    REP(i, NUM_FIELDS) total += NumFieldChanged[i];

    jstat = JSON();
    REP(i, NUM_FIELDS) {
        if (!NumFieldChanged[i]) continue;
        float bpp = TotalFieldBytes[i] * 1.0 / num_packets;
        string header = HEADER_NAMES[static_cast<Header>(i)];
        JSON ele;
        ele["count"] = V((u64)NumFieldChanged[i]);
        ele["bytes"] = V((u64)TotalFieldBytes[i]);

        printf("%s: %u, %.3f%%, %.3f bpp\n",
                header.c_str(),
                NumFieldChanged[i],
                NumFieldChanged[i] * 100.0 / total,
                bpp);

        jstat[header.c_str()] = V(ele);
    }

    j["NumFieldChangePerPacket"] = V(jstat);
    printf("*******\n");

    printf("Number of field changes per packet\n");
    avg = 0, total = 0;
    jstat = JSON();
    REP(i, 20) {
        if (!NumChangePerPacket[i]) break;
        printf("%d: %u\n",
                i, NumChangePerPacket[i]);
        avg += i * NumChangePerPacket[i];
        total += NumChangePerPacket[i];
        jstat[ntos(i)] = V((u64)NumChangePerPacket[i]);
    }
    printf("Average: %.3f fchgs/packet\n", avg/total);
    j["FieldChangePerPacket"] = V(jstat);
}

/* These are for non-compressed diff records */
template<class T>
int 
Compressor::EmitTimestamp(T *obj) 
{
    gzwrite(fp_ts_comp, (void *)obj, sizeof(T));
    return sizeof(T);
}

int 
Compressor::EmitFirstpacket(const u8 *payload, u8 caplen) 
{
    gzwrite(fp_firstpkt_comp, (void *)&caplen, sizeof(caplen));
    gzwrite(fp_firstpkt_comp, (void *)payload, caplen);
    return caplen + sizeof(caplen);
}

int 
Compressor::EmitDiffRecord(u8 *buff, int diffsize) 
{
    int sz = sizeof(struct DiffRecord) + diffsize;
    gzwrite(fp_diff_comp, (void *)buff, sz);
    return sz;
}

void 
Compressor::write_time_stamp(struct timeval &ts) 
{
    /* First timestamp */
    if (unlikely(ts_prev.tv_sec == ~0)) {
        ts_delta_size += EmitTimestamp(&ts);
    } 
    else {
        u64 usec_delta = (ts.tv_sec - ts_prev.tv_sec) * int(1e6);
        usec_delta += (ts.tv_usec - ts_prev.tv_usec);

        if (usec_delta >= UINT_MAX) {
            ERR("Timestamp is wrapping\n");
        }

        u32 val = usec_delta;
        ts_delta_size += EmitTimestamp(&val);
    }

    ts_prev = ts;
}

u32 Compressor::write_first_header(Packet &pkt) 
{
    firstpkt_size += EmitFirstpacket(pkt.payload, pkt.caplen);
    return first_packet_id++;
}

/* TODO: Switch to using "Emit()" functions as a narrow waist for marshalling data */
void Compressor::write_diff_packet(Flow &flow, Packet &curr, int first_packet_id) 
{
    u8 buff[100];
    DiffRecord *diff = (DiffRecord *)(&buff[0]);
    FieldRecord *field = diff->records;
    int diffsize = 0;
    u32 *hv_prev = NULL;
    u32 hv_curr[NUM_FIELDS];

    hv_prev = flow.get_prev_harray();
    memset(hv_curr, -1, sizeof (hv_curr));
    curr.get_headers_opt(hv_curr);

    desc_size += 1;

    if (first_packet_id >= 0) {
        diff->packet_ref = first_packet_id;
        diff->num_changes = FIRST_PACKET_ENCODE;
        goto write;
    } 
    else {
        diff->packet_ref = flow.prev.seq;
        diff->num_changes = 0;
    }

    for (int i = IP_TOS_F; i < NUM_FIELDS; i++) {
        Header key = static_cast<Header>(i);
        auto value = hv_curr[i];

        if (key != IP_ID and (value == hv_prev[key] or value == ~0))
            continue;

        if (key == TCP_SEQ or key == TCP_ACK or key == IP_ID) {
            value = hv_curr[i] - hv_prev[i];
        }

        if (key == IP_ID) {
            if (value == 1) {
                continue;
            } else {
                NumNonOneIPID++;
            }
        }

        if (HEADER_WRITE_BITS[key] == 16)
            value = value & 0xffff;

        NumFieldChanged[key]++;
        diff->num_changes++;
        field = encode(field, key, value, diffsize);
    }

write:
    diff_size += EmitDiffRecord(buff, diffsize);
    NumChangePerPacket[diff->num_changes]++;
}

void Compressor::write_pkt(Packet &pkt) 
{
    FlowKey key(pkt);
    Flow &flow = flows[key];
    int first = flow.add_packet(pkt, &flow_stats);
    int first_packet_id = -1;
    if (first) {
        first_packet_id = write_first_header(pkt);
    }

    write_time_stamp(pkt.ts);
    write_diff_packet(flow, pkt, first_packet_id);
    num_packets++;
}

/* Encodes key, value into curr and returns the next pointer */
FieldRecord *
Compressor::encode(FieldRecord *curr, Header key, u32 value, int &diffsize) 
{
    int size;
    curr->field_nr = static_cast<u8>(key);
    size = varint_encode(value, curr->field_value);
    TotalFieldBytes[key] += 1 + size;
    curr->value_len = size - 1;
    assert (1 <= size and size <= 4);
    diffsize += 1 + size;
    desc_size += 1;
    return (FieldRecord *)(((u8 *) curr) + 1 + size);
}
