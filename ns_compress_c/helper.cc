/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */

#include "helper.hh"
#include "types.hh"

u64 
get_file_size(const char *filename) 
{
    FILE *fp = fopen(filename, "r");
    u64 size = 0;

    if (fp == NULL)
        return -1;

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fclose(fp);
    return size;
}

string 
ntos(u64 num) 
{
    char buff[32];
    sprintf(buff, "%llu", num);
    return string(buff);
}

void 
print_proto_stats(string parent,
        struct proto_stats *dict,
        int num_elem,
        u64 pcap_bytes_on_wire,
        map<u16, string> &id_to_name,
        JSON &json)
{
    u32 num_found = 0;
    REP(i, num_elem) {
        if (dict[i].count)
            num_found++;
    }

    JSON jstat;

    printf("%s protocol statistics %d found:\n", parent.c_str(), num_found);
    REP(i, num_elem) {
        if (!dict[i].count)
            continue;
        u16 proto = i;
        struct proto_stats stat = dict[i];
        float fraction = stat.bytes * 1.0 / pcap_bytes_on_wire;
        printf("proto: %d, name: %s, count: %u, bytes: %llu, fraction: %.3f\n",
                proto,
                id_to_name[proto].c_str(),
                stat.count,
                stat.bytes,
                fraction);


        JSON protostat;
        string protoname = id_to_name[proto];
        if (protoname == "")
            protoname = ntos(proto);

        protostat["count"] = picojson::value((u64)stat.count);
        protostat["bytes"] = picojson::value((u64)stat.bytes);
        jstat[protoname] = picojson::value(protostat);
    }

    json[parent.c_str()] = picojson::value(jstat);
    puts("");
}

u64 
memory_usage_kb() 
{
    FILE* file = fopen("/proc/self/status", "r");
    u64 mem = 0;
    char line[128];

    while (fgets(line, 128, file) != NULL) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %llu kB", &mem);
            break;
        }
    }

    return mem;
}

void 
print_timestamp(struct timeval ts) 
{
    printf("timestamp val: %ld.%06ld\n", ts.tv_sec, ts.tv_usec);
}

static char get_hex_char(u8 hexval)
{
    if(hexval <= 9) {
        return hexval + '0';
    }
    else {
        return (hexval - 10) + 'a';
    }
}

void hexify_packet(const u8 *buf, char *hex, size_t buflen)
{
    unsigned int i;
    for(i = 0; i < buflen; i++) {
        *hex++ = get_hex_char((buf[i] >> 4) & 0x0f);
        *hex++ = get_hex_char(buf[i] & 0x0f);
    }
    *hex = '\0';
}

void byteify_packet(const char *hex, u8 *bytes, size_t *buflen) 
{
    int count = 0;
    *buflen = 0;
    if (hex == NULL)
        return;

    while (*hex) {
        count++;
        if (*hex <= '9') {
            *bytes = (*bytes * 16) + (*hex - '0');
        }
        else {
            *bytes = (*bytes * 16) + (*hex - 'a' + 10);
        }

        if (count == 2) {
            count = 0;
            bytes++;
            (*buflen)++;
        }
        hex++;
    }
}

double diff_time_ms(const timeval &t1, const timeval &t2)
{
    return ((t1.tv_sec - t2.tv_sec) * 1000.) + 
            (t1.tv_usec - t2.tv_usec)/1000.;
}
