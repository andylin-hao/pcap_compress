/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */

#ifndef __HELPER_HH__
#define __HELPER_HH__

#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <cstdio>
#include <cstdarg>

#include "types.hh"
#include "picojson.h"

#define USEC_PER_SEC (1e6)
#define BUFSIZE (10 << 20)
#define FIRST_PACKET_ENCODE (0xf)

#define LET(var,x) auto var(x)
#define EACH(it, cont) for (LET(it, (cont).begin()); it != (cont).end(); ++it)
#define REP(i, n) for (int i = 0; i < (n); ++i)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define V(x) picojson::value(x)
#define nil ((void*)0)
#define nelem(x) (sizeof(x)/sizeof((x)[0]))

/* Color output */
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

/* Debug output */
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT __FILE__ ":" TOSTRING(__LINE__)

#ifdef DEBUG
# define DBG(...) print_debug(AT, __VA_ARGS__)
#else
# define DBG(...)
#endif

#define ERR(...) print_error(__VA_ARGS__)

using namespace std;

static inline void print_debug(const char *location, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    string s = string(ANSI_COLOR_YELLOW) + location + ": " + msg + ANSI_COLOR_RESET;
    vprintf(s.c_str(), args);
    fflush(stdout);
    va_end(args);
}

static inline void print_error(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    string s = string(ANSI_COLOR_RED) + msg + ANSI_COLOR_RESET;
    vfprintf(stderr, s.c_str(), args);
    fflush(stderr);
    va_end(args);
}

static inline void print_color(const char *color, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    string s = string(color) + msg + ANSI_COLOR_RESET;
    vprintf(s.c_str(), args);
    fflush(stdout);
    va_end(args);
}

u64 get_file_size(const char *filename);
string ntos(u64 num);
void print_proto_stats(string parent, struct proto_stats *dict, int num_elem,
        u64 pcap_bytes_on_wire, map<u16, string> &id_to_name, JSON &json);
u64 memory_usage_kb();
void print_timestamp(struct timeval ts);
void hexify_packet(const u8 *buf, char *hex, size_t buflen);
void byteify_packet(const char *hex, u8 *bytes, size_t *buflen);
double diff_time_ms(const timeval &t1, const timeval &t2);

template<class T>
float 
entropy(map<T, u64> &dict) 
{
    vector< pair<u64, T> > items;
    u64 total = 0;
    double entropy = 0.0;

    EACH(it, dict) {
        LET(key, it->first);
        LET(value, it->second);
        items.push_back(make_pair(value, key));
        total += it->second;
    }

    sort(items.begin(), items.end());
    EACH(it, items) {
        LET(key, it->second);
        LET(value, it->first);
        double pi = value * 1.0 / total;
        if (pi > 0)
            entropy += pi * log2(1.0 / pi);
        // printf("%d: %d\n", key, value);
    }

    return entropy;
}

template<class T>
void 
print_table(map<T, u64> &dict, map<T, string> &names, string msg) 
{
    vector< pair<u64, T> > items;
    u64 total = 0;

    printf("%s\n", msg.c_str());

    EACH(it, dict) {
        LET(key, it->first);
        LET(value, it->second);
        items.push_back(make_pair(value, key));
        total += it->second;
    }

    sort(items.begin(), items.end());
    EACH(it, items) {
        LET(key, it->second);
        LET(value, it->first);
        float fraction = value * 1.0 / total;
        printf("%s: %llu, fraction: %.3f\n", names[key].c_str(), value, fraction);
    }

    puts("");
}

template<class T>
void 
print_table_int(map<T, u64> &dict, const char *msg, double fr_greater, JSON &json) 
{
    vector< pair<u64, T> > items;
    u64 total = 0;
    u64 kmax = 0;
    u64 kmin = ~0;
    double kavg = 0;
    JSON ele;

    printf("%s\n", msg);

    EACH(it, dict) {
        LET(key, it->first);
        LET(value, it->second);
        kmax = max(kmax, (u64)key);
        kmin = min(kmin, (u64)key);

        items.push_back(make_pair(value, key));
        total += it->second;
    }

    sort(items.begin(), items.end());

    EACH(it, items) {
        LET(key, it->second);
        LET(value, it->first);
        float fraction = value * 1.0 / total;
        kavg += fraction * key;

        if (fraction > fr_greater)
            printf("%llu: %llu, frac: %.3f\n", (u64)key, value, fraction);

        ele[ntos(key)] = picojson::value(value);
    }

    printf("MaxKey: %llu, MinKey: %llu, AvgKey: %.3lf\n",
            kmax, kmin, kavg);

    json[msg] = picojson::value(ele);

    puts("");
}

template <class T>
void 
add_maps(map<T, u64> &a, map<T, u64> &b) 
{
    EACH(it, b) {
        a[it->first] += it->second;
    }
}

#endif //__HELPER_HH__
