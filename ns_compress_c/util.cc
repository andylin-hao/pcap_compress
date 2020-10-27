/*
 * Copyright 2014, Stanford University. This file is licensed under Apache 2.0,
 * as described in included LICENSE.txt.
 *
 * Author: nikhilh@cs.stanford.com (Nikhil Handigol)
 *         jvimal@stanford.edu (Vimal Jeyakumar)
 *         brandonh@cs.stanford.edu (Brandon Heller)
 */

#include "util.hh"

using namespace std;

static int COMPRESSION_LEVEL = 1;

FILE *
dieopenr(int fd)
{
    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        ERR("Cannot open temp file for reading\n");
        exit(-1);
    }
    fseek(fp, 0, SEEK_SET);
    return fp;
}

FILE *
dieopenw() 
{
    FILE *fp = tmpfile();

    if (!fp) {
        ERR("Cannot open temp file for writing\n");
        exit(-1);
    }
    setvbuf(fp, NULL, _IOFBF, BUFSIZE);
    return fp;
}

gzFile 
compressed_read_stream(FILE *fp) 
{
    return gzdopen(fileno(fp), "r");
}

gzFile 
compressed_write_stream(FILE *fp) 
{
    gzFile ret = gzdopen(fileno(fp), "w");

    if (ret == NULL) {
        ERR("Couldn't convert file %p to gzip stream.\n", fp);
        exit(-1);
    }

    /* Turns out higher compression levels don't work that well */
    gzsetparams(ret, COMPRESSION_LEVEL, Z_DEFAULT_STRATEGY);
    return ret;
}

int 
varint_encode(u32 value, u8 *target) 
{
    u8 *src = (u8 *)&value;

    *target++ = *src++;
    if (likely(value <= 0xff))
        return 1;

    *target++ = *src++;
    if (value <= 0xffff)
        return 2;

    *target++ = *src++;
    if (value <= 0xffffff)
        return 3;

    *target++ = *src++;
    return 4;
}

u32 
varint_decode(int len, u8 *src) 
{
    u32 ret = 0;
    u8 *target = (u8 *)&ret;

    do {
        *target++ = *src++;
    } while (--len);

    return ret;
}

inline u64 
ts_to_usec(struct timeval &ts) 
{
    return ts.tv_sec * USEC_PER_SEC + ts.tv_usec;
}

inline u64 
ts_diff_usec(struct timeval &end, struct timeval &start) 
{
    u64 us = 0;
    us += (end.tv_sec - start.tv_sec) * USEC_PER_SEC;
    us += end.tv_usec - start.tv_usec;
    return us;
}
