/*
 * This program is used to find location for assigned ip address.
 * The ip database can be download from http://www.cz88.net
 * The ip db format document can be found in
 *   http://lumaqq.linuxsir.org/article/qqwry_format_detail.html .
 * both db and the document are reserved by provider.
 *
 * It support FCGI mode if compiled with option -D FCGI.
 * Author: Yuanjian Yi <yiyuanjian@gmail.com>
 *
 * This is file is subject to BSD license.
 */
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <malloc.h>
#include <string.h>

#include <time.h>
#include <sys/time.h>

#include <iconv.h>

#ifdef FCGI
#include <fcgi_stdio.h>
#endif

#define AREA_UNKNOWN "Unknown"
#define BUF_GB2312 256
#define BUF_UTF8 512

#define DB_FILE "qqwry.dat"

extern int errno;

typedef unsigned int uint;
typedef unsigned char uchar;

/* change first 4 chars to unsigned int. */
uint str2uint(const char *str, size_t size) {
    if (size > 4)
        size = 4;

    uint sum = 0;
    int i = 0;
    while (i < size) {
        sum += (uchar) str[i] << 8 * i;
        i++;
    }

    return sum;
}

/* get area address */
const char *get_area_addr(const char *const op_ptr, const char *a_ptr) {
    uchar area_flag = (uchar) * a_ptr;

    if (area_flag == 0x01 || area_flag == 0x02) {
        a_ptr = op_ptr + str2uint(a_ptr + 1, 3);
        if (a_ptr == op_ptr) {
            a_ptr = AREA_UNKNOWN;
        }
    }

    return a_ptr;
}

/* get location from memory db */
int get_location(const char *const op_ptr, uint record_offset, char *buf,
                 size_t buf_size) {
    const char *c_ptr;
    const char *a_ptr;
    uchar lc_flag;
    uchar rdt_flag;

    const char *rdt_ptr;

    const char *lc_ptr = op_ptr + record_offset;
    lc_flag = (uchar) * (lc_ptr + 4);

    if (lc_flag == 0x02) {      // mode 2, pic 4
        c_ptr = op_ptr + str2uint(lc_ptr + 5, 3);
        a_ptr = get_area_addr(op_ptr, lc_ptr + 8);
    }

    if (lc_flag == 0x01) {      //mode 1 //pic 3,5,6
        rdt_ptr = op_ptr + str2uint(lc_ptr + 5, 3);
        rdt_flag = (uchar) * rdt_ptr;
        if (rdt_flag == 0x02) { // mode 1, redirect twice //pic 5, 6
            c_ptr = op_ptr + str2uint(rdt_ptr + 1, 3);
            a_ptr = get_area_addr(op_ptr, rdt_ptr + 4);
        } else {                //pic 3
            c_ptr = rdt_ptr;
            a_ptr = get_area_addr(op_ptr, rdt_ptr + strlen(c_ptr) + 1);
        }
    }

    if (lc_flag > 0x02) {       //pic 2
        c_ptr = lc_ptr + 4;
        a_ptr = get_area_addr(op_ptr, lc_ptr + 4 + strlen(c_ptr) + 1);
    }

    return snprintf(buf, buf_size, "%s %s", c_ptr, a_ptr);
}

/* trans gb2312 charset to utf8 */
size_t gb2312_to_utf8(char *src, char *out, size_t out_size) {
    size_t size;

    memset(out, '\0', out_size);

    size_t src_len = strlen(src);
    iconv_t cd;
    if ((cd = iconv_open("utf-8", "gb18030")) == 0) {
        return -1;
    }
    if ((size = iconv(cd, &src, &src_len, &out, &out_size)) == -1) {
        iconv_close(cd);
        return -1;
    }

    iconv_close(cd);
    return size;
}

/* copy db to memory, improve performance for fcgi mode */
const char *copy2memory(char *file) {
    struct stat fst;
    if (stat(file, &fst) == -1) {
        perror("read stat of db file :");
        return NULL;
    }

    char *db_ptr = (char *) malloc(sizeof(char) * fst.st_size);

    //copy to memory
    FILE *fp = fopen(file, "rb");
    fseek(fp, 0l, SEEK_SET);
    if (fread(db_ptr, sizeof(char), fst.st_size, fp) != fst.st_size) {
        perror("can't read file: ");
        free(db_ptr);
        return NULL;
    }

    return db_ptr;
}

uint get_record_offset(const char *const op, uint ip) {
    if (op == NULL)
        return 0;

    uint index_offset_h = str2uint(op, 4);
    uint index_offset_t = str2uint(op + 4, 4);

    uint offset;
    uint tmp_ip;
#ifdef DEBUG
    struct in_addr addr;
#endif
    uint h = 0, t = (index_offset_t - index_offset_h) / 7 + 1;
    uint mid;
    // middle search
    while (h <= t) {
        mid = (h + t) / 2;
        offset = index_offset_h + mid * 7;
        tmp_ip = str2uint(op + offset, 4);
#ifdef DEBUG
        addr.s_addr = htonl(tmp_ip);
        printf("h: %u, t: %u, mid: %u, ip: %s \n", h, t, mid,
               inet_ntoa(addr));
#endif
        if (tmp_ip > ip) {
            t = mid - 1;
            continue;
        }

        if (tmp_ip == ip) {
            break;
        }

        if (str2uint(op + str2uint(op + offset + 4, 3), 4) >= ip) {
            break;
        }
        h = mid + 1;
    }

    return str2uint(op + offset + 4, 3);
}

int main(int argc, char **argv) {
    struct timeval st_start;
    struct timeval st_end;
#ifndef FCGI
    /* check argument and ip */
    if (argc != 2) {
        printf("Usage: %s ip\n", argv[0]);
        return 1;
    }

    uint user_ip = inet_addr(argv[1]);
    if (user_ip == INADDR_NONE) {
        printf("invalied ip\n");
        return 1;
    }
#endif

    // copy db to memory
    const char *const op = copy2memory(DB_FILE);
    if (op == NULL) {
        return 1;
    }
#ifdef FCGI
    while (FCGI_Accept() >= 0) {
        gettimeofday(&st_start, NULL);
        printf("Content-Type: text/html; charset=utf-8\r\n\r\n");
        //        "<html>\n<head>\n<title>Ip location</title>\n</head>\n\n"
        //        "<body>\n");

        if (getenv("QUERY_STRING") == NULL
            || strlen(getenv("QUERY_STRING")) == 0) {
            printf("Please assign ip address.");
            continue;
        }

        uint user_ip;
        if ((user_ip = inet_addr(getenv("QUERY_STRING"))) == INADDR_NONE) {
            printf("Ip invaild\n");
            continue;
        }
#endif
        user_ip = ntohl(user_ip);

        uint record_offset = get_record_offset(op, user_ip);
#ifdef DEBUG
        struct in_addr addr;
        addr.s_addr = htonl(str2uint(op + record_offset, 4));
        printf("record_offset: %u, lastip: %s \n", record_offset,
               inet_ntoa(addr));
#endif
        char in[BUF_GB2312];
        get_location(op, record_offset, in, BUF_GB2312);

#ifdef DEBUG
        printf("in: %s\n", in);
#endif

        char out[BUF_UTF8];
        if (gb2312_to_utf8(in, out, BUF_UTF8) == -1) {
            fprintf(stderr, "ERROR in : %s\n", argv[1]);
            perror("error occurred:");
            return 1;
        }

        printf("%s\n", out);
#ifdef FCGI
        gettimeofday(&st_end, NULL);

        int run_time =
            (st_end.tv_sec - st_start.tv_sec) * 1000000 
            + (st_end.tv_usec - st_start.tv_usec);

        printf("<br />\nProcessing in %.6f second(s)",
               (float) run_time / (float) 1000000);

    }
#endif

    return 0;
}