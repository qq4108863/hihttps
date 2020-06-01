/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * For more ,please contact QQ/wechat:4108863 mail:4108863@qq.com
 */


#include "config.h"

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>  /* WAIT_PID */

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  /* TCP_NODELAY */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <libgen.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "logging.h"
#include "configuration.h"
#include "hihttps.h"
#include "hssl_locks.h"
#include "ocsp.h"
#include "shctx.h"
#include "foreign/vpf.h"
#include "foreign/uthash.h"

/* hihttps.c */
extern hihttps_config *CONFIG;

#define LOG_REOPEN_INTERVAL 60

FILE * logfile;
struct stat logf_st;
time_t logf_check_t;

double
Time_now(void)
{
    struct timespec tv;

    AZ(clock_gettime(CLOCK_REALTIME, &tv));
    return (tv.tv_sec + 1e-9 * tv.tv_nsec);
}

void
VWLOG(int level, const char *fmt, va_list ap)
{
    struct timeval tv;
    struct tm tm;
    char buf[1024];
    int n;
    va_list ap1;

    va_copy(ap1, ap);
    if (CONFIG->SYSLOG) {
        vsyslog(level, fmt, ap);
    }

    if (!logfile) {
        va_end(ap1);
        return;
    }
    AZ(gettimeofday(&tv, NULL));
    if (logfile != stdout && logfile != stderr
        && tv.tv_sec >= logf_check_t + LOG_REOPEN_INTERVAL) {
        struct stat st;
        if (stat(CONFIG->LOG_FILENAME, &st) < 0
            || st.st_dev != logf_st.st_dev
            || st.st_ino != logf_st.st_ino) {
            fclose(logfile);

            logfile = fopen(CONFIG->LOG_FILENAME, "a");
            if (logfile == NULL
                || fstat(fileno(logfile), &logf_st) < 0)
                memset(&logf_st, 0, sizeof(logf_st));
        }
        logf_check_t = tv.tv_sec;
    }

    AN(localtime_r(&tv.tv_sec, &tm));
    n = strftime(buf, sizeof(buf), "%Y%m%dT%H%M%S", &tm);
    snprintf(buf + n, sizeof(buf) - n, ".%06d [%5d] %s",
        (int) tv.tv_usec, getpid(), fmt);
    vfprintf(logfile, buf, ap1);
    va_end(ap1);
}

void
WLOG(int level, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    VWLOG(level, fmt, ap);
    va_end(ap);
}

void
logproxy(int level, const proxystate* ps, const char *fmt, ...)
{
    char buf[1024];
    char hbuf[INET6_ADDRSTRLEN+1];
    char sbuf[8];
    int n;
    va_list ap;
    socklen_t salen;

    CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);

    salen = (ps->remote_ip.ss_family == AF_INET) ?
        sizeof(struct sockaddr) : sizeof(struct sockaddr_in6);
    n = getnameinfo((struct sockaddr *) &ps->remote_ip, salen, hbuf,
        sizeof hbuf, sbuf, sizeof sbuf,
        NI_NUMERICHOST | NI_NUMERICSERV);
    if (n != 0) {
        strcpy(hbuf, "n/a");
        strcpy(sbuf, "n/a");
    }

    va_start(ap, fmt);
    if (ps->remote_ip.ss_family == AF_INET)
        snprintf(buf, sizeof(buf), "%s:%s :%d %d:%d %s",
            hbuf, sbuf, ps->connect_port, ps->fd_up, ps->fd_down, fmt);
    else
        snprintf(buf, sizeof(buf), "[%s]:%s :%d %d:%d %s",
            hbuf, sbuf, ps->connect_port, ps->fd_up, ps->fd_down, fmt);
    VWLOG(level, buf, ap);
    va_end(ap);
}

// XXX: Rename
void
fail(const char *s)
{
    ERR("%s: %s\n", s, strerror(errno));
    exit(1);
}


void
log_ssl_error(proxystate *ps, const char *what, ...)
{
    va_list ap;
    int e;
    char buf[256];
    char whatbuf[1024];

    CHECK_OBJ_ORNULL(ps, PROXYSTATE_MAGIC);

    va_start(ap, what);
    vsnprintf(whatbuf, sizeof(whatbuf), what, ap);
    va_end(ap);

    while ((e = ERR_get_error())) {
        ERR_error_string_n(e, buf, sizeof(buf));
        if (ps)
            ERRPROXY(ps, "%s: %s\n", whatbuf, buf);
        else
            ERR("%s: %s\n", whatbuf, buf);
    }
}
