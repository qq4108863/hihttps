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


#ifndef LOGGING_H_INCLUDED
#define LOGGING_H_INCLUDED

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

#include "ev.h"
#include <stdio.h>
#include <syslog.h>

// #include "asn_gentm.h"
#include "configuration.h"
#include "hihttps.h"
// #include "miniobj.h"
// #include "ringbuffer.h"
// #include "vas.h"
// #include "vsb.h"


double Time_now(void);

void WLOG(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
void logproxy(int level, const proxystate* ps, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

void VWLOG(int level, const char *fmt, va_list ap);
void WLOG(int level, const char *fmt, ...);

void log_ssl_error(proxystate *ps, const char *what, ...);

void fail(const char *s);

#define LOG(...)							\
	do {								\
		if (CONFIG->LOG_LEVEL > 1)				\
			WLOG(LOG_INFO, __VA_ARGS__ );			\
	} while (0)

#define ERR(...)					\
	do {						\
		if (CONFIG->LOG_LEVEL > 0)		\
			WLOG(LOG_ERR, __VA_ARGS__ );	\
	} while (0)

#define LOGL(...) WLOG(LOG_INFO, __VA_ARGS__)

#define SOCKERR(msg)						\
	do {							\
		if (errno == ECONNRESET) {			\
			LOG(msg ": %s\n", strerror(errno));	\
		} else {					\
			ERR(msg ": %s\n", strerror(errno));	\
		}						\
	} while (0)


#define LOGPROXY(...)							\
	do {								\
		if (CONFIG->LOG_LEVEL > 1 &&				\
		    (logfile || CONFIG->SYSLOG))			\
			logproxy(LOG_INFO, __VA_ARGS__ );		\
	} while(0)

#define ERRPROXY(...)							\
	do {								\
		if (CONFIG->LOG_LEVEL > 0 &&				\
		    (logfile || CONFIG->SYSLOG))			\
			logproxy(LOG_ERR, __VA_ARGS__ );		\
	} while (0)


#endif  /* LOGGING_H_INCLUDED */
