
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CRC32_H_INCLUDED_
#define _NGX_CRC32_H_INCLUDED_


#include "../waf/ssl_array.h"



#define ngx_crc32_final(crc)                                                  \
    crc ^= 0xffffffff

uint32_t
ngx_crc32_long(u_char *p, size_t len);

ngx_int_t ngx_crc32_table_init(void);


#endif /* _NGX_CRC32_H_INCLUDED_ */
