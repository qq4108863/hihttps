

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */
#ifndef __SSL_UTILS_H__
#define __SSL_UTILS_H__

#include "ssl_array.h"	
char *
strfaststr(unsigned char *haystack, unsigned int hl, 
		 unsigned char *needle, unsigned int nl);


int naxsi_unescape(ngx_str_t *str);

unsigned char *ngx_utf8_check(ngx_str_t *str);

u_int naxsi_escape_nullbytes(ngx_str_t *str);



ngx_int_t
ngx_http_dummy_create_hashtables_n(ngx_http_dummy_loc_conf_t *dlc, 
				   ngx_conf_t *cf);




#endif


