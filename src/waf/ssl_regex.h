/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_REGEX_H_INCLUDED_
#define _NGX_REGEX_H_INCLUDED_

#define USE_PCRE 1 


#include <stdlib.h>
#include <string.h>
#include "ssl_array.h"


// max # of matches per regexp
#define	MAX_MATCH       10


#ifdef USE_PCRE
#include <pcre.h>
#include <pcreposix.h>

/* For pre-8.20 PCRE compatibility */
#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif

#elif USE_PCRE2
#include <pcre2.h>
#include <pcre2posix.h>

#else /* no PCRE, nor PCRE2 */
#include <regex.h>
#define PCRE_CASELESS           0x0001
#define PCRE_MULTILINE          0x0002
#define PCRE_DOTALL             0x0004
#define PCRE_EXTENDED           0x0008

#endif



typedef struct {
#ifdef USE_PCRE
    pcre        *code;
    pcre_extra  *extra;


#else /* no PCRE, nor PCRE2 */
	void        *code;
    void	    *extra;
	
#endif


} ngx_regex_t;


typedef struct {
    ngx_str_t     pattern;
    ngx_pool_t   *pool;
    ngx_int_t     options;
	
#ifdef USE_PCRE
    ngx_regex_t  *regex;
   
#else
	regex_t       re;
#endif
	
    int           captures;
    int           named_captures;
    int           name_size;
    u_char       *names;
    ngx_str_t     err;
} ngx_regex_compile_t;

ngx_int_t ngx_regex_compile(ngx_regex_compile_t *rc);




#endif

