/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SSL_ARRAY_H_INCLUDED_
#define _NGX_SSL_ARRAY_H_INCLUDED_



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>



#ifndef NGX_ALIGNMENT
#define NGX_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#endif

#define ngx_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define ngx_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))

#define ngx_memzero(buf, n)       (void) memset(buf, 0, n)
#define ngx_memset(buf, c, n)     (void) memset(buf, c, n)


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (getpagesize() - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)

#define ngx_free          free
#define ngx_memcpy(dst, src, n)   (void) memcpy(dst, src, n)

#define ngx_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define ngx_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)



#define ngx_strncmp(s1, s2, n)  strncmp((const char *) s1, (const char *) s2, n)


/* msvc and icc7 compile strcmp() to inline loop */
#define ngx_strcmp(s1, s2)  strcmp((const char *) s1, (const char *) s2)


#define ngx_strstr(s1, s2)  strstr((const char *) s1, (const char *) s2)
#define ngx_strlen(s)       strlen((const char *) s)

#define ngx_string(str)     { sizeof(str) - 1, (u_char *) str }
#define ngx_null_string     { 0, NULL }
#define ngx_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#define ngx_str_null(str)   (str)->len = 0; (str)->data = NULL


#define ngx_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define ngx_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

#define ngx_strchr(s1, c)   strchr((const char *) s1, (int) c)

/* msvc and icc7 compile memcmp() to the inline loop */
#define ngx_memcmp(s1, s2, n)  memcmp((const char *) s1, (const char *) s2, n)



#define  NGX_OK          0
#define  NGX_ERROR      -1
#define  NGX_AGAIN      -2
#define  NGX_BUSY       -3
#define  NGX_DONE       -4
#define  NGX_DECLINED   -5
#define  NGX_ABORT      -6


#define  NGX_CONF_OK          0
#define  NGX_CONF_ERROR      -1




typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef intptr_t        ngx_flag_t;



typedef struct {
    size_t      len;
    u_char     *data;
} ngx_str_t;


typedef struct ngx_pool_s            ngx_pool_t;
typedef struct ngx_conf_s            ngx_conf_t;





typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;
    void                 *data;
    ngx_pool_cleanup_t   *next;
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

struct ngx_pool_large_s {
    ngx_pool_large_t     *next;
    void                 *alloc;
};


typedef struct {
    u_char               *last;
    u_char               *end;
    ngx_pool_t           *next;
    ngx_uint_t            failed;
} ngx_pool_data_t;


struct ngx_pool_s {
    ngx_pool_data_t       d;
    size_t                max;
    ngx_pool_t           *current;
    //ngx_chain_t          *chain;
    ngx_pool_large_t     *large;
    //ngx_pool_cleanup_t   *cleanup;
   // ngx_log_t            *log;
};


typedef struct {
    void        *elts;
    ngx_uint_t   nelts;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *pool;
} ngx_array_t;

struct ngx_conf_s {
    char                 *name;
    ngx_array_t          *args;

    //ngx_cycle_t          *cycle;
    ngx_pool_t           *pool;
    ngx_pool_t           *temp_pool;
    //ngx_conf_file_t      *conf_file;
    //ngx_log_t            *log;

    void                 *ctx;
    ngx_uint_t            module_type;
    ngx_uint_t            cmd_type;

   // ngx_conf_handler_pt   handler;
    void                 *handler_conf;
};

ngx_int_t
ngx_strncasecmp(u_char * s1, u_char * s2, size_t n);

void *ngx_alloc(size_t size);


ngx_pool_t *ngx_create_pool(size_t size);
void ngx_destroy_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);


ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size);
void ngx_array_destroy(ngx_array_t *a);
void *ngx_array_push(ngx_array_t *a);
void *ngx_array_push_n(ngx_array_t *a, ngx_uint_t n);

static inline ngx_int_t
ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;

    array->elts = ngx_palloc(pool, n * size);
    if (array->elts == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}





#endif

