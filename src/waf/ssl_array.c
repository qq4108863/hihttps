#include "ssl_array.h"

/*
 * We use ngx_strcasecmp()/ngx_strncasecmp() for 7-bit ASCII strings only,
 * and implement our own ngx_strcasecmp()/ngx_strncasecmp()
 * to avoid libc locale overhead.  Besides, we use the ngx_uint_t's
 * instead of the u_char's, because they are slightly faster.
 */

ngx_int_t
ngx_strcasecmp(u_char *s1, u_char *s2)
{
    ngx_uint_t  c1, c2;

    for ( ;; ) {
        c1 = (ngx_uint_t) *s1++;
        c2 = (ngx_uint_t) *s2++;

        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

        if (c1 == c2) {

            if (c1) {
                continue;
            }

            return 0;
        }

        return c1 - c2;
    }
}


ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    ngx_uint_t  c1, c2;

    while (n) {
        c1 = (ngx_uint_t) *s1++;
        c2 = (ngx_uint_t) *s2++;

        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

        if (c1 == c2) {

            if (c1) {
                n--;
                continue;
            }

            return 0;
        }

        return c1 - c2;
    }

    return 0;
}




void *
ngx_memalign(size_t alignment, size_t size)
{
    void  *p;

    p = memalign(alignment, size);    

    return p;
}

void *
ngx_alloc(size_t size)
{
    void  *p;

    p = malloc(size);    

    return p;
}


static void *
ngx_palloc_block(ngx_pool_t *pool, size_t size)
{
    u_char      *m;
    size_t       psize;
    ngx_pool_t  *p, *new;

    psize = (size_t) (pool->d.end - (u_char *) pool);

    m = ngx_memalign(NGX_POOL_ALIGNMENT, psize);
    if (m == NULL) {
        return NULL;
    }

    new = (ngx_pool_t *) m;

    new->d.end = m + psize;
    new->d.next = NULL;
    new->d.failed = 0;

    m += sizeof(ngx_pool_data_t);
    m = ngx_align_ptr(m, NGX_ALIGNMENT);
    new->d.last = m + size;

    for (p = pool->current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            pool->current = p->d.next;
        }
    }

    p->d.next = new;

    return m;
}



static inline void *
ngx_palloc_small(ngx_pool_t *pool, size_t size, ngx_uint_t align)
{
    u_char      *m;
    ngx_pool_t  *p;

    p = pool->current;

    do {
        m = p->d.last;

        if (align) {
            m = ngx_align_ptr(m, NGX_ALIGNMENT);
        }

        if ((size_t) (p->d.end - m) >= size) {
            p->d.last = m + size;

            return m;
        }

        p = p->d.next;

    } while (p);

    return ngx_palloc_block(pool, size);
}




static void *
ngx_palloc_large(ngx_pool_t *pool, size_t size)
{
    void              *p;
    ngx_uint_t         n;
    ngx_pool_large_t  *large;

    p = ngx_alloc(size);
    if (p == NULL) {
        return NULL;
    }

    n = 0;

    for (large = pool->large; large; large = large->next) {
        if (large->alloc == NULL) {
            large->alloc = p;
            return p;
        }

        if (n++ > 3) {
            break;
        }
    }

    large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
#if !(NGX_DEBUG_PALLOC)
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 1);
    }
#endif

    return ngx_palloc_large(pool, size);
}


void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
#if !(NGX_DEBUG_PALLOC)
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 0);
    }
#endif

    return ngx_palloc_large(pool, size);
}

void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    p = ngx_palloc(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


ngx_pool_t *
ngx_create_pool(size_t size)
{
    ngx_pool_t  *p;

    p = ngx_memalign(NGX_POOL_ALIGNMENT, size);
    if (p == NULL) {
        return NULL;
    }

    p->d.last = (u_char *) p + sizeof(ngx_pool_t);
    p->d.end = (u_char *) p + size;
    p->d.next = NULL;
    p->d.failed = 0;

    size = size - sizeof(ngx_pool_t);
    p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;

    p->current = p;
    //p->chain = NULL;
    p->large = NULL;
    //p->cleanup = NULL;
    //p->log = log;

    return p;
}




void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_t          *p, *n;
    ngx_pool_large_t    *l;
  //  ngx_pool_cleanup_t  *c;




    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        ngx_free(p);

        if (n == NULL) {
            break;
        }
    }
}




static inline ngx_int_t
ngx_array_init22(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n, size_t size)
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






ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }

    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}


void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t  *p;

    p = a->pool;

    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }

    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}


void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;

    if (a->nelts == a->nalloc) {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;

        if ((u_char *) a->elts + size == p->d.last
            && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += a->size;
            a->nalloc++;

        } else {
            /* allocate a new array */

            new = ngx_palloc(p, 2 * size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;

    return elt;
}


void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

    size = n * a->size;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;

        } else {
            /* allocate a new array */

            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = ngx_palloc(p, nalloc * a->size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}

/*

pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
   if (pool == NULL) {
	   return NGX_CONF_ERROR;
   }*/


#define NGX_UNESCAPE_URI       1
#define NGX_UNESCAPE_REDIRECT  2
   
   uintptr_t
   ngx_escape_uri(u_char *dst, u_char *src, size_t size, ngx_uint_t type)
   {
	   ngx_uint_t	   n;
	   uint32_t 	  *escape;
	   static u_char   hex[] = "0123456789ABCDEF";
   
					   /* " ", "#", "%", "?", %00-%1F, %7F-%FF */
   
	   static uint32_t	 uri[] = {
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
   
					   /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		   0x80000029, /* 1000 0000 0000 0000  0000 0000 0010 1001 */
   
					   /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		   0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
   
					   /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		   0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */
   
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	   };
   
					   /* " ", "#", "%", "&", "+", "?", %00-%1F, %7F-%FF */
   
	   static uint32_t	 args[] = {
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
   
					   /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		   0x88000869, /* 1000 1000 0000 0000  0000 1000 0110 1001 */
   
					   /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		   0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
   
					   /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		   0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */
   
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	   };
   
					   /* not ALPHA, DIGIT, "-", ".", "_", "~" */
   
	   static uint32_t	 uri_component[] = {
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
   
					   /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		   0xfc009fff, /* 1111 1100 0000 0000  1001 1111 1111 1111 */
   
					   /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		   0x78000001, /* 0111 1000 0000 0000  0000 0000 0000 0001 */
   
					   /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		   0xb8000001, /* 1011 1000 0000 0000  0000 0000 0000 0001 */
   
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	   };
   
					   /* " ", "#", """, "%", "'", %00-%1F, %7F-%FF */
   
	   static uint32_t	 html[] = {
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
   
					   /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		   0x000000ad, /* 0000 0000 0000 0000  0000 0000 1010 1101 */
   
					   /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		   0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
   
					   /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		   0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */
   
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	   };
   
					   /* " ", """, "%", "'", %00-%1F, %7F-%FF */
   
	   static uint32_t	 refresh[] = {
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
   
					   /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		   0x00000085, /* 0000 0000 0000 0000  0000 0000 1000 0101 */
   
					   /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		   0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
   
					   /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		   0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */
   
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		   0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	   };
   
					   /* " ", "%", %00-%1F */
   
	   static uint32_t	 memcached[] = {
		   0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
   
					   /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		   0x00000021, /* 0000 0000 0000 0000  0000 0000 0010 0001 */
   
					   /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		   0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
   
					   /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		   0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
   
		   0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
		   0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
		   0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
		   0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
	   };
   
					   /* mail_auth is the same as memcached */
   
	   static uint32_t	*map[] =
		   { uri, args, uri_component, html, refresh, memcached, memcached };
   
   
	   escape = map[type];
   
	   if (dst == NULL) {
   
		   /* find the number of the characters to be escaped */
   
		   n = 0;
   
		   while (size) {
			   if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
				   n++;
			   }
			   src++;
			   size--;
		   }
   
		   return (uintptr_t) n;
	   }
   
	   while (size) {
		   if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
			   *dst++ = '%';
			   *dst++ = hex[*src >> 4];
			   *dst++ = hex[*src & 0xf];
			   src++;
   
		   } else {
			   *dst++ = *src++;
		   }
		   size--;
	   }
   
	   return (uintptr_t) dst;
   }



   
   void
   ngx_unescape_uri(u_char **dst, u_char **src, size_t size, ngx_uint_t type)
   {
	   u_char  *d, *s, ch, c, decoded;
	   enum {
		   sw_usual = 0,
		   sw_quoted,
		   sw_quoted_second
	   } state;
   
	   d = *dst;
	   s = *src;
   
	   state = 0;
	   decoded = 0;
   
	   while (size--) {
   
		   ch = *s++;
   
		   switch (state) {
		   case sw_usual:
			   if (ch == '?'
				   && (type & (NGX_UNESCAPE_URI|NGX_UNESCAPE_REDIRECT)))
			   {
				   *d++ = ch;
				   goto done;
			   }
   
			   if (ch == '%') {
				   state = sw_quoted;
				   break;
			   }
   
			   *d++ = ch;
			   break;
   
		   case sw_quoted:
   
			   if (ch >= '0' && ch <= '9') {
				   decoded = (u_char) (ch - '0');
				   state = sw_quoted_second;
				   break;
			   }
   
			   c = (u_char) (ch | 0x20);
			   if (c >= 'a' && c <= 'f') {
				   decoded = (u_char) (c - 'a' + 10);
				   state = sw_quoted_second;
				   break;
			   }
   
			   /* the invalid quoted character */
   
			   state = sw_usual;
   
			   *d++ = ch;
   
			   break;
   
		   case sw_quoted_second:
   
			   state = sw_usual;
   
			   if (ch >= '0' && ch <= '9') {
				   ch = (u_char) ((decoded << 4) + (ch - '0'));
   
				   if (type & NGX_UNESCAPE_REDIRECT) {
					   if (ch > '%' && ch < 0x7f) {
						   *d++ = ch;
						   break;
					   }
   
					   *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);
   
					   break;
				   }
   
				   *d++ = ch;
   
				   break;
			   }
   
			   c = (u_char) (ch | 0x20);
			   if (c >= 'a' && c <= 'f') {
				   ch = (u_char) ((decoded << 4) + (c - 'a') + 10);
   
				   if (type & NGX_UNESCAPE_URI) {
					   if (ch == '?') {
						   *d++ = ch;
						   goto done;
					   }
   
					   *d++ = ch;
					   break;
				   }
   
				   if (type & NGX_UNESCAPE_REDIRECT) {
					   if (ch == '?') {
						   *d++ = ch;
						   goto done;
					   }
   
					   if (ch > '%' && ch < 0x7f) {
						   *d++ = ch;
						   break;
					   }
   
					   *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);
					   break;
				   }
   
				   *d++ = ch;
   
				   break;
			   }
   
			   /* the invalid quoted character */
   
			   break;
		   }
	   }
   
   done:
   
	   *dst = d;
	   *src = s;
   }
   
   
   uintptr_t
   ngx_escape_html(u_char *dst, u_char *src, size_t size)
   {
	   u_char	   ch;
	   ngx_uint_t  len;
   
	   if (dst == NULL) {
   
		   len = 0;
   
		   while (size) {
			   switch (*src++) {
   
			   case '<':
				   len += sizeof("&lt;") - 2;
				   break;
   
			   case '>':
				   len += sizeof("&gt;") - 2;
				   break;
   
			   case '&':
				   len += sizeof("&amp;") - 2;
				   break;
   
			   case '"':
				   len += sizeof("&quot;") - 2;
				   break;
   
			   default:
				   break;
			   }
			   size--;
		   }
   
		   return (uintptr_t) len;
	   }
   
	   while (size) {
		   ch = *src++;
   
		   switch (ch) {
   
		   case '<':
			   *dst++ = '&'; *dst++ = 'l'; *dst++ = 't'; *dst++ = ';';
			   break;
   
		   case '>':
			   *dst++ = '&'; *dst++ = 'g'; *dst++ = 't'; *dst++ = ';';
			   break;
   
		   case '&':
			   *dst++ = '&'; *dst++ = 'a'; *dst++ = 'm'; *dst++ = 'p';
			   *dst++ = ';';
			   break;
   
		   case '"':
			   *dst++ = '&'; *dst++ = 'q'; *dst++ = 'u'; *dst++ = 'o';
			   *dst++ = 't'; *dst++ = ';';
			   break;
   
		   default:
			   *dst++ = ch;
			   break;
		   }
		   size--;
	   }
   
	   return (uintptr_t) dst;
   }
   
   
   uintptr_t
   ngx_escape_json(u_char *dst, u_char *src, size_t size)
   {
	   u_char	   ch;
	   ngx_uint_t  len;
   
	   if (dst == NULL) {
		   len = 0;
   
		   while (size) {
			   ch = *src++;
   
			   if (ch == '\\' || ch == '"') {
				   len++;
   
			   } else if (ch <= 0x1f) {
   
				   switch (ch) {
				   case '\n':
				   case '\r':
				   case '\t':
				   case '\b':
				   case '\f':
					   len++;
					   break;
   
				   default:
					   len += sizeof("\\u001F") - 2;
				   }
			   }
   
			   size--;
		   }
   
		   return (uintptr_t) len;
	   }
   
	   while (size) {
		   ch = *src++;
   
		   if (ch > 0x1f) {
   
			   if (ch == '\\' || ch == '"') {
				   *dst++ = '\\';
			   }
   
			   *dst++ = ch;
   
		   } else {
			   *dst++ = '\\';
   
			   switch (ch) {
			   case '\n':
				   *dst++ = 'n';
				   break;
   
			   case '\r':
				   *dst++ = 'r';
				   break;
   
			   case '\t':
				   *dst++ = 't';
				   break;
   
			   case '\b':
				   *dst++ = 'b';
				   break;
   
			   case '\f':
				   *dst++ = 'f';
				   break;
   
			   default:
				   *dst++ = 'u'; *dst++ = '0'; *dst++ = '0';
				   *dst++ = '0' + (ch >> 4);
   
				   ch &= 0xf;
   
				   *dst++ = (ch < 10) ? ('0' + ch) : ('A' + ch - 10);
			   }
		   }
   
		   size--;
	   }
   
	   return (uintptr_t) dst;
   }

