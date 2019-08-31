

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include "ssl_array.h"
#include "ssl_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>

ngx_uint_t  ngx_cacheline_size = 64;


void
ngx_strlow(u_char *dst, u_char *src, size_t n)
{
    while (n) {
        *dst = ngx_tolower(*src);
        dst++;
        src++;
        n--;
    }
}

u_char *
ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }

    while (--n) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }

        dst++;
        src++;
    }

    *dst = '\0';

    return dst;
}




void *
ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len)
{
    ngx_uint_t       i;
    ngx_hash_elt_t  *elt;

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "hf:\"%*s\"", len, name);
#endif

    elt = hash->buckets[key % hash->size];

    if (elt == NULL) {
        return NULL;
    }

    while (elt->value) {
        if (len != (size_t) elt->len) {
            goto next;
        }

        for (i = 0; i < len; i++) {
            if (name[i] != elt->name[i]) {
                goto next;
            }
        }

        return elt->value;

    next:

        elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
                                               sizeof(void *));
        continue;
    }

    return NULL;
}


#define NGX_HASH_ELT_SIZE(name)                                               \
    (sizeof(void *) + ngx_align((name)->key.len + 2, sizeof(void *)))


	
	ngx_int_t
	ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names, ngx_uint_t nelts)
	{
		u_char			*elts;
		size_t			 len;
		u_short 		*test;
		ngx_uint_t		 i, n, key, size, start, bucket_size;
		ngx_hash_elt_t	*elt, **buckets;
	
		if (hinit->max_size == 0) {
			
			return NGX_ERROR;
		}
	
		for (n = 0; n < nelts; n++) {
			if (hinit->bucket_size < NGX_HASH_ELT_SIZE(&names[n]) + sizeof(void *))
			{
				
				return NGX_ERROR;
			}
		}
	
		test = ngx_alloc(hinit->max_size * sizeof(u_short));
		if (test == NULL) {
			return NGX_ERROR;
		}
	
		bucket_size = hinit->bucket_size - sizeof(void *);
	
		start = nelts / (bucket_size / (2 * sizeof(void *)));
		start = start ? start : 1;
	
		if (hinit->max_size > 10000 && nelts && hinit->max_size / nelts < 100) {
			start = hinit->max_size - 1000;
		}
	
		for (size = start; size <= hinit->max_size; size++) {
	
			ngx_memzero(test, size * sizeof(u_short));
	
			for (n = 0; n < nelts; n++) {
				if (names[n].key.data == NULL) {
					continue;
				}
	
				key = names[n].key_hash % size;
				test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));
	
#if 0
				ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
							  "%ui: %ui %ui \"%V\"",
							  size, key, test[key], &names[n].key);
#endif
	
				if (test[key] > (u_short) bucket_size) {
					goto next;
				}
			}
	
			goto found;
	
		next:
	
			continue;
		}
	
		size = hinit->max_size;
	
		
	
	found:
	
		for (i = 0; i < size; i++) {
			test[i] = sizeof(void *);
		}
	
		for (n = 0; n < nelts; n++) {
			if (names[n].key.data == NULL) {
				continue;
			}
	
			key = names[n].key_hash % size;
			test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));
		}
	
		len = 0;
	
		for (i = 0; i < size; i++) {
			if (test[i] == sizeof(void *)) {
				continue;
			}
	
			test[i] = (u_short) (ngx_align(test[i], ngx_cacheline_size));
	
			len += test[i];
		}
	
		if (hinit->hash == NULL) {
			hinit->hash = ngx_pcalloc(hinit->pool, sizeof(ngx_hash_wildcard_t)
												 + size * sizeof(ngx_hash_elt_t *));
			if (hinit->hash == NULL) {
				ngx_free(test);
				return NGX_ERROR;
			}
	
			buckets = (ngx_hash_elt_t **)
						  ((u_char *) hinit->hash + sizeof(ngx_hash_wildcard_t));
	
		} else {
			buckets = ngx_pcalloc(hinit->pool, size * sizeof(ngx_hash_elt_t *));
			if (buckets == NULL) {
				ngx_free(test);
				return NGX_ERROR;
			}
		}
	
		elts = ngx_palloc(hinit->pool, len + ngx_cacheline_size);
		if (elts == NULL) {
			ngx_free(test);
			return NGX_ERROR;
		}
	
		elts = ngx_align_ptr(elts, ngx_cacheline_size);
	
		for (i = 0; i < size; i++) {
			if (test[i] == sizeof(void *)) {
				continue;
			}
	
			buckets[i] = (ngx_hash_elt_t *) elts;
			elts += test[i];
		}
	
		for (i = 0; i < size; i++) {
			test[i] = 0;
		}
	
		for (n = 0; n < nelts; n++) {
			if (names[n].key.data == NULL) {
				continue;
			}
	
			key = names[n].key_hash % size;
			elt = (ngx_hash_elt_t *) ((u_char *) buckets[key] + test[key]);
	
			elt->value = names[n].value;
			elt->len = (u_short) names[n].key.len;
	
			ngx_strlow(elt->name, names[n].key.data, names[n].key.len);
	
			test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));
		}
	
		for (i = 0; i < size; i++) {
			if (buckets[i] == NULL) {
				continue;
			}
	
			elt = (ngx_hash_elt_t *) ((u_char *) buckets[i] + test[i]);
	
			elt->value = NULL;
		}
	
		ngx_free(test);
	
		hinit->hash->buckets = buckets;
		hinit->hash->size = size;
	
#if 0
	
		for (i = 0; i < size; i++) {
			ngx_str_t	val;
			ngx_uint_t	key;
	
			elt = buckets[i];
	
			if (elt == NULL) {
				ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
							  "%ui: NULL", i);
				continue;
			}
	
			while (elt->value) {
				val.len = elt->len;
				val.data = &elt->name[0];
	
				key = hinit->key(val.data, val.len);
	
				ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
							  "%ui: %p \"%V\" %ui", i, elt, &val, key);
	
				elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
													   sizeof(void *));
			}
		}
	
#endif
	
		return NGX_OK;
	}



	ngx_uint_t
ngx_hash_key(u_char *data, size_t len)
{
    ngx_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = ngx_hash(key, data[i]);
    }

    return key;
}


ngx_uint_t
ngx_hash_key_lc(u_char *data, size_t len)
{
    ngx_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = ngx_hash(key, ngx_tolower(data[i]));
    }

    return key;
}


ngx_uint_t
ngx_hash_strlow(u_char *dst, u_char *src, size_t n)
{
    ngx_uint_t  key;

    key = 0;

    while (n--) {
        *dst = ngx_tolower(*src);
        key = ngx_hash(key, *dst);
        dst++;
        src++;
    }

    return key;
}



ngx_int_t
ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type)
{
    ngx_uint_t  asize;

    if (type == NGX_HASH_SMALL) {
        asize = 4;
        ha->hsize = 107;

    } else {
        asize = NGX_HASH_LARGE_ASIZE;
        ha->hsize = NGX_HASH_LARGE_HSIZE;
    }

    if (ngx_array_init(&ha->keys, ha->temp_pool, asize, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&ha->dns_wc_head, ha->temp_pool, asize,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&ha->dns_wc_tail, ha->temp_pool, asize,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ha->keys_hash = ngx_pcalloc(ha->temp_pool, sizeof(ngx_array_t) * ha->hsize);
    if (ha->keys_hash == NULL) {
        return NGX_ERROR;
    }

    ha->dns_wc_head_hash = ngx_pcalloc(ha->temp_pool,
                                       sizeof(ngx_array_t) * ha->hsize);
    if (ha->dns_wc_head_hash == NULL) {
        return NGX_ERROR;
    }

    ha->dns_wc_tail_hash = ngx_pcalloc(ha->temp_pool,
                                       sizeof(ngx_array_t) * ha->hsize);
    if (ha->dns_wc_tail_hash == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}



ngx_int_t
ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key, void *value,
    ngx_uint_t flags)
{
    size_t           len;
    u_char          *p;
    ngx_str_t       *name;
    ngx_uint_t       i, k, n, skip, last;
    ngx_array_t     *keys, *hwc;
    ngx_hash_key_t  *hk;

    last = key->len;

    if (flags & NGX_HASH_WILDCARD_KEY) {

        /*
         * supported wildcards:
         *     "*.example.com", ".example.com", and "www.example.*"
         */

        n = 0;

        for (i = 0; i < key->len; i++) {

            if (key->data[i] == '*') {
                if (++n > 1) {
                    return NGX_DECLINED;
                }
            }

            if (key->data[i] == '.' && key->data[i + 1] == '.') {
                return NGX_DECLINED;
            }

            if (key->data[i] == '\0') {
                return NGX_DECLINED;
            }
        }

        if (key->len > 1 && key->data[0] == '.') {
            skip = 1;
            goto wildcard;
        }

        if (key->len > 2) {

            if (key->data[0] == '*' && key->data[1] == '.') {
                skip = 2;
                goto wildcard;
            }

            if (key->data[i - 2] == '.' && key->data[i - 1] == '*') {
                skip = 0;
                last -= 2;
                goto wildcard;
            }
        }

        if (n) {
            return NGX_DECLINED;
        }
    }

    /* exact hash */

    k = 0;

    for (i = 0; i < last; i++) {
        if (!(flags & NGX_HASH_READONLY_KEY)) {
            key->data[i] = ngx_tolower(key->data[i]);
        }
        k = ngx_hash(k, key->data[i]);
    }

    k %= ha->hsize;

    /* check conflicts in exact hash */

    name = ha->keys_hash[k].elts;

    if (name) {
        for (i = 0; i < ha->keys_hash[k].nelts; i++) {
            if (last != name[i].len) {
                continue;
            }

            if (ngx_strncmp(key->data, name[i].data, last) == 0) {
                return NGX_BUSY;
            }
        }

    } else {
        if (ngx_array_init(&ha->keys_hash[k], ha->temp_pool, 4,
                           sizeof(ngx_str_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    name = ngx_array_push(&ha->keys_hash[k]);
    if (name == NULL) {
        return NGX_ERROR;
    }

    *name = *key;

    hk = ngx_array_push(&ha->keys);
    if (hk == NULL) {
        return NGX_ERROR;
    }

    hk->key = *key;
    hk->key_hash = ngx_hash_key(key->data, last);
    hk->value = value;

    return NGX_OK;


wildcard:

    /* wildcard hash */

    k = ngx_hash_strlow(&key->data[skip], &key->data[skip], last - skip);

    k %= ha->hsize;

    if (skip == 1) {

        /* check conflicts in exact hash for ".example.com" */

        name = ha->keys_hash[k].elts;

        if (name) {
            len = last - skip;

            for (i = 0; i < ha->keys_hash[k].nelts; i++) {
                if (len != name[i].len) {
                    continue;
                }

                if (ngx_strncmp(&key->data[1], name[i].data, len) == 0) {
                    return NGX_BUSY;
                }
            }

        } else {
            if (ngx_array_init(&ha->keys_hash[k], ha->temp_pool, 4,
                               sizeof(ngx_str_t))
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        name = ngx_array_push(&ha->keys_hash[k]);
        if (name == NULL) {
            return NGX_ERROR;
        }

        name->len = last - 1;
        name->data = ngx_pnalloc(ha->temp_pool, name->len);
        if (name->data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(name->data, &key->data[1], name->len);
    }


    if (skip) {

        /*
         * convert "*.example.com" to "com.example.\0"
         *      and ".example.com" to "com.example\0"
         */

        p = ngx_pnalloc(ha->temp_pool, last);
        if (p == NULL) {
            return NGX_ERROR;
        }

        len = 0;
        n = 0;

        for (i = last - 1; i; i--) {
            if (key->data[i] == '.') {
                ngx_memcpy(&p[n], &key->data[i + 1], len);
                n += len;
                p[n++] = '.';
                len = 0;
                continue;
            }

            len++;
        }

        if (len) {
            ngx_memcpy(&p[n], &key->data[1], len);
            n += len;
        }

        p[n] = '\0';

        hwc = &ha->dns_wc_head;
        keys = &ha->dns_wc_head_hash[k];

    } else {

        /* convert "www.example.*" to "www.example\0" */

        last++;

        p = ngx_pnalloc(ha->temp_pool, last);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_cpystrn(p, key->data, last);

        hwc = &ha->dns_wc_tail;
        keys = &ha->dns_wc_tail_hash[k];
    }


    /* check conflicts in wildcard hash */

    name = keys->elts;

    if (name) {
        len = last - skip;

        for (i = 0; i < keys->nelts; i++) {
            if (len != name[i].len) {
                continue;
            }

            if (ngx_strncmp(key->data + skip, name[i].data, len) == 0) {
                return NGX_BUSY;
            }
        }

    } else {
        if (ngx_array_init(keys, ha->temp_pool, 4, sizeof(ngx_str_t)) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    name = ngx_array_push(keys);
    if (name == NULL) {
        return NGX_ERROR;
    }

    name->len = last - skip;
    name->data = ngx_pnalloc(ha->temp_pool, name->len);
    if (name->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(name->data, key->data + skip, name->len);


    /* add to wildcard hash */

    hk = ngx_array_push(hwc);
    if (hk == NULL) {
        return NGX_ERROR;
    }

    hk->key.len = last - 1;
    hk->key.data = p;
    hk->key_hash = 0;
    hk->value = value;

    return NGX_OK;
}



