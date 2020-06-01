/* Expectation Maximization for Gaussian Mixture Models.
Copyright (C) 2012-2014 Juan Daniel Valor Miro

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details. */

#ifndef _ai_train_h
#define _ai_train_h
#include "rbtree.h"
#include "../waf/httpx.h"
#include "../waf/rules.h"



#define         AI_JSON_MAX_DEPTH     8




typedef struct ngx_train_node_s   ngx_train_node_t;

struct ngx_train_node_s {
    u_char                  *data;
	size_t                   len;
	ngx_train_node_t        *next;
};

typedef struct ngx_list_s  ngx_list_t;


struct ngx_list_s {
	u_char                  *data;
    double                  sigma;
    double                  mean;
    ngx_uint_t              num; // 8 bytes of x64
    int                     is_number; 
    int                     test;
    char                    dim[8];
    ngx_train_node_t        *node; 
    ngx_list_t              *next;
	
};


typedef struct {
    double                  mean;
    double                  sigma;
    ngx_uint_t              num;
    unsigned char           *name;   
}ai_http_rule_t;

typedef struct ngx_cached_open_file_s  ngx_cached_open_file_t;

struct ngx_cached_open_file_s {
    ngx_rbtree_node_t        node;
   

    u_char                  *name;
    time_t                   created;
    time_t                   accessed;

   
    uint32_t                 uses;
	uint32_t                 offset;
	uint32_t                 num;

    ai_http_rule_t           uri_rule;
    ngx_list_t               *args_rule;
    char                     *vocab;
    int                      words;
    

    unsigned                 gan:1;
    unsigned                 count:24;
    unsigned                 close:1;
    unsigned                 use_event:1;

    unsigned                 is_dir:1;
    unsigned                 is_file:1;
    unsigned                 is_link:1;
    unsigned                 is_exec:1;
    unsigned                 is_directio:1;

};



typedef struct {
    ngx_rbtree_t             rbtree;
    ngx_rbtree_node_t        sentinel;
    //ngx_queue_t              expire_queue;

    ngx_uint_t               current;
    ngx_uint_t               max;
    time_t                   inactive;
} ngx_open_file_cache_t;


/*
** this structure is used only for json parsing.
*/
typedef struct ai_json_s {
    ngx_str_t	            json;
    u_char	               *src;
    ngx_int_t	            off, len;
    u_char	                c;
    int		                depth;
    int                     num; 
    int                     only_count;
    int                     detect;
    ngx_str_t	            ckey;
    ngx_str_t               name[AI_JSON_MAX_DEPTH];
    ngx_cached_open_file_t  *file;
    http_waf_msg            *req;    
} ai_json_t;

/* faster than calling out to libc isdigit */
#define ISDIGIT(a) ((unsigned)((a) - '0') <= 9)


ngx_int_t 
judge_if_json_format(u_char *begin,int len);

void ai_file_train_init(char *exe_dir);	
ngx_cached_open_file_t * 
save_train_http_data(u_char *url,u_char *data,int len,int method);

ngx_cached_open_file_t * 
save_train_http_post_data(u_char *dir,u_char *file,u_char *data,int len,http_waf_msg *req);

ngx_cached_open_file_t *
save_train_mqtt_data(ngx_str_t *topic,ngx_str_t *payload,http_waf_msg *req);




#endif
