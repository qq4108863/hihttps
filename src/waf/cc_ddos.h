

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */
#ifndef __CCDDOS_H__
#define __CCDDOS_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "httpx.h"
	
typedef struct _cckey
{
	int count;
	int block_timeout;
	time_t t;

}ngx_cc_key_t;

void init_cc_ddos(void);
int process_cc_ddos(struct sockaddr_storage addr,http_waf_msg *req);
int if_block_connect(struct sockaddr_storage addr);




#endif


