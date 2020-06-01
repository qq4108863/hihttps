

/*
 * Copyright (C) QQ:4108863 wechat:wmkwang
 * Copyright (C) QQ:4108863 wechat:wmkwang
 */


#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/dir.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "hashmap.h"
#include "cc_ddos.h"
#include "httpx.h"
#include "rules.h"

Hashmap hash_cc_ddos;


int process_cc_ddos(struct sockaddr_storage addr,http_waf_msg *req)
{
    int i,block;
    char buf_cc_key[sizeof(ngx_cc_key_t)];
	char buf_uri[128],ip[32];
	
	ngx_cc_key_t *ip_uri_status;
	time_t t;
	
    snprintf(ip,sizeof(ip)-1,"%s",inet_ntoa(((struct sockaddr_in *)&addr)->sin_addr));
	snprintf(buf_uri,sizeof(buf_uri)-1,"ip=%s:%d",ip,req->rule_id);



	ip_uri_status = (ngx_cc_key_t *)hashmap_get(&hash_cc_ddos,buf_uri,0);
	if(!ip_uri_status)
	{
			memset(buf_cc_key,0,sizeof(ngx_cc_key_t));				
			hashmap_put_cckey(&hash_cc_ddos, buf_uri, 0,buf_cc_key, 0);	
			i = ((Hashmap *)&hash_cc_ddos)->used_slots;
			
			if(i > 1000000)
			{
				hashmap_close(&hash_cc_ddos);
				hashmap_open(&hash_cc_ddos,65521);
			}
			
			ip_uri_status = (ngx_cc_key_t *)hashmap_get(&hash_cc_ddos,buf_uri,0);
			if(!ip_uri_status)		
				return 0;			
	}

	time(&t);
	block = 0;
	
	if( ip_uri_status->t == 0 )
	    ip_uri_status->t = t;
	ip_uri_status->count++;

	//printf("DDOS %s burst_time_slice=%d,counter_threshold=%d,block_timeout=%d\n",buf_uri,
		//req->ddos_rule.burst_time_slice,req->ddos_rule.counter_threshold,req->ddos_rule.block_timeout);

	if((t - ip_uri_status->t) > req->ddos_rule.burst_time_slice)
	{
		ip_uri_status->t     = t;		
		ip_uri_status->count = 0;
	}

	else
	{
		if(ip_uri_status->count > req->ddos_rule.counter_threshold)
		{	
			ip_uri_status->t     = t;
			ip_uri_status->count = -10000;
			block = 1;			
		}
	}


	if(1 == block)
	{
		if (gvar.action == DROP) {
		    ip_uri_status = (ngx_cc_key_t *)hashmap_get(&hash_cc_ddos,ip,0);
    		if(!ip_uri_status)
    		{
    			memset(buf_cc_key,0,sizeof(ngx_cc_key_t));				
    			hashmap_put_cckey(&hash_cc_ddos, ip, 0,buf_cc_key, 0);	
    			ip_uri_status = (ngx_cc_key_t *)hashmap_get(&hash_cc_ddos,ip,0);
    			if(!ip_uri_status)		
    				return 0;	
    		}
        }
		
		ip_uri_status->t = t;
		ip_uri_status->block_timeout = req->ddos_rule.block_timeout;
		return gvar.action;
	}
	
	
   return 0;


}


int if_block_connect(struct sockaddr_storage addr)
{
	ngx_cc_key_t *ip_uri_status;
	time_t t;
	char ip[32];
	
	
	snprintf(ip,sizeof(ip)-1,"%s",inet_ntoa(((struct sockaddr_in *)&addr)->sin_addr));
	ip_uri_status = (ngx_cc_key_t *)hashmap_get(&hash_cc_ddos,ip,0);
	if(!ip_uri_status)
		return 0;
	
	time(&t);
	if((t - ip_uri_status->t) < ip_uri_status->block_timeout)
	{
		//printf("blocked ip=%s:%d,block_timeout=%d,left=%lus\n",ip,ntohs(((struct  sockaddr_in*)&addr)->sin_port),ip_uri_status->block_timeout,(t - ip_uri_status->t));
		return gvar.action;
	}

	

	return 0;
}


	
void init_cc_ddos(void)
{
		
	hashmap_open(&hash_cc_ddos, 65521);
	
}






