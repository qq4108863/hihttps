

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
 * For more ,please contact QQ:4108863 weichat:wmkwang mail:4108863@qq.com
 */

#ifndef __ATTACK_LOG_H__
#define __ATTACK_LOG_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "httpx.h"
#include "mqtt.h"



	
void init_atk_log(void);
void open_log_socket(void);

void log_http_to_file(struct sockaddr_storage addr,http_waf_msg *req,int action,char *raw_buf,int raw_len);
void log_mqtt_to_file(struct sockaddr_storage addr,mqtt_waf_msg *req,int action,char *raw_buf,int raw_len);
void bytes_stat(struct sockaddr_storage addr,int in,int out);
void req_stat(struct sockaddr_storage addr,int req,int atk);





#endif


