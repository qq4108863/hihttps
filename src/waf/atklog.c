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
 * For more ,please contact QQ:4108863/wechat:wmkwang/mail:4108863@qq.com
 * http://www.hihttps.com
 */


#include <sys/types.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "httpx.h"
#include "mqtt.h"
#include "rules.h"



//Attack log to file ,or send udp to log data center


int logsockfd = -1;
FILE * atk_log_file = NULL;

#define MAX_STAT 8
typedef struct statlog_s  {
    unsigned int  ip;
    unsigned int  cum_conn; 
    unsigned long bytes_in; 
    unsigned long bytes_out;
    unsigned long cum_req;
    unsigned long cum_atk;     
    unsigned long cum_err;     
} statlog_t;

/*SSLLOGCENTER  专业版把攻击数据提交到分布式日志中心

*/



statlog_t statlog[MAX_STAT] = { 0 };
time_t last_time = 0;




/**
* print_log 调试16进制打印输出
*
* @name 名字
* @data 打印的内容
* len   打印的字节数
* @return 无
*/

static void print_log(char *name,unsigned char *data,int len)
{
    int i,j,k;

    //if(!debug_mode)
        //return;
    
    if(name) printf("-------%s-------%dbytes-----------------------------\n",name,len);

    for (i=0; i<len; i+=16) {
        printf("| ");
        for (j=i, k=0; k<16 && j<len; ++j, ++k)
            printf("%.2x ",data[j]);
        for (; k<16; ++k)
            printf("   ");
       printf("|");
        for (j=i, k=0; k<16 && j<len; ++j, ++k) {
            unsigned char c = data[j];
            if (!isprint(c) || (c=='\t')) c = '.';
            printf("%c",c);
        }
        for (; k<16; ++k)
            printf("   ");
        printf("|\n");
    }

}



void send_stat_logcenter(void )
{

    return;

}


void zero_stat_log(void)
{
    memset(&statlog,0,sizeof(statlog));
    
}

void bytes_stat(struct sockaddr_storage addr,int in,int out)
{
    return;

}

void req_stat(struct sockaddr_storage addr,int req,int atk)
{
    unsigned int src;
    int i;
    
    switch (addr.ss_family) {
    case AF_INET:
        src = ((struct sockaddr_in *)&addr)->sin_addr.s_addr;    
        break;
    case AF_INET6:        
        return;
    default:
        return;
    }
    
    src = ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
    for(i = 0;i < MAX_STAT;i++)
    {
        if(statlog[i].ip == src)
        {
            statlog[i].cum_req  += req;
            statlog[i].cum_atk  += atk;
            break;
        }
        
    }
    

    
}






void open_log_socket(void)
{
   return;
    

}




void init_atk_log(void)
{
    struct tm *tm_now;
    time_t now;
    char filename[64];

    if(gvar.log == 0)
        return;

    time(&now);
    tm_now = localtime(&now);

    snprintf(filename,127,"/var/log/%.2d-%.2d-%.2d.log",1900+tm_now->tm_year, 1+tm_now->tm_mon, tm_now->tm_mday);
    atk_log_file = fopen(filename,"a");

}



void send_to_logcenter(struct sockaddr_storage addr,http_waf_msg *req,char *detail,char *raw_buf,int raw_len)
{

    
    return;

}

/*

08/09/2017-21:15:51.526950  [**] [1:2240002:1] SURICATA DNS malformed request data [**] [Classification: (null)] [Priority: 3]
{UDP} 192.168.80.2:53 -> 192.168.80.86:52492

07/01/2014-04:21:06.994705 vg.no [**] / [**] Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2)
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.114 Safari/537.36 [**] <no referer> [**]
GET [**] HTTP/1.1 [**] 301 => http://www.vg.no/ [**] 239 bytes [**] 192.168.1.6:64726 -> 195.88.54.16:80


*/
void log_http_to_file(struct sockaddr_storage addr,http_waf_msg *req,int action,char *raw_buf,int raw_len)
{

    struct timeval tv;
    struct tm tm;
    char buf[2048],ip_port[32];
    int  len, max_len,msg_len;


    /*already logged*/
    
    if(req->logcenter)
        return;

    req_stat(addr, 1, 0); /*req_cnt*/
    req_stat(addr, 0, 1);/*atk_cnt*/
    
    msg_len = sizeof(buf) - 8;
    max_len = msg_len;

    
    
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);

    len = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S  ", &tm);
    max_len = msg_len - len;
    
    //snprintf(buf + n, sizeof(buf) - n, ".%06d [%5d] %s",    (int) tv.tv_usec, getpid(), fmt);

    snprintf(ip_port,sizeof(ip_port)-1,"%s:%d",inet_ntoa(((struct sockaddr_in *)&addr)->sin_addr),
             ntohs(((struct  sockaddr_in*)&addr)->sin_port));
    len += snprintf(buf + len,max_len,"%s",ip_port);             
    max_len = msg_len - len;
    
    

    if(action == ALERT)
    {
        len += snprintf(buf + len,max_len," [*ALERT*] ");             
        max_len = msg_len - len;
    }
    
    if(action == DROP)
    {
        len += snprintf(buf + len,max_len," [*DROP*] ");             
        max_len = msg_len - len;
    }

    len += snprintf(buf + len,max_len," [%d] [",req->rule_id);             
    max_len = msg_len - len;
    
    if(req->mtd == HTTP_MT_GET)
    {
        len += snprintf(buf + len,max_len,"GET ",req->req_dir);             
        max_len = msg_len - len;
    }
    if(req->mtd == HTTP_MT_POST)
    {
        len += snprintf(buf + len,max_len,"POST ",req->req_dir);             
        max_len = msg_len - len;
    }

    if(req->req_dir)
    {
        len += snprintf(buf + len,max_len,"%s",req->req_dir);             
        max_len = msg_len - len;
        if(max_len < 0)
            goto end;
    }
    if(req->req_file)
    {
        len += snprintf(buf + len,max_len,"/%s]",req->req_file);             
        max_len = msg_len - len;
        if(max_len < 0)
            goto end;
    }

    
    if(req->str_matched)
    {
        len += snprintf(buf + len,max_len," STR:\"%s\" Matched,",req->str_matched);             
        max_len = msg_len - len;
        if(max_len < 0)
                goto end;
    }
    

    if(req->log_msg)
    {
        len += snprintf(buf + len,max_len," %s \n",req->log_msg);             
        max_len = msg_len - len;
        if(max_len < 0)
            goto end;
    }
    

    //You can add more detail logs here, such as  whole http get header or more body......
    //呵呵，谢谢看到这里了，更多日志管理中心代码请咨询商业版....QQ:4108863/wechat:wmkwang 
    
    
    end:
    
    printf("%s",buf);
    send_to_logcenter(addr, req, buf,raw_buf,raw_len);
    req->logcenter = 1;
    
    if(gvar.log && atk_log_file)
    {
        fwrite(buf,strlen(buf),1,atk_log_file);
        fflush(atk_log_file);
    }

}


/*

08/09/2017-21:15:51.526950  [**] [1:2240002:1] SURICATA DNS malformed request data [**] [Classification: (null)] [Priority: 3]
{UDP} 192.168.80.2:53 -> 192.168.80.86:52492

*/
void log_mqtt_to_file(struct sockaddr_storage addr,mqtt_waf_msg *req,int action,char *raw_buf,int raw_len)
{

    struct timeval tv;
    struct tm tm;
    char buf[2048],ip_port[32];
    int  len, max_len,msg_len;


    /*already logged*/
    
    if(req->logcenter)
        return;

    req_stat(addr, 1, 0); /*req_cnt*/
    req_stat(addr, 0, 1);/*atk_cnt*/
    
    msg_len = sizeof(buf) - 8;
    max_len = msg_len;

    
    
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);

    len = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S  ", &tm);
    max_len = msg_len - len;
    
    //snprintf(buf + n, sizeof(buf) - n, ".%06d [%5d] %s",    (int) tv.tv_usec, getpid(), fmt);

    snprintf(ip_port,sizeof(ip_port)-1,"%s:%d",inet_ntoa(((struct sockaddr_in *)&addr)->sin_addr),
             ntohs(((struct  sockaddr_in*)&addr)->sin_port));
    len += snprintf(buf + len,max_len,"%s",ip_port);             
    max_len = msg_len - len;
    
    

    if(action == ALERT)
    {
        len += snprintf(buf + len,max_len," [*ALERT*] ");             
        max_len = msg_len - len;
    }
    
    if(action == DROP)
    {
        len += snprintf(buf + len,max_len," [*DROP*] ");             
        max_len = msg_len - len;
    }

    len += snprintf(buf + len,max_len," [%d] [",req->rule_id);             
    max_len = msg_len - len;
    
    /*
    if(req->mtd == HTTP_MT_GET)
    {
        len += snprintf(buf + len,max_len,"GET ",req->req_dir);             
        max_len = msg_len - len;
    }
    if(req->mtd == HTTP_MT_POST)
    {
        len += snprintf(buf + len,max_len,"POST ",req->req_dir);             
        max_len = msg_len - len;
    }

    if(req->req_dir)
    {
        len += snprintf(buf + len,max_len,"%s",req->req_dir);             
        max_len = msg_len - len;
        if(max_len < 0)
            goto end;
    }
    if(req->req_file)
    {
        len += snprintf(buf + len,max_len,"/%s]",req->req_file);             
        max_len = msg_len - len;
        if(max_len < 0)
            goto end;
    }*/

    
    if(req->str_matched)
    {
        len += snprintf(buf + len,max_len," STR:\"%s\" Matched,",req->str_matched);             
        max_len = msg_len - len;
        if(max_len < 0)
            goto end;
    }
    

    if(req->log_msg)
    {
        len += snprintf(buf + len,max_len," %s \n",req->log_msg);             
        max_len = msg_len - len;
        if(max_len < 0)
            goto end;
    }
    

    //You can add more detail logs here, such as  whole http get header or more body......
    //呵呵，谢谢看到这里了，更多日志管理中心代码请咨询商业版....QQ:4108863/wechat:wmkwang 
    
    
    end:
    
    printf("%s",buf);
    send_to_logcenter(addr, (http_waf_msg *)req, buf,raw_buf,raw_len);
    req->logcenter = 1;
    
    if(gvar.log && atk_log_file)
    {
        fwrite(buf,strlen(buf),1,atk_log_file);
        fflush(atk_log_file);
    }

}


