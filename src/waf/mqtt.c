 /*
  * Protocol description:
  *
  * MQTT is a Client Server publish/subscribe messaging transport
  * protocol. The protocol runs over TCP/IP, or over other network
  * protocols that provide ordered, lossless, bi-directional
  * connections.
  *
  * MQTT v3.1 specification:
  * http://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html
  *
  * MQTT v3.1.1 specification:
  * http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/
  *
  * MQTT v5.0 specification:
  * http://docs.oasis-open.org/mqtt/mqtt/v5.0/
  *
  
  *
  * For more ,please contact QQ:4108863/wechat:wmkwang/mail:4108863@qq.com
  * http://www.hihttps.com/
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


#include "mqtt.h"
#include "ssl_array.h"
#include "rules.h"
#include "ssl_utils.h"
#include "ssl_json.h"
#include "../machine-learning/machine-learning.h"


#define MAX_MQTT_PACKET_SIZE  65535

#define MQTT_DEFAULT_PORT     1883 /* IANA registered under service name as mqtt */
#define MQTT_SSL_DEFAULT_PORT 8883 /* IANA registered under service name secure-mqtt */
#define MQTT_ATK_ERR_HEAD  501

/* MQTT Protocol Versions */
#define MQTT_PROTO_V31      3
#define MQTT_PROTO_V311     4
#define MQTT_PROTO_V50      5

#define MQTT_HDR_SIZE_BEFORE_LEN 1

/* MQTT Message Types */
#define MQTT_RESERVED        0
#define MQTT_CONNECT         1
#define MQTT_CONNACK         2
#define MQTT_PUBLISH         3
#define MQTT_PUBACK          4
#define MQTT_PUBREC          5
#define MQTT_PUBREL          6
#define MQTT_PUBCOMP         7
#define MQTT_SUBSCRIBE       8
#define MQTT_SUBACK          9
#define MQTT_UNSUBSCRIBE    10
#define MQTT_UNSUBACK       11
#define MQTT_PINGREQ        12
#define MQTT_PINGRESP       13
#define MQTT_DISCONNECT     14
#define MQTT_AUTH           15
#define MQTT_RESERVED_16    16

/* Flag Values to extract fields */
#define MQTT_MASK_MSG_TYPE          0xF0
#define MQTT_MASK_HDR_RESERVED      0x0F
#define MQTT_MASK_HDR_DUP_RESERVED  0x07
#define MQTT_MASK_QOS               0x06
#define MQTT_MASK_DUP_FLAG          0x08
#define MQTT_MASK_RETAIN            0x01

/* MQTT v5.0 Flag Values for the Subscription Options @ Subscribe Packet */
#define MQTT_MASK_SUBS_QOS          0x03
#define MQTT_MASK_SUBS_NL           0x04
#define MQTT_MASK_SUBS_RAP          0x08
#define MQTT_MASK_SUBS_RETAIN       0x30
#define MQTT_MASK_SUBS_RESERVED     0xC0


#define MG_MQTT_ERROR_MALFORMED_MSG 0x04

/* Message flags */
#define MG_MQTT_RETAIN 0x1
#define MG_MQTT_DUP 0x4
#define MG_MQTT_QOS(qos) ((qos) << 1)
#define MG_MQTT_GET_QOS(flags) (((flags) &0x6) >> 1)
#define MG_MQTT_SET_QOS(flags, qos) (flags) = ((flags) & ~0x6) | ((qos) << 1)

/* Connection flags */
#define MG_MQTT_CLEAN_SESSION 0x02
#define MG_MQTT_HAS_WILL 0x04
#define MG_MQTT_WILL_RETAIN 0x20
#define MG_MQTT_HAS_PASSWORD 0x40
#define MG_MQTT_HAS_USER_NAME 0x80
#define MG_MQTT_GET_WILL_QOS(flags) (((flags) &0x18) >> 3)
#define MG_MQTT_SET_WILL_QOS(flags, qos) \
  (flags) = ((flags) & ~0x18) | ((qos) << 3)

/* CONNACK return codes */
#define MG_EV_MQTT_CONNACK_ACCEPTED 0
#define MG_EV_MQTT_CONNACK_UNACCEPTABLE_VERSION 1
#define MG_EV_MQTT_CONNACK_IDENTIFIER_REJECTED 2
#define MG_EV_MQTT_CONNACK_SERVER_UNAVAILABLE 3
#define MG_EV_MQTT_CONNACK_BAD_AUTH 4
#define MG_EV_MQTT_CONNACK_NOT_AUTHORIZED 5


#ifndef MG_MQTT_MAX_SESSION_SUBSCRIPTIONS
#define MG_MQTT_MAX_SESSION_SUBSCRIPTIONS 512
#endif

static ngx_str_t str_chk_mqtt;
u_char *MQTT_DDOS = "DDOS";
u_char *MQTT_PASSWD = "PASSWD";





/* Describes chunk of memory */
struct mg_str {

  size_t len;    /* Memory chunk length */
  const char *p; /* Memory chunk pointer */
};

struct mg_mqtt_message {
  int cmd;
  int qos;
  int len; /* message length in the IO buffer */
  struct mg_str topic;
  struct mg_str payload;

  uint8_t connack_ret_code; /* connack */
  uint16_t message_id;      /* puback */

  /* connect */
  uint8_t protocol_version;
  uint8_t connect_flags;
  uint16_t keep_alive_timer;
  struct mg_str protocol_name;
  struct mg_str client_id;
  struct mg_str will_topic;
  struct mg_str will_message;
  struct mg_str user_name;
  struct mg_str password;
};


/**
* print_data 调试16进制打印输出
*
* @name 名字
* @data 打印的内容
* len   打印的字节数
* @return 无
*/

static void print_data(char *name,unsigned char *data,int len)
{
	int i,j,k;

	//if(!debug_mode)
		//return;
	
	if(name) printf("---------------%s-------%dbytes-----------------------------\n",name,len);

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

static uint16_t getu16(const char *p) {
  const uint8_t *up = (const uint8_t *) p;
  return (up[0] << 8) + up[1];
}

static const char *scanto(const char *p, struct mg_str *s) {
  s->len = getu16(p);
  s->p = p + 2;
  return s->p + s->len;
}

int mqtt_next_subscribe_topic(struct mg_mqtt_message *msg,
                                 struct mg_str *topic, uint8_t *qos, int pos) {
  unsigned char *buf = (unsigned char *) msg->payload.p + pos;
  int new_pos;

  if ((size_t) pos >= msg->payload.len) return -1;

  topic->len = buf[0] << 8 | buf[1];
  topic->p = (char *) buf + 2;
  new_pos = pos + 2 + topic->len + 1;//printf("newpos=%d ,%d\n",new_pos,msg->payload.len);
  if ((size_t) new_pos > msg->payload.len) return -1;
  *qos = buf[2 + topic->len];
  return new_pos;
}


/* c0 00 */
static int mqtt_ping(mqtt_waf_msg *req,const unsigned char *p,const unsigned char *end,struct mg_mqtt_message *mm)
{
	//You can add PINGREQ check here
	return MQTT_MSG_DONE;
}

/* d0 00 */
static int mqtt_pong(mqtt_waf_msg *req,const unsigned char *p,const unsigned char *end,struct mg_mqtt_message *mm)
{
	//You can add PINGRESP check here
	printf("PINGRESP\n");
	return MQTT_MSG_DONE;
}
/* e0 00 */
static int mqtt_disconnect(mqtt_waf_msg *req,const unsigned char *p,const unsigned char *end,struct mg_mqtt_message *mm)
{
	//You can add PINGRESP check here
	return MQTT_MSG_DONE;
}
/* 40 02 00 09 */
static int  mqtt_puback(mqtt_waf_msg *req,const unsigned char *p,const unsigned char *end,struct mg_mqtt_message *mm)
{	
	int len;

	len = end - p;
	if(len > 5) return MG_MQTT_ERROR_MALFORMED_MSG;
	
	return MQTT_MSG_DONE;
}

/* 50 02 00 09 */
static int mqtt_pubrec(mqtt_waf_msg *req,const unsigned char *p,const unsigned char *end,struct mg_mqtt_message *mm)
{
	int len;

	len = end - p;
	if(len > 5) return MG_MQTT_ERROR_MALFORMED_MSG;
	
	return MQTT_MSG_DONE;
}

/* 60 02 00 09 */
static int mqtt_pubrel(mqtt_waf_msg *req,const unsigned char *p,const unsigned char *end,struct mg_mqtt_message *mm)
{
	int len;

	len = end - p;
	if(len > 5) return MG_MQTT_ERROR_MALFORMED_MSG;
	
	return MQTT_MSG_DONE;
}

/* 70 02 00 09 */
static int mqtt_pubcom(mqtt_waf_msg *req,const unsigned char *p,const unsigned char *end,struct mg_mqtt_message *mm)
{
	int len;

	len = end - p;
	if(len > 5) return MG_MQTT_ERROR_MALFORMED_MSG;
	
	return MQTT_MSG_DONE;
}

/*
---------------mqtt send-------40bytes-----------------------------
| 30 26 00 14 68 6f 6d 65 2f 67 61 72 64 65 6e 2f |0&..home/garden/|
| 66 6f 75 6e 74 61 69 6e 31 32 33 34 35 36 37 38 |fountain12345678|
| 39 30 61 62 63 64 65 66                         |90abcdef
*/

static int mqtt_publish(mqtt_waf_msg *req,const unsigned char *p,const unsigned char *end,struct mg_mqtt_message *mm)
{
	int                          len;
    ngx_cached_open_file_t       *file = NULL;

	  p = scanto(p, &mm->topic);
      if (p > end) return MG_MQTT_ERROR_MALFORMED_MSG;
      if (mm->qos > 0) {
        if (end - p < 2) return MG_MQTT_ERROR_MALFORMED_MSG;
        mm->message_id = getu16(p);
        p += 2;
      }
      mm->payload.p   = p;
      mm->payload.len = end - p;

	  req->req_cnt    = 1;	

     

	//printf("qos=%d len=%d publish [%.*s] [%.*s]\n",mm->qos,(int) mm->payload.len,(int) mm->topic.len, mm->topic.p,mm->payload.len > 128?128:(int) mm->payload.len, mm->payload.p);
	chk_mqtt_rules((ngx_str_t *)&mm->topic,C_MQTT_PUBLISH,req);
	chk_mqtt_rules((ngx_str_t *)&mm->payload,C_MQTT_PUBLISH,req);
   // printf("ruleid =%d.........\n",req->rule_id);

    //only json  ,cc & ddos ruleid=20 22
    /*if (req->rule_id < 100 && NGX_OK == judge_if_json_format((u_char *)(mm->payload.p),(int)(mm->payload.len) ) ) { 
        file = save_train_mqtt_data((ngx_str_t *)&mm->topic,(ngx_str_t *)&mm->payload,req);
        if (file) {
          
               ai_json_detect(mm->payload.p,mm->payload.len,req,file);              
 
        }
    }*/
   

	/*you can decode json here 
	ngx_http_dummy_json_parse((char *)&mm->payload,	  (int)mm->payload.len,req);
	*/

	return MQTT_MSG_DONE;
}

/*
---------------mqtt send-------30bytes-----------------------------
| a2 1c 00 04 00 18 68 6f 6d 65 2f 67 61 72 64 65 |......home/garde|
| 6e 2f 66 6f 75 6e 74 61 69 6e 2f 74 73 74       |n/fountain/tst  |

*/

static int mqtt_unsubscribe(mqtt_waf_msg *req,const unsigned char *p,const unsigned char *end,struct mg_mqtt_message *mm)
{
	int len;

	len = end - p;
	if(len < 5) return MG_MQTT_ERROR_MALFORMED_MSG;
	mm->message_id = getu16(p);
    p += 4;
      /*
       * topic expressions are left in the payload and can be parsed with
       * `mg_mqtt_next_subscribe_topic`
       */
    mm->payload.p = p;
    mm->payload.len = end - p;
	req->req_cnt    = 1;

	//printf("unsubscribe topic [%.*s]\n",(int) mm->payload.len, mm->payload.p);
	return MQTT_MSG_DONE;
}


/*
---------------mqtt send-------27bytes-----------------------------
| 82 19 00 01 00 14 68 6f 6d 65 2f 67 61 72 64 65 |......home/garde|
| 6e 2f 66 6f 75 6e 74 61 69 6e 00                |n/fountain.     |
*/

static int mqtt_subscribe(mqtt_waf_msg *req,const unsigned char *p,const unsigned char *end,struct mg_mqtt_message *mm)
{
	int len;
	struct mg_str topic;
  	uint8_t qos = 0;
  	int pos = 0;

	len = end - p;
	if(len < 4) return MG_MQTT_ERROR_MALFORMED_MSG;
	mm->message_id = getu16(p);
    p += 2;
      /*
       * topic expressions are left in the payload and can be parsed with
       * `mg_mqtt_next_subscribe_topic`
       */
    mm->payload.p   = p;
    mm->payload.len = end - p;
	req->req_cnt    = 1;

	pos = mqtt_next_subscribe_topic(mm, &topic, &qos, pos);
	if(pos != -1) 
	{
		//printf("subscribe topic [%.*s]\n",(int) topic.len, topic.p);
		chk_mqtt_rules((ngx_str_t *)&topic,ARGS,req);
	}
	return MQTT_MSG_DONE;
}


/*

---------------mqtt send-------105bytes-----------------------------
| 10 67 00 04 4d 51 54 54 04 c2 00 3c 00 19 4d 51 |.g..MQTT...<..MQ|
| 54 54 5f 46 58 5f 43 6c 69 65 6e 74 5f 39 69 75 |TT_FX_Client_9iu|
| 79 38 37 36 35 35 35 00 12 69 6f 74 66 72 65 65 |y876555..iotfree|
| 74 65 73 74 2f 74 68 69 6e 67 30 00 2c 59 55 37 |test/thing0.,YU7|
| 54 6f 76 38 7a 46 57 2b 57 75 61 4c 78 39 73 39 |Tov8zFW+WuaLx9s9|
| 49 33 4d 4b 79 63 6c 69 65 39 53 47 44 75 75 4e |I3MKyclie9SGDuuN|
| 6b 6c 36 6f 39 4c 58 6f 3d                      |kl6o9LXo= 
*/

static int mqtt_connect(mqtt_waf_msg *req,const unsigned char *p,const unsigned char *end,struct mg_mqtt_message *mm)
{
	int len;

	len = end - p;

	  p = scanto(p, &mm->protocol_name);
      if (p > end - 4) return MG_MQTT_ERROR_MALFORMED_MSG;
      mm->protocol_version = *(uint8_t *) p++;
      mm->connect_flags = *(uint8_t *) p++;
      mm->keep_alive_timer = getu16(p);
      p += 2;
      if (p >= end) return MG_MQTT_ERROR_MALFORMED_MSG;
      p = scanto(p, &mm->client_id);
      if (p > end) return MG_MQTT_ERROR_MALFORMED_MSG;
	  chk_mqtt_rules((ngx_str_t *)&mm->client_id,ARGS,req);
	   
      if (mm->connect_flags & MG_MQTT_HAS_WILL) {
        if (p >= end) return MG_MQTT_ERROR_MALFORMED_MSG;
        p = scanto(p, &mm->will_topic);
      }
      if (mm->connect_flags & MG_MQTT_HAS_WILL) {
        if (p >= end) return MG_MQTT_ERROR_MALFORMED_MSG;
        p = scanto(p, &mm->will_message);
      }
      if (mm->connect_flags & MG_MQTT_HAS_USER_NAME) {
        if (p >= end) return MG_MQTT_ERROR_MALFORMED_MSG;
        p = scanto(p, &mm->user_name);
	    chk_mqtt_rules((ngx_str_t *)&mm->user_name,ARGS,req);
      }
      if (mm->connect_flags & MG_MQTT_HAS_PASSWORD) {
        if (p >= end) return MG_MQTT_ERROR_MALFORMED_MSG;
        p = scanto(p, &mm->password);
	    chk_mqtt_rules((ngx_str_t *)&mm->password,ARGS,req);
		
		str_chk_mqtt.data = MQTT_PASSWD;
		str_chk_mqtt.len  = strlen(MQTT_PASSWD);
		if(1 == chk_all_rules(&str_chk_mqtt,DDOS,req))	
			req->ddos = 1;
      }
      if (p != end) return MG_MQTT_ERROR_MALFORMED_MSG;
	  

      printf("%d %2x %d proto [%.*s] client_id [%.*s] will_topic [%.*s] "
           "will_msg [%.*s] user_name [%.*s] password [%.*s]\n",
           (int) len, (int) mm->connect_flags, (int) mm->keep_alive_timer,
           (int) mm->protocol_name.len, mm->protocol_name.p,
           (int) mm->client_id.len, mm->client_id.p, (int) mm->will_topic.len,
           mm->will_topic.p, (int) mm->will_message.len, mm->will_message.p,
           (int) mm->user_name.len, mm->user_name.p, (int) mm->password.len,
           mm->password.p);
	
	return MQTT_MSG_DONE;;
	

}

static void init_mqtt_msg(mqtt_waf_msg *req)
{
	req->ddos         = 0;
	req->rule_id      = 0;
	req->severity     = 0;
	req->white_topic    = 0;
	req->black_topic    = 0;
	req->no_www_file  = 0;
	req->logcenter    = 0;
	req->err_state    = 0;
	req->uri          = NULL;
	req->host         = NULL;
	req->req_file     = NULL;
	req->req_dir      = NULL;
	req->log_msg      = NULL;
	req->str_matched  = NULL;
}

static int mqtt_ck_action(mqtt_waf_msg *req)
{

	
	if(gvar.err_is_attack == 1 && req->msg_state == MSG_ERROR)
	{
		snprintf(mqtt_log_msg,sizeof(mqtt_log_msg)-1,"MQTT PROTOCOL ERROR ,Perhaps	Attack...");			
		req->log_msg	 = mqtt_log_msg;
		req->rule_id	 = MQTT_ATK_ERR_HEAD;	
	}	

	if(req->msg_state == MQTT_MSG_ERROR)
		req->msg_state = MQTT_MSG_DONE;

	
	if(req->white_topic == 1)
		return ALLOW;
		
	
	if(gvar.action == ALERT)
	{
		if(req->rule_id > 100) //0 -100 reserve for ddos....
			return ALERT;
		if(req->black_topic == 1)
			return ALERT;
		if(req->no_www_file == 1)
			return ALERT;
			
			
	}	
	
		
	if(gvar.action == DROP)
	{
		if(req->rule_id > 100) //0 -100 reserve for ddos....
			return DROP;
		if(req->black_topic == 1)
			return DROP;
		if(req->no_www_file == 1)
				return DROP;		
			
	}	

	if(req->req_cnt == 1)
	{
		req->req_cnt = 0;
		return REQ_CNT;		
	}
	
	return ALLOW;
}

static void process_mqtt_msg(mqtt_waf_msg *req)
{
	unsigned char header,mqtt_msg_type,lc = 0,*str;
	int i,len,len_len;
	const char *p, *end, *eop; 
	struct mg_mqtt_message mm;
  

	if(req->pos < 4)
	{
		//req->msg_state = MQTT_MSG_RQMETH;
		return;
	}

    str   = req->buf;
	for(i = 0;i < req->pos - 1;i++)
	{		
		str[i] = tolower(str[i]);
	}
    
	header = req->buf[0];

	  /* decode mqtt variable length */
	  len = len_len = 0;
	  p   = req->buf + 1;
	  eop = &req->buf[req->pos];
	  while (p < eop) {
	    lc = *((const unsigned char *) p++);
	    len += (lc & 0x7f) << 7 * len_len;
	    len_len++;
	    if (!(lc & 0x80)) break;
	    if (len_len > 4){
			req->msg_state = MQTT_MSG_ERROR;
			return;
	    }
	  }
	  
	//  printf("len=%d  %d , len_len=%d--total=%d\n",len,(req->pos -len_len - 1),len_len,eop - p);			
	  if(len > MAX_MQTT_PACKET_SIZE || len <= 0) //PING = 0
	  {
		  	req->msg_state = MQTT_MSG_ERROR;
			return;
	  }

	  if(len > (req->pos -len_len - 1))
	  {
		  	req->msg_state = MQTT_MSG_RQMETH;
			return;
	  }

	  if(len < (req->pos -len_len - 1) )
	  {
		  	req->msg_state = MQTT_MSG_ERROR;
		  	//printf("MQTT_MSG_ERROR.......\n");
			return;
	  }

	req->msg_state = MQTT_MSG_DONE;

	
	str_chk_mqtt.data = MQTT_DDOS;
	str_chk_mqtt.len  = strlen(MQTT_DDOS);
	if(1 == chk_all_rules(&str_chk_mqtt,DDOS,req))	
		req->ddos = 1;

	
	memset(&mm, 0, sizeof(mm)); 
	mm.qos = MG_MQTT_GET_QOS(header);
	end = p + len;  
	mqtt_msg_type = header >> 4;
	switch (mqtt_msg_type)
	{
		
		case MQTT_CONNECT:
			req->msg_state = mqtt_connect(req,p,end,&mm);
			break;
		case MQTT_CONNACK:

			break;

		case MQTT_PUBLISH:
			req->msg_state = mqtt_publish(req,p,end,&mm);
			break;
		case MQTT_SUBSCRIBE:
			req->msg_state = mqtt_subscribe(req,p,end,&mm);
			break;
		case MQTT_UNSUBSCRIBE:
			req->msg_state = mqtt_unsubscribe(req,p,end,&mm);
			break;
		case MQTT_PUBACK:
    	case MQTT_PUBREC:
    	case MQTT_PUBREL:
    	case MQTT_PUBCOMP:
			break;
		case MQTT_UNSUBACK:
			break;

		/* The following messages don't have variable header */
    	case MQTT_PINGREQ:
    	case MQTT_PINGRESP:
			mqtt_pong(req,p,end,&mm);
    	  	break;

	    case MQTT_DISCONNECT:
	      /* MQTT v5.0: Byte 1 in the Variable Header is the Disconnect Reason Code.
	       * If the Remaining Length is less than 1 the value of 0x00
	       * (Normal disconnection) is used.
	       */
	      /* FALLTHROUGH */
		  mqtt_disconnect(req,p,end,&mm);
	    case MQTT_AUTH:
			break;
		
			
		default:
			break;
	}

}


int process_mqtt(const char *buf,int len,mqtt_waf_msg *req)

{
	//printf("rcv len=%d state=%d\n",len,req->msg_state);
	//print_data("mqtt send", (unsigned char *)buf, len > 32 ?32:len);
	
	
	switch(req->msg_state)
	{
			/*first mqtt header msg */
			case MQTT_MSG_RQBEFORE:
			/*keep alive,next message*/
			case MQTT_MSG_DONE:	
				
				memcpy(req->buf,buf,len);
				req->file_size += len;
				req->pos = len;
				req->buf[len] = '\0';
				init_mqtt_msg(req);
				process_mqtt_msg(req);
				break;
	
			/*data not over*/
			case MQTT_MSG_RQMETH: 
				if((req->pos + len) > MAX_MQTT_PACKET_SIZE)
				{
					req->msg_state = MQTT_MSG_DONE;
					return mqtt_ck_action(req);
				}
					//return check_action(req);
				memcpy(req->buf + req->pos,buf,len);
				req->pos += len;
				req->buf[req->pos] = '\0';
				process_mqtt_msg(req);				
				break;			
				
			default:
				break;
		}
	
	return mqtt_ck_action(req);


}





