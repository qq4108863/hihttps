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
 * For more ,please contact QQ/wechat:4108863 mail:4108863@qq.com
 */



#ifndef __HTTPX_H__
#define __HTTPX_H__

#include <time.h>
#include <stdlib.h>

//#define HAVE_MQTT	1


#define  MACHINE_LEANRING_RULE_ID 888

static   char http_log_msg[512] = {0};
static   char http_str_match[256] = {0};

#define MAX_HTTP_HEADER_SIZE 1024*20
#define MAX_HTTP_BODY_SIZE 1024*20

typedef struct
{
	int			burst_time_slice;
	int			counter_threshold;
	int			block_timeout;
}http_ddos_rule_t;

typedef enum _http_mthd http_mthd;
enum _http_mthd {
    HTTP_MT_OPTIONS = 0, /* RFC2616 */
    HTTP_MT_GET,
    HTTP_MT_HEAD,
    HTTP_MT_POST,
    HTTP_MT_PUT,
    HTTP_MT_DELETE,
    HTTP_MT_TRACE,
    HTTP_MT_CONNECT,
    HTTP_MT_PATCH,
    HTTP_MT_LINK,
    HTTP_MT_UNLINK,
    HTTP_MT_PROPFIND,    /* RFC2518 */
    HTTP_MT_MKCOL,
    HTTP_MT_COPY,
    HTTP_MT_MOVE,
    HTTP_MT_LOCK,
    HTTP_MT_UNLOCK,
    HTTP_MT_POLL,        /* Outlook Web Access */
    HTTP_MT_BCOPY,
    HTTP_MT_BMOVE,
    HTTP_MT_SEARCH,
    HTTP_MT_BDELETE,
    HTTP_MT_PROPPATCH,
    HTTP_MT_BPROPFIND,
    HTTP_MT_BPROPPATCH,
    HTTP_MT_LABEL,             /* RFC 3253 8.2 */
    HTTP_MT_MERGE,             /* RFC 3253 11.2 */
    HTTP_MT_REPORT,            /* RFC 3253 3.6 */
    HTTP_MT_UPDATE,            /* RFC 3253 7.1 */
    HTTP_MT_CHECKIN,           /* RFC 3253 4.4, 9.4 */
    HTTP_MT_CHECKOUT,          /* RFC 3253 4.3, 9.3 */
    HTTP_MT_UNCHECKOUT,        /* RFC 3253 4.5 */
    HTTP_MT_MKACTIVITY,        /* RFC 3253 13.5 */
    HTTP_MT_MKWORKSPACE,       /* RFC 3253 6.3 */
    HTTP_MT_VERSION_CONTROL,   /* RFC 3253 3.5 */
    HTTP_MT_BASELINE_CONTROL,  /* RFC 3253 12.6 */
    HTTP_MT_NOTIFY,            /* uPnP forum */
    HTTP_MT_SUBSCRIBE,
    HTTP_MT_UNSUBSCRIBE,
    HTTP_MT_ICY,               /* Shoutcast client (forse) */
    HTTP_MT_NONE
};


/* Legacy version of the HTTP/1 message state, used by the channels, should
 * ultimately be removed.
 */
enum ngx_h1_state {
	MSG_RQBEFORE     =  0, // request: leading LF, before start line
	MSG_RQBEFORE_CR  =  1, // request: leading CRLF, before start line
	/* these ones define a request start line */
	MSG_RQMETH       =  2, // parsing the Method	

	MSG_LAST_LF      = 3, // parsing last LF
	/* error state : must be before MSG_BODY so that (>=BODY) always indicates
	 * that data are being processed.
	 */
	MSG_ERROR        = 4, // an error occurred
	/* Body processing.
	 * The state MSG_BODY is a delimiter to know if we're waiting for headers
	 * or body. All the sub-states below also indicate we're processing the body,
	 * with some additional information.
	 */
	MSG_BODY         = 5, // parsing body at end of headers
	MSG_DONE         = 6 // parsing body at end of headers
	
};



typedef enum _http_resp http_resp;
enum _http_resp {
    HTTP_RESP_HTTP,   /**< HTTP/1.x */
    HTTP_RESP_ICY,    /**< Shoutcast client server response */
    HTTP_RESP_NONE
};


typedef enum _http_ver http_ver;
enum _http_ver {
    HTTP_VER_1_0,
    HTTP_VER_1_1,
    HTTP_VER_NONE
};


typedef enum _http_status http_status;
enum _http_status {
    HTTP_ST_100=100,   /**< Continue */
    HTTP_ST_101,       /**< Switching Protocols */
    HTTP_ST_102,       /**< Processing */
    HTTP_ST_199=199,   /**< Informational - Others */
    
    HTTP_ST_200,       /**< OK */
    HTTP_ST_201,       /**< Created */
    HTTP_ST_202,       /**< Accepted */
    HTTP_ST_203,       /**< Non-authoritative Information */
    HTTP_ST_204,       /**< No Content */
    HTTP_ST_205,       /**< Reset Content */
    HTTP_ST_206,       /**< Partial Content */
    HTTP_ST_207,       /**< Multi-Status */
    HTTP_ST_299=299,   /**< Success - Others */
    
    HTTP_ST_300,       /**< Multiple Choices */
    HTTP_ST_301,       /**< Moved Permanently */
    HTTP_ST_302,       /**< Found */
    HTTP_ST_303,       /**< See Other */
    HTTP_ST_304,       /**< Not Modified */
    HTTP_ST_305,       /**< Use Proxy */
    HTTP_ST_307,       /**< Temporary Redirect */
    HTTP_ST_399=399,   /**< Redirection - Others */
    
    HTTP_ST_400,       /**< Bad Request */
    HTTP_ST_401,       /**< Unauthorized */
    HTTP_ST_402,       /**< Payment Required */
    HTTP_ST_403,       /**< Forbidden */
    HTTP_ST_404,       /**< Not Found */
    HTTP_ST_405,       /**< Method Not Allowed */
    HTTP_ST_406,       /**< Not Acceptable */
    HTTP_ST_407,       /**< Proxy Authentication Required */
    HTTP_ST_408,       /**< Request Time-out */
    HTTP_ST_409,       /**< Conflict */
    HTTP_ST_410,       /**< Gone */
    HTTP_ST_411,       /**< Length Required */
    HTTP_ST_412,       /**< Precondition Failed */
    HTTP_ST_413,       /**< Request Entity Too Large */
    HTTP_ST_414,       /**< Request-URI Too Long */
    HTTP_ST_415,       /**< Unsupported Media Type */
    HTTP_ST_416,       /**< Requested Range Not Satisfiable */
    HTTP_ST_417,       /**< Expectation Failed */
    HTTP_ST_422=422,   /**< Unprocessable Entity */
    HTTP_ST_423,       /**< Locked */
    HTTP_ST_424,       /**< Failed Dependency */
    HTTP_ST_499=499,   /**< Client Error - Others */
    
    HTTP_ST_500,       /**< Internal Server Error */
    HTTP_ST_501,       /**< Not Implemented */
    HTTP_ST_502,       /**< Bad Gateway */
    HTTP_ST_503,       /**< Service Unavailable */
    HTTP_ST_504,       /**< Gateway Time-out */
    HTTP_ST_505,       /**< HTTP Version not supported */
    HTTP_ST_507=507,   /**< Insufficient Storage */
    HTTP_ST_599=599,   /**< Server Error - Others */
    HTTP_ST_NONE
};
	

enum h1_content_type {
	HTTP_CONTENT_NONE       =  0, // request: NOTHING
	HTTP_CONTENT_MULTIPART  =  1, // request: multipart/form-data
	HTTP_CONTENT_JSON  =  2, // request: multipart/form-data
};
	
typedef struct _http_waf_msg mqtt_waf_msg;
typedef struct _http_waf_msg http_waf_msg;
struct _http_waf_msg {
	enum ngx_h1_state msg_state;
    http_mthd mtd;                /**< method */
	int content_type;             /**multipart/json */
	   
	int only_once;						/**only once */	
	u_char *buf;					  /*ring buf*/	
	unsigned int  pos;
    u_char *uri;                    /**< url */
    u_char *host;                   /*<* host */
	u_char *args_start;
	u_char *req_file;
	u_char *req_dir;
	u_char *boundary;

	int req_cnt;                  /*request count */ 
	int ddos;                     /*ddos & cc */ 
	int no_www_file;              /*if exits url file in www */
//#ifdef HAVE_MQTT
	int white_topic;			  /* publish or subcrible topic  white list */			
	int black_topic;			  /* publish or subcrible topic  black list */	
//#endif
	int white_url;				  /* url white list */			
	int black_url;				  /* url black list */	

	
	int rule_id;                  //matched attack ruleid
	int severity;                 //severity:'CRITICAL' 'warning'
	int action;                   //ALLOW 0 DROP 1  ALERT 2
	int logcenter;                //if send to  logcenter
	int err_state;                //error head is attack
	u_char *log_msg;              //attack rule log msg
	u_char *str_matched;          //matched attack
	http_ddos_rule_t ddos_rule;
	
    //char *content_type[2];        /**< content type */
    char *content_encoding[2];    /**< content encoding */
    char *client;                 /**< client type */
    http_status status;           /**< status responce */
    char *rset;                   /**< range set pats (range) */
    unsigned long rbase;          /**< offeset download (range) */
    unsigned long rend;           /**< end download (range) */
    unsigned long rsize;          /**< total size (range) */
    char *req_hdr_file;           /**< request header, file path */
    int req_hdr_size;             /**< request header size */
    u_char *req_body;          /**< request body, file path */
    size_t req_body_size;         /**< request body size */
	size_t content_len;         /**< request body size */
	size_t file_size;
	int    boundary_len; 
    char *res_hdr_file;           /**< response header, file path */
    int res_hdr_size;             /**< response header size */
    char *res_body;          /**< response body, file path */
    size_t res_body_size;         /**< response body size */
    int error;                    /**< error code */
    unsigned long serial;         /**< serial number (used in pei) */
    time_t start_cap;             /**< start capture time */
    time_t end_cap;               /**< end capture time */
	
};



int process_http(const char *buffer,int len,http_waf_msg *req);


#endif /* __HTTP_H__ */
