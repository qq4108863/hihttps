

/* 
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
* GNU General Public License for more details.
*
For more ,please contact QQ:4108863/wechat:wmkwang/mail:4108863@qq.com
http://www.hihttps.com/
*/

#ifndef __SSL_MQTT_H__
#define __SSL_MQTT_H__

#include "httpx.h"

static char mqtt_log_msg[256] = {0};

/* Legacy version of the MQTT message state, used by the channels, should
 * ultimately be removed.
 */
enum ngx_mqtt_state {
	MQTT_MSG_RQBEFORE     =  0, // request: leading LF, before start line
	MQTT_MSG_RQBEFORE_CR  =  1, // request: leading CRLF, before start line
	/* these ones define a request start line */
	MQTT_MSG_RQMETH       =  2, // parsing the Method	

	MQTT_MSG_LAST_LF      = 3, // parsing last LF
	/* error state : must be before MSG_BODY so that (>=BODY) always indicates
	 * that data are being processed.
	 */
	MQTT_MSG_ERROR        = 4, // an error occurred
	/* Body processing.
	 * The state MSG_BODY is a delimiter to know if we're waiting for headers
	 * or body. All the sub-states below also indicate we're processing the body,
	 * with some additional information.
	 */
	MQTT_MSG_BODY         = 5, // parsing body at end of headers
	MQTT_MSG_DONE         = 6 // parsing body at end of headers
	
};



int process_mqtt(const char *buf,int len,mqtt_waf_msg *req);



#endif



