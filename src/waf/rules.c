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
 * For more ,please contact QQ/wechat:4108863/mail:4108863@qq.com
 */

#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include "rules.h"
#include "wwwfiles.h"
#include "ssl_utils.h"
#include "ssl_regex.h"
#include "httpx.h"
#include "mqtt.h"
#include "atklog.h"
#include "cc_ddos.h"


#include "../libinjection/libinjection_sqli.h"
#include "../libinjection/libinjection_xss.h"
#include "../machine-learning/machine-learning.h"
#include "../machine-learning/simhash.h"



#define ngx_command_t char 
#define MAX_LEN 255
ngx_pool_t           *cf_pool = NULL;
ngx_conf_t           *cf = NULL;
ngx_http_dummy_main_conf_t        *main_cf;
ngx_http_dummy_loc_conf_t          *conf;

const char *NGX_HTTP_302 =
    "HTTP/1.1 302 Found\r\n"
    "Cache-Control: no-cache\r\n"
    "Content-length: 0\r\n"
    "Location: ";
char *NGX_HTTP_200 =
    "HTTP/1.1 200 OK\r\n"
    "Cache-Control: no-cache\r\n"
    "Connection: close\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "<html><body><h1>200 OK</h1>\nHiHTTPS ready, by 4108863@qq.com\n</body></html>\n";




/*
** Structures related to the configuration parser
*/
typedef struct  {
  char    *prefix;
  int   (*pars)(ngx_conf_t *, ngx_str_t *, ngx_http_rule_t *);
} ngx_http_dummy_parser_t;


/*
** Structures related to the configuration parser
*/
typedef struct  {
  char    *prefix;
  int   (*pars)(ngx_conf_t *, ngx_command_t  *, void *);
} ngx_http_dummy_keyword_t;

/*
** Structures related to the configuration parser
*/
typedef struct  {
  char    *prefix;
  int   (*pars)(ngx_conf_t *, ngx_str_t *, ngx_http_rule_t *);
} ngx_http_modsecurity_parser_t;


static unsigned int get_executable_path( char* processdir,char* processname, unsigned int len);


int read_line(char *buf, int len, FILE *fp)
{
    char *tmp;

    if (buf == NULL)
    {
        return -1;
    }

    memset(buf, '\0', len*sizeof(char));

    if (fgets(buf, len, fp) == NULL)
    {
        *buf = '\0';
        return 0;
    }
    else
    {
        if ((tmp = strrchr(buf, '\n')) != NULL)
        {
            *tmp = '\0';
        }
        if ((tmp = strrchr(buf, '\r')) != NULL)
        {
            *tmp = '\0';
        }
    }

    return 1;
}

int
dummy_negative(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  rule->br->negative = 1;
  return (NGX_CONF_OK);
}

int
dummy_libinj_xss(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  rule->br->match_type = LIBINJ_XSS;
  return (NGX_CONF_OK);
}

int
dummy_libinj_sql(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  rule->br->match_type = LIBINJ_SQL;
  return (NGX_CONF_OK);
}

int 
dummy_score(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  int                score, len;
  char                *tmp_ptr, *tmp_end;
  ngx_http_special_score_t    *sc;
  
  rule->score = 0;
  rule->block = 0;
  rule->allow = 0;
  rule->drop = 0;
  tmp_ptr = (char *) (tmp->data + strlen(SCORE_T));
  NX_LOG_DEBUG(_debug_score, NGX_LOG_EMERG, r, 0,
           "XX-(debug) dummy score (%V)",
           tmp);
  /*allocate scores array*/
  if (!rule->sscores) {
    rule->sscores = ngx_array_create(r->pool, 1, sizeof(ngx_http_special_score_t));
  }

  while (*tmp_ptr) { 
    if (tmp_ptr[0] == '$') {
      NX_LOG_DEBUG(_debug_score, NGX_LOG_EMERG, r, 0,
           "XX-(debug) special scoring rule (%s)",
           tmp_ptr);
      tmp_end = strchr(tmp_ptr, ':');
      if (!tmp_end)
    return (NGX_CONF_ERROR);
      len = tmp_end - tmp_ptr;
      if (len <= 0)
    return (NGX_CONF_ERROR);
      sc = ngx_array_push(rule->sscores);
      if (!sc)
    return (NGX_CONF_ERROR);
      sc->sc_tag = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
      if (!sc->sc_tag)
    return (NGX_CONF_ERROR);
      sc->sc_tag->data = ngx_pcalloc(r->pool, len+1);
      if (!sc->sc_tag->data)
    return (NGX_CONF_ERROR);
      //memset(rule->sc_tag->data, 0, len+1);
      memcpy(sc->sc_tag->data, tmp_ptr, len);
      sc->sc_tag->len = len;
      sc->sc_score = atoi(tmp_end+1);
      NX_LOG_DEBUG(_debug_score, NGX_LOG_EMERG, r, 0,
           "XX-(debug) special scoring (%V) => (%d)",
           sc->sc_tag, sc->sc_score);
      
      /* move to end of score. */
      while ( /*don't overflow*/((unsigned int)((unsigned char *)tmp_ptr - tmp->data)) < tmp->len &&
          /*and seek for next score */ *tmp_ptr != ',')
    ++tmp_ptr;
    }
    else if (tmp_ptr[0] == ',')
      ++tmp_ptr;
    else if (!strcasecmp(tmp_ptr, "BLOCK")) {
      rule->block = 1;
      tmp_ptr += 5;
    }
    else if (!strcasecmp(tmp_ptr, "DROP")) {
      rule->drop = 1;
      tmp_ptr += 4;
    }
    else if (!strcasecmp(tmp_ptr, "ALLOW")) {
      rule->allow = 1;
      tmp_ptr += 5;
    }
    else if (!strcasecmp(tmp_ptr, "LOG")) {
      rule->log = 1;
      tmp_ptr += 3;
    }
    
    //or maybe you just want to assign a score
    else if ( (tmp_ptr[0] >= '0' && tmp_ptr[0] <= '9') || tmp_ptr[0] == '-') {
      score = atoi((const char *)tmp->data+2);
      rule->score = score;
      break;
    }
    else
      return (NGX_CONF_ERROR);
  }
#if defined(_debug_score) && _debug_score != 0
  unsigned int z;
  ngx_http_special_score_t    *scr;
  scr = rule->sscores->elts;
  if (rule->sscores) {
    for (z = 0; z < rule->sscores->nelts; z++) {
      ngx_conf_log_error(NGX_LOG_EMERG, r, 0,
             "XX-score n°%d special scoring (%V) => (%d)",
             z, scr[z].sc_tag, scr[z].sc_score);
      
    }
  }
  else
    ngx_conf_log_error(NGX_LOG_EMERG, r, 0,
               "XX-no custom scores for this rule.");
#endif
  return (NGX_CONF_OK);
}


int 
dummy_zone(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  int                    tmp_len, has_zone=0;
  ngx_http_custom_rule_location_t    *custom_rule;
  char *tmp_ptr, *tmp_end;


  if (!rule->br)
    return (NGX_CONF_ERROR);
  
  tmp_ptr = (char *) tmp->data+strlen(MATCH_ZONE_T);
  while (*tmp_ptr) {
    
    if (tmp_ptr[0] == '|')
      tmp_ptr++;
    /* match global zones */
    if (!strncmp(tmp_ptr, "RAW_BODY", strlen("RAW_BODY"))) {
      rule->br->raw_body = 1;
      tmp_ptr += strlen("RAW_BODY");
      has_zone = 1;
      continue;
    }
    else
      if (!strncmp(tmp_ptr, "BODY", strlen("BODY"))) {
    rule->br->body = 1;
    tmp_ptr += strlen("BODY");
    has_zone = 1;
    continue;
      }
      else
    if (!strncmp(tmp_ptr, "HEADERS", strlen("HEADERS"))) {
      rule->br->headers = 1;
      tmp_ptr += strlen("HEADERS");
      has_zone = 1;
      continue;
    }

    else
    if (!strncmp(tmp_ptr, "DDOS", strlen("DDOS"))) {
      rule->br->ddos = 1;
      tmp_ptr += strlen("DDOS");
      has_zone = 1;
      continue;
    }
    
    else
      if (!strncmp(tmp_ptr, "URL", strlen("URL"))) {
        rule->br->url = 1;
        tmp_ptr += strlen("URL");
        has_zone = 1;
        continue;
      }
      else
        if (!strncmp(tmp_ptr, "ARGS", strlen("ARGS"))) {
          rule->br->args = 1;
          tmp_ptr += strlen("ARGS");
          has_zone = 1;
          continue;
        }
        else
          /* match against variable name*/
          if (!strncmp(tmp_ptr, "NAME", strlen("NAME"))) {
        rule->br->target_name = 1;
        tmp_ptr += strlen("NAME");
        has_zone = 1;
        continue;
          }
          else
        /* for file_ext, just push'em in the body rules.
           when multipart parsing comes in, it'll tag the zone as
           FILE_EXT as the rule will be pushed in body rules it'll be 
           checked !*/
        if (!strncmp(tmp_ptr, "FILE_EXT", strlen("FILE_EXT"))) {
          rule->br->file_ext = 1;
          rule->br->body = 1;
          tmp_ptr += strlen("FILE_EXT");
          has_zone = 1;
          continue;
        }
        else
          /* custom match  zones */
#define MZ_GET_VAR_T "$ARGS_VAR:"
#define MZ_HEADER_VAR_T "$HEADERS_VAR:"
#define MZ_POST_VAR_T "$BODY_VAR:"
#define MZ_SPECIFIC_URL_T "$URL:"
          //probably a custom zone
          if (tmp_ptr[0] == '$') {
            // tag as a custom_location rule.
            rule->br->custom_location = 1;
            if (!rule->br->custom_locations) {
              rule->br->custom_locations = ngx_array_create(r->pool, 1, 
                                    sizeof(ngx_http_custom_rule_location_t));
              if (!rule->br->custom_locations)
            return (NGX_CONF_ERROR);
            }
            custom_rule = ngx_array_push(rule->br->custom_locations);
            if (!custom_rule)
              return (NGX_CONF_ERROR);
            memset(custom_rule, 0, sizeof(ngx_http_custom_rule_location_t));
            if (!strncmp(tmp_ptr, MZ_GET_VAR_T, strlen(MZ_GET_VAR_T))) {
              has_zone = 1;
              custom_rule->args_var = 1;
              rule->br->args_var = 1;
              tmp_ptr += strlen(MZ_GET_VAR_T);
            }
            else if (!strncmp(tmp_ptr, MZ_POST_VAR_T, 
                      strlen(MZ_POST_VAR_T))) {
              has_zone = 1;
              custom_rule->body_var = 1;
              rule->br->body_var = 1;
              tmp_ptr += strlen(MZ_POST_VAR_T);
            }
            else if (!strncmp(tmp_ptr, MZ_HEADER_VAR_T, 
                      strlen(MZ_HEADER_VAR_T))) {
              has_zone = 1;
              custom_rule->headers_var = 1;
              rule->br->headers_var = 1;
              tmp_ptr += strlen(MZ_HEADER_VAR_T);
            }
            else if (!strncmp(tmp_ptr, MZ_SPECIFIC_URL_T, 
                      strlen(MZ_SPECIFIC_URL_T))) { 
              custom_rule->specific_url = 1; 
              tmp_ptr += strlen(MZ_SPECIFIC_URL_T);
            }
            else 
              /* add support for regex-style match zones. 
              ** this whole function should be rewritten as it's getting
              ** messy as hell
              */
#define MZ_GET_VAR_X "$ARGS_VAR_X:"
#define MZ_HEADER_VAR_X "$HEADERS_VAR_X:"
#define MZ_POST_VAR_X "$BODY_VAR_X:"
#define MZ_SPECIFIC_URL_X "$URL_X:"
              /*
              ** if the rule is a negative rule (has an ID, not a WL field)
              ** we need to pre-compile the regex for runtime.
              ** Don't do it for whitelists, as its done in a separate manner.
              */
              if (!strncmp(tmp_ptr, MZ_GET_VAR_X, strlen(MZ_GET_VAR_X))) {
            has_zone = 1;
            custom_rule->args_var = 1;
            rule->br->args_var = 1;
            rule->br->rx_mz = 1;
            tmp_ptr += strlen(MZ_GET_VAR_X);
              }
              else if (!strncmp(tmp_ptr, MZ_POST_VAR_X, 
                    strlen(MZ_POST_VAR_X))) {
            has_zone = 1;
            rule->br->rx_mz = 1;
            custom_rule->body_var = 1;
            rule->br->body_var = 1;
            tmp_ptr += strlen(MZ_POST_VAR_X);
              }
              else if (!strncmp(tmp_ptr, MZ_HEADER_VAR_X, 
                    strlen(MZ_HEADER_VAR_X))) {
            has_zone = 1;
            custom_rule->headers_var = 1;
            rule->br->headers_var = 1;
            rule->br->rx_mz = 1;
            tmp_ptr += strlen(MZ_HEADER_VAR_X);
              }
              else if (!strncmp(tmp_ptr, MZ_SPECIFIC_URL_X, 
                    strlen(MZ_SPECIFIC_URL_X))) { 
            custom_rule->specific_url = 1;
            rule->br->rx_mz = 1;
            tmp_ptr += strlen(MZ_SPECIFIC_URL_X);
              }
              else 
            return (NGX_CONF_ERROR);
          
            /*          else 
                  return (NGX_CONF_ERROR);*/
            tmp_end = strchr((const char *) tmp_ptr, '|');
            if (!tmp_end) 
              tmp_end = tmp_ptr + strlen(tmp_ptr);
            tmp_len = tmp_end - tmp_ptr;
            if (tmp_len <= 0)
              return (NGX_CONF_ERROR);
            custom_rule->target.data = ngx_pcalloc(r->pool, tmp_len+1);
            if (!custom_rule->target.data)
              return (NGX_CONF_ERROR);
            custom_rule->target.len = tmp_len;
            memcpy(custom_rule->target.data, tmp_ptr, tmp_len);
            /*
            ** pre-compile regex !
            */

            
            if (rule->br->rx_mz == 1) {

              custom_rule->target_rx = ngx_pcalloc(r->pool, sizeof(ngx_regex_compile_t));
              if (!custom_rule->target_rx)
            return (NGX_CONF_ERROR);
              custom_rule->target_rx->options = PCRE_CASELESS|PCRE_MULTILINE;
              custom_rule->target_rx->pattern = custom_rule->target;
              custom_rule->target_rx->pool = r->pool;
              custom_rule->target_rx->err.len = 0;
              custom_rule->target_rx->err.data = NULL;
  
              if (ngx_regex_compile(custom_rule->target_rx) != NGX_OK) {
            NX_LOG_DEBUG(_debug_rx, NGX_LOG_EMERG, r, 0, "XX-FAILED RX:%V",
                     custom_rule->target);
            return (NGX_CONF_ERROR);
              }
            }
            custom_rule->hash = ngx_hash_key_lc(custom_rule->target.data, 
                            custom_rule->target.len);
            
            NX_LOG_DEBUG(_debug_zone, NGX_LOG_EMERG, r, 0, "XX- ZONE:[%V]", 
                 &(custom_rule->target));  
            tmp_ptr += tmp_len;
            continue;
          }
          else
            return (NGX_CONF_ERROR);
  }
  /*
  ** ensure the match-zone actually returns a zone :)
  */
  if (has_zone == 0) {
   
    return (NGX_CONF_ERROR);
  }

  return (NGX_CONF_OK);
}

int
dummy_id(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  rule->rule_id = atoi((const char *) tmp->data+strlen(ID_T));
  return (NGX_CONF_OK);
}

int
dummy_str(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  ngx_str_t    *str;
  uint        i;

  if (!rule->br)
    return (NGX_CONF_ERROR);
  rule->br->match_type = STR;
  str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));  
  if (!str)
    return (NGX_CONF_ERROR);  
  str->data = ngx_pcalloc(r->pool, tmp->len);
  if (!str->data)
    return (NGX_CONF_ERROR);
  
  memcpy(str->data,tmp->data + strlen(STR_T),tmp->len - strlen(STR_T));
  //str->data = tmp->data + strlen(STR_T);
  str->len = tmp->len - strlen(STR_T);
  for (i = 0; i < str->len; i++)
    str->data[i] = tolower(str->data[i]);
  rule->br->str = str;  //printf("dummy_str:%s------------\n",rule->br->str->data);
  return (NGX_CONF_OK);
}

int
dummy_msg(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  ngx_str_t    *str;
  
  if (!rule->br)
    return (NGX_CONF_ERROR);
  str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
  if (!str)
    return (NGX_CONF_ERROR);
  str->data = ngx_pcalloc(r->pool, tmp->len);
  if (!str->data)
    return (NGX_CONF_ERROR);
  snprintf(str->data,tmp->len-1,"err");
  memcpy(str->data,tmp->data + strlen(STR_T),tmp->len - strlen(STR_T));
  str->len = tmp->len - strlen(STR_T);
  rule->log_msg = str;
  return (NGX_CONF_OK);
}

int
dummy_whitelist(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  
  ngx_array_t    *wl_ar;
  unsigned int    i, ct;
  ngx_int_t    *id;
  ngx_str_t    str;
  
  str.data = tmp->data + strlen(WHITELIST_T);
  str.len = tmp->len - strlen(WHITELIST_T);
  for (ct = 1, i = 0; i < str.len; i++)
    if (str.data[i] == ',')
      ct++;
  wl_ar = ngx_array_create(r->pool, ct, sizeof(ngx_int_t));
  if (!wl_ar)
    return (NGX_CONF_ERROR);
  NX_LOG_DEBUG(_debug_whitelist, NGX_LOG_EMERG, r, 0, "XX- allocated %d elems for WL", ct);
  for (i = 0; i < str.len; i++) {
    if (i == 0 || str.data[i-1] == ',') {
      id = (ngx_int_t *) ngx_array_push(wl_ar);
      if (!id) 
    return (NGX_CONF_ERROR);
      *id = (ngx_int_t) atoi((const char *)str.data+i);
    }
  }
  rule->wlid_array = wl_ar;
  return (NGX_CONF_OK);
}



int 
dummy_rx(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  ngx_regex_compile_t  *rgc;
  ngx_str_t           ha;
  


  if (!rule->br)
    return (NGX_CONF_ERROR);
  rule->br->match_type = RX;
  //just prepare a string to hold the directive without 'rx:'
  ha.data = tmp->data+strlen(RX_T);
  ha.len = tmp->len-strlen(RX_T);
  rgc = ngx_pcalloc(r->pool, sizeof(ngx_regex_compile_t));
  if (!rgc)
    return (NGX_CONF_ERROR);
  rgc->options = PCRE_CASELESS|PCRE_MULTILINE;
  rgc->pattern = ha;
  rgc->pool = r->pool;
  rgc->err.len = 0;
  rgc->err.data = NULL;
  
  if (ngx_regex_compile(rgc) != NGX_OK) { 
    NX_LOG_DEBUG(_debug_rx, NGX_LOG_EMERG, r, 0, "XX-FAILED RX:%V",
         tmp);
    rule->br->match_type = -1;
    rule->br->rx = NULL;
      return (NGX_CONF_ERROR);
    }
  rule->br->rx = rgc;
  //printf("Rx pattern=%s\n",(const char *)(rule->br->rx->pattern.data));
  //NX_LOG_DEBUG(_debug_rx, NGX_LOG_EMERG, r, 0, "XX- RX:[%V]",
          // &(rule->br->rx->pattern));  
  return (NGX_CONF_OK);
}


int
mod_str(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  ngx_str_t    *str;
  uint        i;

  if (!rule->br)
    return (NGX_CONF_ERROR);
  rule->br->match_type = STR;
  str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));  
  if (!str)
    return (NGX_CONF_ERROR);  
  str->data = ngx_pcalloc(r->pool, tmp->len);
  if (!str->data)
    return (NGX_CONF_ERROR);
  
  memcpy(str->data,tmp->data + strlen("@pm "),tmp->len - strlen("@pm "));
  //str->data = tmp->data + strlen(STR_T);
  str->len = tmp->len - strlen("@pm ");
  for (i = 0; i < str->len; i++)
    str->data[i] = tolower(str->data[i]);
  rule->br->str = str;  //printf("mod_str:%s------------\n",rule->br->str->data);
  return (NGX_CONF_OK);
}




int 
mod_rx(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  ngx_regex_compile_t  *rgc;
  ngx_str_t           ha;
  


  if (!rule->br)
    return (NGX_CONF_ERROR);
  rule->br->match_type = RX;
  //just prepare a string to hold the directive without 'rx:'
  ha.data = tmp->data+strlen("@rx ");
  ha.len = tmp->len-strlen("@rx ");
  rgc = ngx_pcalloc(r->pool, sizeof(ngx_regex_compile_t));
  if (!rgc)
    return (NGX_CONF_ERROR);
  rgc->options = PCRE_CASELESS|PCRE_MULTILINE;
  rgc->pattern = ha;
  rgc->pool = r->pool;
  rgc->err.len = 0;
  rgc->err.data = NULL;
  
  if (ngx_regex_compile(rgc) != NGX_OK) {
    //printf("ngx_regex_compile:error\n");
    rule->br->match_type = -1;
    rule->br->rx = NULL;
      return (NGX_CONF_ERROR);
    }
  rule->br->rx = rgc;
  //printf("Rx pattern=%s\n",(const char *)(rule->br->rx->pattern.data));
  
  return (NGX_CONF_OK);
}







int
add_mod_from_file(ngx_conf_t *cf,       ngx_http_rule_t    *rule)
{
  ngx_http_dummy_main_conf_t    *alcf = main_cf;
  ngx_str_t            *value;
  ngx_http_rule_t     *rule_r;
  
  if (!alcf || !cf)
    return (NGX_CONF_ERROR);  /* alloc a new rule */ 

      
 
  if (rule->br->user_agent) {
      
    if (alcf->user_agent_rules == NULL) {
      alcf->user_agent_rules = ngx_array_create(cf->pool, 2,
                        sizeof(ngx_http_rule_t));
      if (alcf->user_agent_rules == NULL) 
    return NGX_CONF_ERROR; 
    }
    rule_r = ngx_array_push(alcf->user_agent_rules);
    if (!rule_r) return (NGX_CONF_ERROR);
    memcpy(rule_r, rule, sizeof(ngx_http_rule_t));
    
  }

    if (rule->br->headers) {
      
    if (alcf->header_rules == NULL) {
      alcf->header_rules = ngx_array_create(cf->pool, 2,
                        sizeof(ngx_http_rule_t));
      if (alcf->header_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->header_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, rule, sizeof(ngx_http_rule_t));

    int i;
    ngx_http_rule_t           *r;

    r=alcf->header_rules->elts;
    for(i=0;i<alcf->header_rules->nelts;i++)    
    {
        if(r[i].br->str)
          printf("add br->headers-----------------%d---%s\n",i,r[i].br->str->data );
    } 
    
  }

    
    
  return (NGX_CONF_ERROR);
}


int
mod_str_from_file(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  ngx_str_t    *str;
  uint        i;
  FILE *fp = NULL;
  char filename[256],line[128],*p;
  int len;

  char path[MAX_LEN+1] = {0};
  char name[16] = {0};

  if(-1 == get_executable_path(path,name,sizeof(path)))
    return (NGX_CONF_ERROR);;
  

  if (!rule->br)
    return (NGX_CONF_ERROR);
  
  

  p = strchr(tmp->data,' ');
  if(!p)
      return (NGX_CONF_ERROR);
  p++;
  
  
  snprintf(filename,sizeof(filename)-1,"%srules/%s",path,p);
  fp = fopen(filename,"r");
  if(!fp)    return (NGX_CONF_ERROR); 

    while (read_line(line, sizeof(line)-1, fp))
    {
        p = line;
         /* ignore whitespace */
        while(isspace(*p) && *p != '\0')
            p++;    
        if (*p == '\0')
            continue;
        if (*p == '#')
            continue;
        len = strlen(line); 

        if (!rule->br->str_file) {
             rule->br->str_file = ngx_array_create(r->pool, 1, 
                                    sizeof(ngx_str_t));
            if (!rule->br->str_file)
                return (NGX_CONF_ERROR);
         }
        str = ngx_array_push(rule->br->str_file);
        if (!str)
            return (NGX_CONF_ERROR); 
        str->data = ngx_pcalloc(r->pool, len + 1); 
        if (!str->data)
            return (NGX_CONF_ERROR);
    
        memcpy(str->data,line,len);
        str->len = len;  
        for (i = 0; i < str->len; i++)
            str->data[i] = tolower(str->data[i]);         

        //printf("mod_str_from_file:%s--%x\n",str->data,&str->data);
    
        //add_mod_from_file(cf,rule);
        
    }    
  
  fclose(fp);
  rule->br->match_type = STRFROMFILE; 
  
  return (NGX_CONF_OK);
}

int
mod_streq(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
    //you can add modsecurity operators here,such as @streq
     return (NGX_CONF_OK);
}
int
mod_str_beginwith(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
    //you can add modsecurity operators here,such as @beginsWith
     return (NGX_CONF_OK);
}
int
mod_str_endwith(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
    //you can add modsecurity operators here,such as @endsWith
     return (NGX_CONF_OK);
}





static ngx_http_dummy_parser_t rule_parser[] = {
  {ID_T, dummy_id},
  {SCORE_T, dummy_score},
  {MSG_T, dummy_msg},
  {RX_T, dummy_rx},
  {STR_T, dummy_str},
  {LIBINJ_XSS_T, dummy_libinj_xss},
  {LIBINJ_SQL_T, dummy_libinj_sql},
  {MATCH_ZONE_T, dummy_zone},
  {NEGATIVE_T, dummy_negative},
  {WHITELIST_T, dummy_whitelist},
  {NULL, NULL}
};

#define DEFAULT_MAX_LOC_T    10 


void ngx_http_dummy_line_conf_error(ngx_conf_t *cf, ngx_str_t    *value)
{

    return;
}

int add_one_naxi_rule(ngx_http_rule_t *current_rule,char *buf)
{
    char *index;
    int z,valid,ret;
    ngx_str_t value;
    
    current_rule->type = BR;
    current_rule->br = ngx_pcalloc(cf_pool, sizeof(ngx_http_basic_rule_t));
    if (!current_rule->br)
        return (NGX_CONF_ERROR);
    
    valid = 0;
    for (index = strtok(buf, "\""); index; index = strtok(NULL, "\""))
    {
        /* ignore whitespace */
        while(isspace(*index)) index++;
        if (*index == '\0') continue;
        if(strlen(index)>3)
        {
                    
            value.data = index;
            value.len  = strlen(index);
            
            
             for (z = 0; rule_parser[z].pars; z++) 
             {
                 if (!strncmp(index, rule_parser[z].prefix,  strlen(rule_parser[z].prefix))) 
                  {
                    ret = rule_parser[z].pars(cf, &value,  current_rule);
            
                }
                valid = 1;
              }
        }            
        
    }

    if(valid)
        return (NGX_CONF_OK);
    else
        return (NGX_CONF_ERROR);
}


ngx_http_dummy_main_conf_t *
ngx_http_dummy_create_main_conf(ngx_conf_t *cf) 
{
  ngx_http_dummy_main_conf_t    *mc;
  
  mc = ngx_pcalloc(cf->pool, sizeof(ngx_http_dummy_main_conf_t));
  if (!mc)
    return NULL; /*LCOV_EXCL_LINE*/
  mc->locations = ngx_array_create(cf->pool, DEFAULT_MAX_LOC_T, 
                   sizeof(ngx_http_dummy_loc_conf_t *));
  if (!mc->locations)
    return NULL; /*LCOV_EXCL_LINE*/
  return (mc);
}

/* create log conf struct */
ngx_http_dummy_loc_conf_t *
ngx_http_dummy_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_dummy_loc_conf_t  *conf;
  
  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dummy_loc_conf_t));
  if (conf == NULL)
    return NULL;
  return (conf);
}




/*
** my hugly configuration parsing function.
** should be rewritten, cause code is hugly and not bof proof at all
** does : top level parsing config function, 
**      see foo_cfg_parse.c for stuff
*/
int
ngx_http_dummy_read_conf(ngx_conf_t *cf, ngx_command_t *cmd, 
             void *conf)
{
  ngx_http_dummy_loc_conf_t    *alcf = conf, **bar; 
  ngx_str_t            *value;
  ngx_http_rule_t        rule, *rule_r;
  
#ifdef _debug_readconf
  if (cf) {
    value = cf->args->elts;
    NX_LOG_DEBUG(_debug_readconf, NGX_LOG_EMERG, cf, 0, "TOP READ CONF %V %V", 
         &(value[0]), &(value[1]));  
  }
#endif
  if (!alcf || !cf)
    return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */

  if (!alcf->pushed) { 
    bar = ngx_array_push(main_cf->locations);
    if (!bar)
      return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    *bar = alcf;
    alcf->pushed = 1;
  }
  /*
  ** if it's a basic rule
  */
  //if (!ngx_strcmp(value[0].data, TOP_BASIC_RULE_T) ||
      //!ngx_strcmp(value[0].data, TOP_BASIC_RULE_N)) {
  if (ngx_memcmp(cmd, TOP_BASIC_RULE_T, sizeof(TOP_BASIC_RULE_T) - 1) == 0){    
    memset(&rule, 0, sizeof(ngx_http_rule_t));
    //if (ngx_http_dummy_cfg_parse_one_rule(cf, value, &rule, 
                     // cf->args->nelts) != NGX_CONF_OK)
      {
    /* LCOV_EXCL_START */
    ngx_http_dummy_line_conf_error(cf, value);
    return (NGX_CONF_ERROR);
    /* LCOV_EXCL_STOP */
      }
    /* push in whitelist rules, as it have a whitelist ID array */
    if (rule.wlid_array && rule.wlid_array->nelts > 0) {
      if (alcf->whitelist_rules == NULL) {
    alcf->whitelist_rules = ngx_array_create(cf->pool, 2,
                         sizeof(ngx_http_rule_t));
    if (alcf->whitelist_rules == NULL) {
      return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
      }
      rule_r = ngx_array_push(alcf->whitelist_rules);
      if (!rule_r) {
    return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
      }
      memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
    }
    /* else push in appropriate ruleset : it's a normal rule */
    else {
      if (rule.br->headers || rule.br->headers_var) {
    if (alcf->header_rules == NULL)  {
      alcf->header_rules = ngx_array_create(cf->pool, 2,
                        sizeof(ngx_http_rule_t));
      if (alcf->header_rules == NULL) 
        return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->header_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
      }
      /* push in body match rules (PATCH/POST/PUT) */
      if (rule.br->body || rule.br->body_var) {
    if (alcf->body_rules == NULL) {
      alcf->body_rules = ngx_array_create(cf->pool, 2,
                          sizeof(ngx_http_rule_t));
      if (alcf->body_rules == NULL) 
        return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->body_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
      }
      /* push in raw body match rules (PATCH/POST/PUT) */
      if (rule.br->raw_body) {
    NX_LOG_DEBUG(_debug_readconf, NGX_LOG_EMERG, cf, 0,
         "pushing rule %d in (read conf) raw_body rules", rule.rule_id);
    if (alcf->raw_body_rules == NULL) {
      alcf->raw_body_rules = ngx_array_create(cf->pool, 2,
                          sizeof(ngx_http_rule_t));
      if (alcf->raw_body_rules == NULL) 
        return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->raw_body_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
      }
      /* push in generic rules, as it's matching the URI */
      if (rule.br->url) {
    NX_LOG_DEBUG(_debug_readconf, NGX_LOG_EMERG, cf, 0,
             "pushing rule %d in generic rules",
             rule.rule_id);
    if (alcf->generic_rules == NULL) {
      alcf->generic_rules = ngx_array_create(cf->pool, 2,
                         sizeof(ngx_http_rule_t));
      if (alcf->generic_rules == NULL) 
        return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->generic_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
      }
      /* push in GET arg rules, but we should push in POST rules too  */
      if (rule.br->args_var || rule.br->args) {
    NX_LOG_DEBUG(_debug_readconf, NGX_LOG_EMERG, cf, 0,
             "pushing rule %d in GET rules", rule.rule_id);
    if (alcf->get_rules == NULL) {
      alcf->get_rules = ngx_array_create(cf->pool, 2,
                         sizeof(ngx_http_rule_t));
      if (alcf->get_rules == NULL) 
        return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->get_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
      }
    }
    return (NGX_CONF_OK);
  }
  ngx_http_dummy_line_conf_error(cf, value);
  return (NGX_CONF_ERROR);
}


/*
CheckRule "$SQL >= 8" BLOCK;
*/


int
ngx_http_naxsi_cr_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd,
               void *conf)
{

  ngx_http_dummy_loc_conf_t    *alcf = conf, **bar;  
  ngx_str_t            *value;
  ngx_http_check_rule_t        *rule_c;
  unsigned int    i;
  u_char            *var_end;
  u_char *p,*value1,*value2;     
  

  if (!alcf || !cf)
    return (NGX_CONF_ERROR); 
  if (!alcf->pushed) { 
    bar = ngx_array_push(main_cf->locations);
    if (!bar)
      return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    *bar = alcf;
    alcf->pushed = 1;
  }


          value1 = strchr(cmd,'\"');
        if(value1 == NULL)  return (NGX_CONF_ERROR);
        value1++;

        p= strchr(value1,'\"');
        if(p == NULL)  return (NGX_CONF_ERROR);
        value2 = p +1;
        *p = '\0';

        /* ignore whitespace BLOCK;*/
        while(isspace(*value2)) value2++; 

        i = 0;
         if (!alcf->check_rules)
           alcf->check_rules = ngx_array_create(cf->pool, 2, 
                            sizeof(ngx_http_check_rule_t));
         if (!alcf->check_rules)
           return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
         rule_c = ngx_array_push(alcf->check_rules);
         if (!rule_c) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
         memset(rule_c, 0, sizeof(ngx_http_check_rule_t));
         /* process the first word : score rule */
         if (value1[i] == '$') {
           var_end = (u_char *) strchr(value1, ' ');
           if (!var_end) { /* LCOV_EXCL_START */
            // ngx_http_dummy_line_conf_error(cf, value);
             return (NGX_CONF_ERROR);
             /* LCOV_EXCL_STOP */
           }
           rule_c->sc_tag.len = var_end - value1;
           rule_c->sc_tag.data = ngx_pcalloc(cf->pool, rule_c->sc_tag.len + 1);
           if (!rule_c->sc_tag.data)
             return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
           memcpy(rule_c->sc_tag.data, value1, rule_c->sc_tag.len);
           i += rule_c->sc_tag.len + 1;
         } else {
           /* LCOV_EXCL_START */
           //ngx_http_dummy_line_conf_error(cf, value);
           return (NGX_CONF_ERROR); 
           /* LCOV_EXCL_STOP */
         }

         // move to next word
          while (value1[i] && value1[i] == ' ')
            i++;
          // get the comparison type
          if (value1[i] == '>' && value1[i+1] == '=')
            rule_c->cmp = SUP_OR_EQUAL;
          else if (value1[i] == '>' && value1[i+1] != '=')
            rule_c->cmp = SUP;
          else if (value1[i] == '<' && value1[i+1] == '=')
            rule_c->cmp = INF_OR_EQUAL;
          else if (value1[i] == '<' && value1[i+1] != '=')
            rule_c->cmp = INF;
          else {
            ngx_http_dummy_line_conf_error(cf, value);
            return (NGX_CONF_ERROR);
          }

           // move to next word
          while (value1[i] && !(value1[i] >= '0' && 
                           value1[i] <= '9') && (value1[i] != '-'))
            i++;
        
          // get the score
          rule_c->sc_score = atoi((const char *)(value1+i));
          /* process the second word : Action rule */
          if (ngx_strstr(value2, "BLOCK"))
            rule_c->block = 1;
          else if (ngx_strstr(value2,"ALLOW"))
            rule_c->allow = 1;
          else if (ngx_strstr(value2, "LOG"))
            rule_c->log = 1;
          else if (ngx_strstr(value2, "DROP"))
            rule_c->drop = 1;
          else {
            /* LCOV_EXCL_START */
            ngx_http_dummy_line_conf_error(cf, value);
            return (NGX_CONF_ERROR);
            /* LCOV_EXCL_STOP */
          }


   return (NGX_CONF_OK);
  
  if (ngx_strcmp(value[0].data, TOP_CHECK_RULE_T) &&
      ngx_strcmp(value[0].data, TOP_CHECK_RULE_N))
    return (NGX_CONF_ERROR);
  
/* #ifdef _debug_readconf */
/*   ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  */
/*              "pushing rule %d in check rules", rule.rule_id);   */
/* #endif */

  i = 0;
  if (!alcf->check_rules)
    alcf->check_rules = ngx_array_create(cf->pool, 2, 
                     sizeof(ngx_http_check_rule_t));
  if (!alcf->check_rules)
    return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
  rule_c = ngx_array_push(alcf->check_rules);
  if (!rule_c) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
  memset(rule_c, 0, sizeof(ngx_http_check_rule_t));
  /* process the first word : score rule */
  if (value[1].data[i] == '$') {
    var_end = (u_char *) ngx_strchr((value[1].data)+i, ' ');
    if (!var_end) { /* LCOV_EXCL_START */
      ngx_http_dummy_line_conf_error(cf, value);
      return (NGX_CONF_ERROR);
      /* LCOV_EXCL_STOP */
    }
    rule_c->sc_tag.len = var_end - value[1].data;
    rule_c->sc_tag.data = ngx_pcalloc(cf->pool, rule_c->sc_tag.len + 1);
    if (!rule_c->sc_tag.data)
      return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_c->sc_tag.data, value[1].data, rule_c->sc_tag.len);
    i += rule_c->sc_tag.len + 1;
  } else {
    /* LCOV_EXCL_START */
    ngx_http_dummy_line_conf_error(cf, value);
    return (NGX_CONF_ERROR); 
    /* LCOV_EXCL_STOP */
  }
  // move to next word
  while (value[1].data[i] && value[1].data[i] == ' ')
    i++;
  // get the comparison type
  if (value[1].data[i] == '>' && value[1].data[i+1] == '=')
    rule_c->cmp = SUP_OR_EQUAL;
  else if (value[1].data[i] == '>' && value[1].data[i+1] != '=')
    rule_c->cmp = SUP;
  else if (value[1].data[i] == '<' && value[1].data[i+1] == '=')
    rule_c->cmp = INF_OR_EQUAL;
  else if (value[1].data[i] == '<' && value[1].data[i+1] != '=')
    rule_c->cmp = INF;
  else {
    ngx_http_dummy_line_conf_error(cf, value);
    return (NGX_CONF_ERROR);
  }
  // move to next word
  while (value[1].data[i] && !(value[1].data[i] >= '0' && 
                   value[1].data[i] <= '9') && (value[1].data[i] != '-'))
    i++;
  NX_LOG_DEBUG(_debug_readconf,  NGX_LOG_EMERG, cf, 0,
           "XX-special score in checkrule:%s from (%d)",
           value[1].data, atoi((const char *)value[1].data+i));
  // get the score
  rule_c->sc_score = atoi((const char *)(value[1].data+i));
  /* process the second word : Action rule */
  if (ngx_strstr(value[2].data, "BLOCK"))
    rule_c->block = 1;
  else if (ngx_strstr(value[2].data,"ALLOW"))
    rule_c->allow = 1;
  else if (ngx_strstr(value[2].data, "LOG"))
    rule_c->log = 1;
  else if (ngx_strstr(value[2].data, "DROP"))
    rule_c->drop = 1;
  else {
    /* LCOV_EXCL_START */
    ngx_http_dummy_line_conf_error(cf, value);
    return (NGX_CONF_ERROR);
    /* LCOV_EXCL_STOP */
  }
  return (NGX_CONF_OK);
}




/*
** URL denied DeniedUrl "/RequestDenied";
*/
int 
ngx_http_naxsi_ud_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd,
               void *conf)
{
  ngx_http_dummy_loc_conf_t    *alcf = conf, **bar;  
  int len;
  ngx_str_t            *value;
  char *p,*p_end;

  if (!alcf || !cf)
    return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */

  if (!alcf->pushed) { 
    bar = ngx_array_push(main_cf->locations);
    if (!bar)
      return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    *bar = alcf;
    alcf->pushed = 1;
  }

      if (ngx_memcmp(cmd, TOP_DENIED_URL_T, sizeof(TOP_DENIED_URL_T) - 1) == 0)
      {
          p = strchr(cmd,'\"');
        if(p == NULL)  return (NGX_CONF_ERROR);
        p++;

        p_end = strchr(p,'\"');
        if(p_end == NULL)  return (NGX_CONF_ERROR);
        *p_end = '\0';
        
        
        alcf->denied_url = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if (!alcf->denied_url)
          return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
        alcf->denied_url->data = ngx_pcalloc(cf->pool, strlen(p)+1);
        if (!alcf->denied_url->data)
          return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
        memcpy(alcf->denied_url->data, p, strlen(p));
        alcf->denied_url->len = strlen(p);

        len = strlen(NGX_HTTP_302)+strlen(p) + 4;
        gvar.denied_url.data = ngx_pcalloc(cf->pool, len + 1);
        if(!gvar.denied_url.data)
             return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
        snprintf(gvar.denied_url.data,len + 1,"%s%s\r\n\r\n",NGX_HTTP_302,p);
        gvar.denied_url.len = len;
        //printf("DeniedUrl=%s\n",gvar.denied_url.data);
        
        return (NGX_CONF_OK);
      }

    return NGX_CONF_ERROR;

  /* store denied URL for location */
  if ( (!ngx_strcmp(value[0].data, TOP_DENIED_URL_N) ||
    !ngx_strcmp(value[0].data, TOP_DENIED_URL_T))
       && value[1].len) {
    alcf->denied_url = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!alcf->denied_url)
      return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    alcf->denied_url->data = ngx_pcalloc(cf->pool, value[1].len+1);
    if (!alcf->denied_url->data)
      return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(alcf->denied_url->data, value[1].data, value[1].len);
    alcf->denied_url->len = value[1].len;
    return (NGX_CONF_OK);
  }
  else
    return NGX_CONF_ERROR;
  
  
}



 /*
** handle flags that can be set/modified at runtime
*/
int
ngx_http_naxsi_flags_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd,
                  void *conf)
{
  ngx_http_dummy_loc_conf_t    *alcf = conf, **bar;  

  ngx_str_t            *value;

  if (!alcf || !cf)
    return (NGX_CONF_ERROR); 

  if (!alcf->pushed) { 
    bar = ngx_array_push(main_cf->locations);
    if (!bar)
      return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    *bar = alcf;
    alcf->pushed = 1;
  }

      if (ngx_memcmp(cmd, TOP_ENABLED_FLAG_T, sizeof(TOP_ENABLED_FLAG_T) - 1)
            == 0)
      {
        alcf->enabled = 1;
        return (NGX_CONF_OK);
      }
    if (ngx_memcmp(cmd, TOP_DISABLED_FLAG_T, sizeof(TOP_DISABLED_FLAG_T) - 1)
            == 0)
    {
        alcf->force_disabled = 1;
        return (NGX_CONF_OK);
    }
    if (ngx_memcmp(cmd, TOP_LEARNING_FLAG_T, sizeof(TOP_LEARNING_FLAG_T) - 1)
                == 0)
    {
        alcf->learning = 1;
        return (NGX_CONF_OK);
    }
    if (ngx_memcmp(cmd, TOP_LIBINJECTION_SQL_T, sizeof(TOP_LIBINJECTION_SQL_T) - 1)
                == 0)
    {
        alcf->libinjection_sql_enabled = 1;
        return (NGX_CONF_OK);
    }
    if (ngx_memcmp(cmd, TOP_LIBINJECTION_XSS_T, sizeof(TOP_LIBINJECTION_XSS_T) - 1)
                == 0)
    {
        alcf->libinjection_xss_enabled = 1;
        return (NGX_CONF_OK);
    }




    return (NGX_CONF_ERROR);        

  /* it's a flagrule, just a hack to enable/disable mod */
  if (!ngx_strcmp(value[0].data, TOP_ENABLED_FLAG_T) ||
      !ngx_strcmp(value[0].data, TOP_ENABLED_FLAG_N)) {
    alcf->enabled = 1;
    return (NGX_CONF_OK);
  }
  else
    /* it's a flagrule, just a hack to enable/disable mod */
    if (!ngx_strcmp(value[0].data, TOP_DISABLED_FLAG_T) ||
    !ngx_strcmp(value[0].data, TOP_DISABLED_FLAG_N)) {
      alcf->force_disabled = 1;
      return (NGX_CONF_OK);
    }
    else
      /* it's a flagrule, currently just a hack to enable/disable learning mode */
      if (!ngx_strcmp(value[0].data, TOP_LEARNING_FLAG_T) ||
      !ngx_strcmp(value[0].data, TOP_LEARNING_FLAG_N)) {
    alcf->learning = 1;
    return (NGX_CONF_OK);
      }
      else
    if (!ngx_strcmp(value[0].data, TOP_LIBINJECTION_SQL_T) ||
        !ngx_strcmp(value[0].data, TOP_LIBINJECTION_SQL_N)) {
      NX_LOG_DEBUG(_debug_loc_conf, NGX_LOG_EMERG, cf, 0,
               "LibInjectionSql enabled");
      alcf->libinjection_sql_enabled = 1;
      return (NGX_CONF_OK);
    }
    else
      if (!ngx_strcmp(value[0].data, TOP_LIBINJECTION_XSS_T) ||
          !ngx_strcmp(value[0].data, TOP_LIBINJECTION_XSS_N)) {
        alcf->libinjection_xss_enabled = 1;
        NX_LOG_DEBUG(_debug_loc_conf, NGX_LOG_EMERG, cf, 0,
                 "LibInjectionXss enabled");
        return (NGX_CONF_OK);
      }
      else    
        return (NGX_CONF_ERROR);
}





int
ngx_http_dummy_read_main_conf(ngx_conf_t *cf, ngx_command_t *cmd, 
                  void *conf)
{
  ngx_http_dummy_main_conf_t    *alcf = conf;
  ngx_str_t            *value;
  ngx_http_rule_t        rule, *rule_r;
  
  if (!alcf || !cf)
    return (NGX_CONF_ERROR);  /* alloc a new rule */
  


      
  memset(&rule, 0, sizeof(ngx_http_rule_t));
  

   if (add_one_naxi_rule( &rule,cmd) != NGX_CONF_OK)                     
   {
       
        return (NGX_CONF_ERROR);
        
   }
 
  if (rule.br->headers || rule.br->headers_var) {
      
    if (alcf->header_rules == NULL) {
      alcf->header_rules = ngx_array_create(cf->pool, 2,
                        sizeof(ngx_http_rule_t));
      if (alcf->header_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->header_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
  /* push in body match rules (PATCH/POST/PUT) */
  if (rule.br->body || rule.br->body_var) {
    
    if (alcf->body_rules == NULL) {
      alcf->body_rules = ngx_array_create(cf->pool, 2,
                      sizeof(ngx_http_rule_t));
      if (alcf->body_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->body_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
  /* push in raw body match rules (PATCH/POST/PUT) xx*/
  if (rule.br->raw_body) {
      
    if (alcf->raw_body_rules == NULL) {
      alcf->raw_body_rules = ngx_array_create(cf->pool, 2,
                          sizeof(ngx_http_rule_t));
      if (alcf->raw_body_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->raw_body_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
  /* push in generic rules, as it's matching the URI */
  if (rule.br->url)    {
     
    if (alcf->generic_rules == NULL) {
      alcf->generic_rules = ngx_array_create(cf->pool, 2,
                         sizeof(ngx_http_rule_t));
      if (alcf->generic_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->generic_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
  /* push in GET arg rules, but we should push in POST rules too  */
  if (rule.br->args_var || rule.br->args) {
      
    if (alcf->get_rules == NULL) {
      alcf->get_rules = ngx_array_create(cf->pool, 2,
                     sizeof(ngx_http_rule_t));
      if (alcf->get_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->get_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
       /* push in GET arg rules, but we should push in POST rules too  */
  if (rule.br->args) {
      
    if (alcf->args_rules == NULL) {
      alcf->args_rules = ngx_array_create(cf->pool, 2,
                     sizeof(ngx_http_rule_t));
      if (alcf->args_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->args_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
  
   /* push in cookies rules, as it's matching the URI */
  if (rule.br->cookies)    {
     
    if (alcf->cookies_rules == NULL) {
      alcf->cookies_rules = ngx_array_create(cf->pool, 2,
                         sizeof(ngx_http_rule_t));
      if (alcf->cookies_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->cookies_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
  
  return (NGX_CONF_OK);
}





static ngx_http_dummy_keyword_t rule_keywords[] = {
  {TOP_MAIN_BASIC_RULE_T, ngx_http_dummy_read_main_conf},
  {TOP_DENIED_URL_T, ngx_http_naxsi_ud_loc_conf},
  {TOP_ENABLED_FLAG_T, ngx_http_naxsi_flags_loc_conf},
  {TOP_DISABLED_FLAG_T, ngx_http_naxsi_flags_loc_conf},
  {TOP_LEARNING_FLAG_T, ngx_http_naxsi_flags_loc_conf},
  {TOP_LIBINJECTION_SQL_T, ngx_http_naxsi_flags_loc_conf},
  {TOP_LIBINJECTION_XSS_T, ngx_http_naxsi_flags_loc_conf},
  {TOP_CHECK_RULE_T, ngx_http_naxsi_cr_loc_conf},
  {TOP_BASIC_RULE_T, ngx_http_naxsi_cr_loc_conf},
  {NULL, NULL}
};

static ngx_http_modsecurity_parser_t mod_parser[] = {
  {"@pm ", mod_str},
  {"@pmf ", mod_str_from_file},
  {"@pmFromFile ", mod_str_from_file},
  {"@streq ", mod_streq},
  {"@rx ", mod_rx},
  {"@beginsWith ", mod_str_beginwith},
  {"@endsWith ", mod_str_endwith},
  {"@detectXSS", dummy_libinj_xss},
  {"@detectSQLi", dummy_libinj_sql},
  {NULL, NULL}
};


/*
REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS

*/

int 
mod_p1(ngx_conf_t *r, char *p1, ngx_http_rule_t *rule)
{
  int                    tmp_len, has_zone=0;
  ngx_http_custom_rule_location_t    *custom_rule;
  char *tmp_ptr, *tmp_end;


  if (!rule->br)
    return (NGX_CONF_ERROR);
  rule->br->name.len = 0;
  
  tmp_ptr = p1;
  while (*tmp_ptr) {//printf("%s\n",tmp_ptr);
    
    if (tmp_ptr[0] == '|')
      tmp_ptr++;
    if (tmp_ptr[0] == '!')
      tmp_ptr++;
    /* match global zones */
     if (!strncmp(tmp_ptr, "REQUEST_COOKIES_NAMES", strlen("REQUEST_COOKIES_NAMES"))) {
          rule->br->cookies = 1;
          tmp_ptr += strlen("REQUEST_COOKIES_NAMES");
          has_zone = 1;     
    }
    else if (!strncmp(tmp_ptr, "REQUEST_COOKIES", strlen("REQUEST_COOKIES"))) {
          rule->br->cookies = 1;
          tmp_ptr += strlen("REQUEST_COOKIES");
          has_zone = 1;     
    }
    else   if (!strncmp(tmp_ptr, "REQUEST_FILENAME", strlen("REQUEST_FILENAME"))) {
        rule->br->url = 1;
        tmp_ptr += strlen("REQUEST_FILENAME");
        has_zone = 1;    
    }
    else   if (!strncmp(tmp_ptr, "REQUEST_BODY", strlen("REQUEST_BODY"))) {
        rule->br->body = 1;
        tmp_ptr += strlen("BODY");
        has_zone = 1;    
    }
    else    if (!strncmp(tmp_ptr, "REQUEST_HEADERS_NAMES", strlen("REQUEST_HEADERS_NAMES"))) {
          rule->br->headers = 1;
          tmp_ptr += strlen("REQUEST_HEADERS_NAMES");
          has_zone = 1;
     
    }
    else    if (!strncmp(tmp_ptr, "REQUEST_HEADERS:User-Agent", strlen("REQUEST_HEADERS:User-Agent"))) {
          rule->br->headers = 1;
          tmp_ptr += strlen("REQUEST_HEADERS:User-Agent");
          has_zone = 1;
     
    }
    else   if (!strncmp(tmp_ptr, "ARGS_NAMES", strlen("ARGS_NAMES"))) {
        rule->br->args = 1;
        tmp_ptr += strlen("ARGS_NAMES");
        has_zone = 1;
       
    }
    else  if (!strncmp(tmp_ptr, "ARGS", strlen("ARGS"))) {
          rule->br->args = 1;
          tmp_ptr += strlen("ARGS");
          has_zone = 1;
          continue;
    }
    else    if (!strncmp(tmp_ptr, "FILES_NAMES", strlen("FILES_NAMES"))) {
        rule->br->target_name = 1;
        rule->br->file_ext = 1;
        tmp_ptr += strlen("FILES_NAMES");
        has_zone = 1;
        
    }
    else    if (!strncmp(tmp_ptr, "FILE_EXT", strlen("FILE_EXT"))) {
          rule->br->file_ext = 1;
          //rule->br->body = 1;
          tmp_ptr += strlen("FILE_EXT");
          has_zone = 1;
         
    }
    else    if (!strncmp(tmp_ptr, "FILES", strlen("FILES"))) {
          rule->br->file_ext = 1;
          //rule->br->body = 1;
          tmp_ptr += strlen("FILES");
          has_zone = 1;
         
    }
    else    if (!strncmp(tmp_ptr, "DDOS", strlen("DDOS"))) {
          rule->br->ddos = 1;
          tmp_ptr += strlen("DDOS");
          has_zone = 1;
         
    }
    else
    {
         while (*tmp_ptr && *tmp_ptr != '|')
            tmp_ptr++;
         
        continue;        
    }      
    
    
    if (tmp_ptr[0] == ':')     
    {
            tmp_ptr++;
            
            tmp_end = strchr((const char *) tmp_ptr, '|');
            if (!tmp_end) 
              tmp_end = tmp_ptr + strlen(tmp_ptr);
            tmp_len = tmp_end - tmp_ptr;
            if (tmp_len <= 0)
              return (NGX_CONF_ERROR);
            rule->br->name.data = ngx_pcalloc(r->pool, tmp_len+1);
            if (!rule->br->name.data)
              return (NGX_CONF_ERROR);
            rule->br->name.len = tmp_len;
            memcpy(rule->br->name.data, tmp_ptr, tmp_len);
           //    printf(">>>>found name=%s len=%d\n",rule->br->name.data,rule->br->name.len);
            tmp_ptr += tmp_len;
    }
    
  }
  
  /*
  ** ensure the match-zone actually returns a zone :)
  */
  if (has_zone == 0)    
    return (NGX_CONF_ERROR);

  return (NGX_CONF_OK);
}


/*
"@pmFromFile scanners-user-agents.data"
*/

int 
mod_p2(ngx_conf_t *r, char *p2, ngx_http_rule_t *rule)
{
    int ret ,z;
    ngx_str_t value;
    char *index = p2;
    

    if(index[0] == '!')
    {
        index++;
        rule->br->negative = 1;
    }
    
    value.data = index;
    value.len  = strlen(index);
    ret = NGX_CONF_ERROR;        
            
    for (z = 0; mod_parser[z].pars; z++) 
    {
        if (!strncmp(index, mod_parser[z].prefix,  strlen(mod_parser[z].prefix))) 
        {
            ret = mod_parser[z].pars(cf, &value,  rule);
            
        }
                
     }
    return ret;
}

void
cc_ddos_parse(char *p3, ngx_http_rule_t *rule)
{
     char *var_name = NULL, *var_value = NULL,*s = NULL;;
        
    rule->ddos.block_timeout     = 0;
    rule->ddos.burst_time_slice  = 0;
    rule->ddos.counter_threshold = 0;

    var_name = strstr(p3,"ddos_burst_time_slice=");
    if(!var_name)    return;
    s = strstr(var_name, "=");
    var_value = s + 1;
    while ((*var_value != '\0')&&(isspace(*var_value))) 
         var_value++;
     rule->ddos.burst_time_slice = atoi(var_value);

    var_name = strstr(p3,"ddos_counter_threshold=");
    if(!var_name)    return;
    s = strstr(var_name, "=");
    var_value = s + 1;    
    while ((*var_value != '\0')&&(isspace(*var_value))) 
         var_value++;
    rule->ddos.counter_threshold = atoi(var_value);

    var_name = strstr(p3,"ddos_block_timeout=");
    if(!var_name)    return;
    s = strstr(var_name, "=");
    var_value = s + 1;
    while ((*var_value != '\0')&&(isspace(*var_value))) 
         var_value++;
    rule->ddos.block_timeout = atoi(var_value);

     
    //printf("DDOS burst_time_slice=%d,counter_threshold=%d,block_timeout=%d\n",rule->ddos.burst_time_slice,rule->ddos.counter_threshold,rule->ddos.block_timeout);
    
}

/*

"id:913100,\
   phase:2,\
   block,\
   capture,\
   t:none,t:lowercase,\
   msg:'Found User-Agent associated with security scanner',\
    ................."
*/    

int 
mod_p3(ngx_conf_t *r, char *p3, ngx_http_rule_t *rule)
{
    char *ptr,*p;
    char ruleid[12];
    int len;
    ngx_str_t    *str;

    ptr = strstr(p3,"id:");
    if(!ptr) 
        return (NGX_CONF_ERROR);

    ptr = ptr + strlen("id:");
    p   = ptr;
     while(*p != '\0' && *p != ','&& *p != '\\' && *p != '\"')
            p++;
    len = p - ptr;

    if(len < 1 || len > 10 )
        return (NGX_CONF_ERROR);
    memcpy(ruleid,ptr,len);
    ruleid[len] = '\0';
    rule->rule_id = atoi(ruleid);
    rule->severity = 0;
    
    //must have ruleid, set default log_msg to nomsg
    str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    if (!str)
        return (NGX_CONF_ERROR);
    
    str->data = ngx_pcalloc(r->pool, 512);
    if (!str->data)
        return (NGX_CONF_ERROR);
    snprintf(str->data,len,"nomsg");
    rule->log_msg = str;

    if(strstr(p3,"severity:\'CRITICAL\'"))
        rule->severity = 1;

    ptr = strstr(p3,"msg:\'");     
    if(!ptr) 
        return (NGX_CONF_ERROR);

    ptr = ptr +strlen("msg:\'");
    p   = ptr;
     while(*p != '\0' && *p != ',' && *p != '\\' && *p != '\"'& *p != '\'')
            p++;
    len = p - ptr;

    if(len < 1 || len > 510 )
        return (NGX_CONF_ERROR);
    
    memcpy(str->data,ptr,len);
    str->len = len;    
    rule->log_msg = str;

    cc_ddos_parse(p3, rule);
    //printf("ruleid=%d            msg=%s ",rule->rule_id,str->data);
    
    return (NGX_CONF_OK);
}



int add_one_mod_rule(ngx_http_rule_t *current_rule,char *p1,char *p2,char *p3)
{
    char *index;
    int z,valid,ret;
    ngx_str_t value;
    
    current_rule->type = BR;
    current_rule->br = ngx_pcalloc(cf_pool, sizeof(ngx_http_basic_rule_t));
    if (!current_rule->br)
        return (NGX_CONF_ERROR);

    
    ret = mod_p3(cf, p3,current_rule);    
    if(ret == NGX_CONF_ERROR)
        return (NGX_CONF_ERROR);
    
    ret = mod_p1(cf, p1,current_rule);
    if(ret == NGX_CONF_ERROR)
        return (NGX_CONF_ERROR);
        
    ret = mod_p2(cf, p2,current_rule);        
    return ret;
}




int
add_rules(ngx_conf_t *cf, char *p1,char *p2 ,char *p3, 
                  void *conf)
{
  ngx_http_dummy_main_conf_t    *alcf = conf;
  ngx_str_t            *value;
  ngx_http_rule_t        rule, *rule_r;
  
  if (!alcf || !cf)
    return (NGX_CONF_ERROR);  /* alloc a new rule */
  

  
  memset(&rule, 0, sizeof(ngx_http_rule_t));
  if (add_one_mod_rule( &rule,p1,p2,p3) != NGX_CONF_OK)      
       return (NGX_CONF_ERROR);  
  if(rule.log_msg && rule.log_msg->data)
  {
       if(rule.severity == 1)
          printf("%d        severity:'CRITICAL'        %s\n",rule.rule_id,rule.log_msg->data);
     else
         printf("%d        severity:'WARNING'        %s\n",rule.rule_id,rule.log_msg->data);
  }
  else
      printf("%d                abnormal\n",rule.rule_id);
   
  if (rule.br->headers || rule.br->headers_var) {
      
    if (alcf->header_rules == NULL) {
      alcf->header_rules = ngx_array_create(cf->pool, 2,
                        sizeof(ngx_http_rule_t));
      if (alcf->header_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->header_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
  
  /* push in body match rules (PATCH/POST/PUT) */
  if (rule.br->body || rule.br->body_var) {
    
    if (alcf->body_rules == NULL) {
      alcf->body_rules = ngx_array_create(cf->pool, 2,
                      sizeof(ngx_http_rule_t));
      if (alcf->body_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->body_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
  
  /* push in raw body match rules (PATCH/POST/PUT) xx*/
  if (rule.br->raw_body) {     
    if (alcf->raw_body_rules == NULL) {
      alcf->raw_body_rules = ngx_array_create(cf->pool, 2,
                          sizeof(ngx_http_rule_t));
      if (alcf->raw_body_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->raw_body_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
  
  /* push in generic rules, as it's matching the URI */
  if (rule.br->url)    {
     
    if (alcf->generic_rules == NULL) {
      alcf->generic_rules = ngx_array_create(cf->pool, 2,
                         sizeof(ngx_http_rule_t));
      if (alcf->generic_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->generic_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
  
  /* push in GET arg rules, but we should push in POST rules too  */
  if (rule.br->get_args) {
      
    if (alcf->args_get_rules == NULL) {
      alcf->args_get_rules = ngx_array_create(cf->pool, 2,
                     sizeof(ngx_http_rule_t));
      if (alcf->args_get_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->args_get_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }

    /* push in GET arg rules, but we should push in POST rules too  */
  if (rule.br->post_args) {
      
    if (alcf->args_post_rules == NULL) {
      alcf->args_post_rules = ngx_array_create(cf->pool, 2,
                     sizeof(ngx_http_rule_t));
      if (alcf->args_post_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->args_post_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }

      /* push in GET arg rules, but we should push in POST rules too  */
  if (rule.br->args) {
      
    if (alcf->args_rules == NULL) {
      alcf->args_rules = ngx_array_create(cf->pool, 2,
                     sizeof(ngx_http_rule_t));
      if (alcf->args_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->args_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }
  
   /* push in cookies rules, as it's matching the URI */
  if (rule.br->cookies)    {
     
    if (alcf->cookies_rules == NULL) {
      alcf->cookies_rules = ngx_array_create(cf->pool, 2,
                         sizeof(ngx_http_rule_t));
      if (alcf->cookies_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->cookies_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }    

  /* push in files rules, as it's matching the URI */
  if (rule.br->file_ext)    {
     
    if (alcf->file_rules == NULL) {
      alcf->file_rules = ngx_array_create(cf->pool, 2,
                         sizeof(ngx_http_rule_t));
      if (alcf->file_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->file_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }    

  /* push in ddos rules, as it's matching the URI */
  if (rule.br->ddos)    {
     
    if (alcf->ddos_rules == NULL) {
      alcf->ddos_rules = ngx_array_create(cf->pool, 2,
                         sizeof(ngx_http_rule_t));
      if (alcf->ddos_rules == NULL) 
    return NGX_CONF_ERROR; /* LCOV_EXCL_LINE */
    }
    rule_r = ngx_array_push(alcf->ddos_rules);
    if (!rule_r) return (NGX_CONF_ERROR); /* LCOV_EXCL_LINE */
    memcpy(rule_r, &rule, sizeof(ngx_http_rule_t));
  }    
  
  return (NGX_CONF_OK);
}



/*
** check variable + name against a set of rules, checking against 'custom' location rules too.
*/

void chk_http_libinjection(        ngx_str_t    *name,
                ngx_str_t    *value,
                ngx_http_request_ctx_t *ctx,                
                enum DUMMY_MATCH_ZONE    zone) {
  /* 
  ** Libinjection integration : 
  ** 1 - check if libinjection_sql is explicitly enabled
  ** 2 - check if libinjection_xss is explicitly enabled
  ** if 1 is true : perform check on both name and content,
  **            in case of match, apply internal rule
  **            increasing the LIBINJECTION_SQL score
  ** if 2 is true ; same as for '1' but with 
  **            LIBINJECTION_XSS
  */
  sfilter state;
  int issqli;
  
  if (ctx->libinjection_sql) {
    
    /* hardcoded call to libinjection on NAME, apply internal rule if matched. */
    libinjection_sqli_init(&state, (const char *)name->data, name->len, FLAG_NONE);
    issqli = libinjection_is_sqli(&state);
    if (issqli == 1) { 
     printf("libinjection_sql matched attack,name=%s\n",name->data);
    }
    
    /* hardcoded call to libinjection on CONTENT, apply internal rule if matched. */
    libinjection_sqli_init(&state, (const char *)value->data, value->len, FLAG_NONE);
    issqli = libinjection_is_sqli(&state);
    if (issqli == 1) {
      printf("libinjection_sql matched attack,value=%s\n",value->data);   
    }
  }
  
  if (ctx->libinjection_xss) {
    /* first on var_name */
    issqli = libinjection_xss((const char *) name->data, name->len);
    if (issqli == 1) {
      printf("libinjection_xss matched attack,name=%s\n",name->data);
    }
    
    /* hardcoded call to libinjection on CONTENT, apply internal rule if matched. */
    issqli = libinjection_xss((const char *) value->data, value->len);
    if (issqli == 1) {
     printf("libinjection_xss matched attack,value=%s\n",value->data);        
    }
  }
}


/*
** in : string to inspect, associated rule
** does : apply the rule on the string, return 1 if matched, 
**      0 else and -1 on error
*/
int
chk_basic_rule(ngx_str_t *str,
                   ngx_http_rule_t *rl,
                   ngx_int_t    *nb_match)
  
{
  ngx_int_t    match, tmp_idx, len;
  unsigned char *ret;
  int        captures[30];

  int flags = 0;    
  int nm = 1;
  regmatch_t pmatch[nm];
 
    
  if (!rl->br || !nb_match) return (-1);
  
  
  *nb_match = 0;
  if (rl->br->match_type == RX && rl->br->rx) {
    tmp_idx = 0;
    len = str->len;
  
#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
    match = ngx_regex_exec_match(rl->br->rx->regex,(const char *) str->data,nm,pmatch,flags);  
#else
    match = ngx_regex_exec_match(&rl->br->rx->re,(const char *) str->data,nm,pmatch,flags); 
#endif
 
    *nb_match += match;
    
    
    if (*nb_match > 0) {
      if (rl->br->negative)
    return (0);
      else 
    return (1);
    }
    else if (*nb_match == 0) {
      if (rl->br->negative)
    return (1);
      else
    return (0);
    }
    return (-1);
  }
  else if (rl->br->match_type == STRFROMFILE  && rl->br->str_file) {

        int j;
        ngx_str_t *needle;
        needle = rl->br->str_file->elts;
        for(j =0 ; j< rl->br->str_file->nelts; j++)
        {                            
            match = 0;
            tmp_idx = 0;
            while (1)   
            {
                    ret = (unsigned char *) strfaststr((unsigned char *)str->data+tmp_idx,
                                   (unsigned int)str->len - tmp_idx,
                                   needle[j].data,
                                   needle[j].len);
                    if (ret)
                    {
                      match = 1;
                      *nb_match = *nb_match+1;
                    }
                    else
                          break;
                    if (nb_match && ret < (str->data + str->len)) 
                    {
                      tmp_idx = (ret - str->data) + 1;
                      if (tmp_idx > (int) (str->len - 1))
                        break;
                    }
                    else
                          break;
            }

            if (match)  return (1);
                  
        }
  }
  else if (rl->br->match_type == STR  && rl->br->str) {
    match = 0;//printf("%d--%s--\n",rl->rule_id, (unsigned char *)rl->br->str->data);
    tmp_idx = 0;
    while (1)    {
      ret = (unsigned char *) strfaststr((unsigned char *)str->data+tmp_idx,
                     (unsigned int)str->len - tmp_idx,
                     (unsigned char *)rl->br->str->data,
                     (unsigned int)rl->br->str->len);
      if (ret) {
    match = 1;
    *nb_match = *nb_match+1;
      }
      else
    break;
      if (nb_match && ret < (str->data + str->len)) {
    tmp_idx = (ret - str->data) + 1;
    if (tmp_idx > (int) (str->len - 1))
      break;
      }
      else
    break;
    }

    
    if (match) {
      if (rl->br->negative)
    return (0);
      else
    return (1);
    }
    else {
      if (rl->br->negative)
    return (1);
      else
    return (0);
    }
    
  }
  else if (rl->br->match_type == LIBINJ_XSS) {
    if (libinjection_xss((const char *) str->data, str->len) == 1)
      return (1);
  }
  else if (rl->br->match_type == LIBINJ_SQL) {//printf(" rule->br->match_type = LIBINJ_sql :%s\n",(const char *)str->data);
    sfilter state;

    libinjection_sqli_init(&state, (const char *)str->data, str->len, FLAG_NONE);
    if (libinjection_is_sqli(&state) == 1)
      return (1);
  }
  
  return (0);
}

int chk_all_rules(ngx_str_t *name, enum DUMMY_MATCH_ZONE    zone,http_waf_msg *req)
{
    //ngx_http_dummy_loc_conf_t *cf = conf;
    ngx_array_t *rules = NULL;
    int i,ret = 0;
    ngx_http_rule_t           *r;
    ngx_int_t               nb_match = 0;

    switch(zone) {
      case HEADERS:
        rules = main_cf->header_rules;
        break;
      case URL:
        rules = main_cf->get_rules;
        break;
      case ARGS_GET:
        rules = main_cf->args_get_rules;
        break;
      case ARGS_POST:
        rules = main_cf->args_post_rules;
        break;
      case ARGS:
        rules = main_cf->args_rules;
        break;
      case BODY:
        rules = main_cf->body_rules;
        break;
      case COOKIE:
       rules = main_cf->cookies_rules;
        break;
      case FILE_EXT:
       rules = main_cf->file_rules;
        break;
      case DDOS:
       rules = main_cf->ddos_rules;
        break;
      default:
        break;
      };
        
    if (rules == NULL)
        return 0;
    if(req && req->rule_id > 200) //1-200 reserve
        return 0;

      /* check for overlong/surrogate utf8 encoding */
  if (ngx_utf8_check(name) != NULL) { 
    ret = ATK_UTF8*200;
    req->rule_id  = ret;
    snprintf(http_log_msg,sizeof(http_log_msg)-1,"UTF8 ERROR,Perhaps  Attack.");
    req->str_matched = name->data;
    req->log_msg     = http_log_msg;
    return (ret);
  }
    
    r = rules->elts;
    for (i = 0; i < rules->nelts ; i++)
    {    
        ret = chk_basic_rule(name, &(r[i]), &nb_match);
        if(ret == 1)
        {    
            if(req)
            {
                req->rule_id  = r[i].rule_id;
                req->severity = r[i].severity;
                if(r[i].log_msg && r[i].log_msg->data);
                req->log_msg = r[i].log_msg->data;    
                req->str_matched = name->data;
                
                if(zone == DDOS)
                {
                    req->ddos_rule.block_timeout     = r[i].ddos.block_timeout;
                    req->ddos_rule.burst_time_slice  = r[i].ddos.burst_time_slice;
                    req->ddos_rule.counter_threshold = r[i].ddos.counter_threshold;
                }
            }
            //printf("Ruleid [%d]:   \"%s\"  Matched   Attack!\n",r[i].rule_id,name->data);    
            return ret;
        }    
    
    }

    return 0;

}


int chk_mqtt_rules(ngx_str_t *name, enum DUMMY_MATCH_ZONE    zone,mqtt_waf_msg *req)
{
    //ngx_http_dummy_loc_conf_t *cf = conf;
    ngx_array_t *rules = NULL;
    int i,ret = 0;
    ngx_http_rule_t           *r;
    ngx_int_t               nb_match = 0;

    switch(zone) {
      case HEADERS:
        rules = main_cf->header_rules;
        break;     
      case C_MQTT_SUBSCRIBE:
        rules = main_cf->args_post_rules;
        break;
      case C_MQTT_PUBLISH:
        rules = main_cf->args_rules;
        break;
       case ARGS:
        rules = main_cf->args_rules;
        break;
      case C_MQTT_LOGIN:
        rules = main_cf->body_rules;
        break;      
      case FILE_EXT:
       rules = main_cf->file_rules;
        break;
      case DDOS:
       rules = main_cf->ddos_rules;
        break;
      default:
        break;
      };
        
    if (rules == NULL)
        return 0;
    if(req && req->rule_id > 200) //1-200 reserve
        return 0;

      /* check for overlong/surrogate utf8 encoding */
  if (ngx_utf8_check(name) != NULL) { 
    ret = ATK_UTF8*200;
    req->rule_id  = ret;
    snprintf(mqtt_log_msg,sizeof(mqtt_log_msg)-1,"UTF8 ERROR,Perhaps  Attack.");
    req->str_matched = name->data;
    req->log_msg     = mqtt_log_msg;
    return (ret);
  }
    
    r = rules->elts;
    for (i = 0; i < rules->nelts ; i++)
    {    
        ret = chk_basic_rule(name, &(r[i]), &nb_match);
        if(ret == 1)
        {    
            if(req)
            {
                req->rule_id  = r[i].rule_id;
                req->severity = r[i].severity;
                if(r[i].log_msg && r[i].log_msg->data);
                req->log_msg = r[i].log_msg->data;    
                req->str_matched = name->data;
                
                if(zone == DDOS)
                {
                    req->ddos_rule.block_timeout     = r[i].ddos.block_timeout;
                    req->ddos_rule.burst_time_slice  = r[i].ddos.burst_time_slice;
                    req->ddos_rule.counter_threshold = r[i].ddos.counter_threshold;
                }
            }
            //printf("Ruleid [%d]:   \"%s\"  Matched   Attack!\n",r[i].rule_id,name->data);    
            return ret;
        }    
    
    }

    return 0;

}

int init_naxsi_rules(void)
{

    ngx_http_dummy_loc_conf_t **loc_cf;
    unsigned int                 i;

     /* Go with each locations registred in the srv_conf. */
      loc_cf = main_cf->locations->elts;
      
      for (i = 0; i < main_cf->locations->nelts; i++) {
        if (loc_cf[i]->enabled && (!loc_cf[i]->denied_url || loc_cf[i]->denied_url->len <= 0)) {
          /* LCOV_EXCL_START */
          ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
                 "Missing DeniedURL, abort.");
          return (NGX_ERROR);
          /* LCOV_EXCL_STOP */
        }
        loc_cf[i]->flag_enable_h = ngx_hash_key_lc((u_char *)RT_ENABLE, strlen(RT_ENABLE));
        loc_cf[i]->flag_learning_h = ngx_hash_key_lc((u_char *)RT_LEARNING, strlen(RT_LEARNING));
        loc_cf[i]->flag_post_action_h = ngx_hash_key_lc((u_char *)RT_POST_ACTION, strlen(RT_POST_ACTION));
        loc_cf[i]->flag_extensive_log_h = ngx_hash_key_lc((u_char *)RT_EXTENSIVE_LOG, strlen(RT_EXTENSIVE_LOG));
        loc_cf[i]->flag_libinjection_xss_h = ngx_hash_key_lc((u_char *)RT_LIBINJECTION_XSS, strlen(RT_LIBINJECTION_XSS));
        loc_cf[i]->flag_libinjection_sql_h = ngx_hash_key_lc((u_char *)RT_LIBINJECTION_SQL, strlen(RT_LIBINJECTION_SQL));
        
        if(ngx_http_dummy_create_hashtables_n(loc_cf[i], cf) != NGX_OK) {
          /* LCOV_EXCL_START */
          ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
                 "WhiteList Hash building failed");
          return (NGX_ERROR);
          /* LCOV_EXCL_STOP */
        }
      }


    /* initialize prng (used for fragmented logs) */
      srandom(time(0) * getpid());
      
      /* 
      ** initalise internal rules for libinjection sqli/xss 
      ** (needs proper special scores) 
      */
      nx_int__libinject_sql = ngx_pcalloc(cf->pool, sizeof(ngx_http_rule_t));
      nx_int__libinject_xss = ngx_pcalloc(cf->pool, sizeof(ngx_http_rule_t));
      if (!nx_int__libinject_xss || !nx_int__libinject_sql) return (NGX_ERROR);
      nx_int__libinject_sql->sscores = ngx_array_create(cf->pool, 2,
                                 sizeof(ngx_http_special_score_t));
      nx_int__libinject_xss->sscores = ngx_array_create(cf->pool, 2,
                                sizeof(ngx_http_special_score_t));
      if (!nx_int__libinject_sql->sscores || !nx_int__libinject_xss->sscores ) return (NGX_ERROR); /* LCOV_EXCL_LINE */
      /* internal ID sqli - 17*/
      nx_int__libinject_sql->rule_id = 17;
      /* internal ID xss - 18*/
      nx_int__libinject_xss->rule_id = 18;    
      /* libinjection sqli/xss - special score init */
      ngx_http_special_score_t *libjct_sql = ngx_array_push(nx_int__libinject_sql->sscores);
      ngx_http_special_score_t *libjct_xss = ngx_array_push(nx_int__libinject_xss->sscores);
      if (!libjct_sql || !libjct_xss) return (NGX_ERROR); /* LCOV_EXCL_LINE */
      libjct_sql->sc_tag = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
      libjct_xss->sc_tag = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
      if (!libjct_sql->sc_tag || !libjct_xss->sc_tag) return (NGX_ERROR); /* LCOV_EXCL_LINE */
      libjct_sql->sc_tag->data = ngx_pcalloc(cf->pool, 18 /* LIBINJECTION_SQL */);
      libjct_xss->sc_tag->data = ngx_pcalloc(cf->pool, 18 /* LIBINJECTION_XSS */);
      if (!libjct_sql->sc_tag->data || !libjct_xss->sc_tag->data) return (NGX_ERROR); /* LCOV_EXCL_LINE */
      strncpy((char *)libjct_sql->sc_tag->data, (char *)"$LIBINJECTION_SQL", 17);
      strncpy((char *)libjct_xss->sc_tag->data, (char *)"$LIBINJECTION_XSS", 17);
      libjct_xss->sc_tag->len = 17;
      libjct_sql->sc_tag->len = 17;
      libjct_sql->sc_score = 8;
      libjct_xss->sc_score = 8;


    return 0;
}
static unsigned int get_executable_path( char* processdir,char* processname, unsigned int len)
{
    char* path_end;
    if(readlink("/proc/self/exe", processdir,len) <=0)
        return -1;
    path_end = strrchr(processdir,  '/');
    if(path_end == NULL)
        return -1;
    ++path_end;
    strncpy(processname, path_end,16);
    *path_end = '\0';
    return (unsigned int)(path_end - processdir);
}


/*
SecRequestBodyLimit 13107200
SecRuleEngine DetectionOnly
......

*/     
    
void parse_global_var(char *buf)
{
    
     
     if (strncasecmp(buf, "LogToFile",sizeof("LogToFile")-1) == 0) 
         gvar.log = 1;
     
     if (strncasecmp(buf, "ruleEngine detectiononly",sizeof("ruleEngine detectiononly")-1) == 0) 
         gvar.action = ALERT;
     
     if (strcasecmp(buf, "ruleEngine drop") == 0) 
         gvar.action = DROP;
     
     if (strcasecmp(buf, "ruleAction alert") == 0) 
         gvar.action = ALERT;
     
     if (strcasecmp(buf, "ruleAction drop") == 0) 
         gvar.action = DROP;

      if (strcasecmp(buf, "ErrIsAttack on") == 0) 
         gvar.err_is_attack = 1;
     
      
     if (strncasecmp(buf, "SecRequestBodyLimit",sizeof("SecRequestBodyLimit")-1) == 0)
         gvar.request_body_limit = atoi(buf + sizeof("SecRequestBodyLimit"));

     if (strncasecmp(buf, "SecRequestHeaderLimit",sizeof("SecRequestHeaderLimite")-1) == 0) 
         gvar.request_header_limit = atoi(buf + sizeof("SecRequestHeaderLimit"));
     
     if (strncasecmp(buf, "SecRequestArgsLimit",sizeof("SecRequestArgsLimit")-1) == 0) 
         gvar.request_args_limit = atoi(buf + sizeof("SecRequestArgsLimit"));

     if (strncasecmp(buf, "rule_dir",sizeof("rule_dir")-1) == 0) 
     {
         gvar.rule_dir.data = (unsigned char *) calloc(strlen(buf),sizeof(char));
        if(!gvar.rule_dir.data) 
            return;
        gvar.rule_dir.len  = strlen(buf);
        sprintf(gvar.rule_dir.data,"%s",buf + sizeof("rule_dir") );
     }

      if (strncasecmp(buf, "www_dir",sizeof("www_dir")-1) == 0) 
     {
         gvar.www_dir.data = (unsigned char *) calloc(strlen(buf),sizeof(char));
        if(!gvar.www_dir.data) 
            return;
        gvar.www_dir.len  = strlen(buf);
        sprintf(gvar.www_dir.data,"%s",buf + sizeof("www_dir") );
     }

     
}



/*
SecRule ARGS_NAMES "@rx [\n\r]" \
    "id:921150,\
    phase:2,\
    block,\
    ver:'OWASP_CRS/3.1.0'"
*/     
    
int parse_modsecurity_rule(char *buf)
{
    char *p,*p1,*p2,*p3;    
    int count = 0;

    
    p1 = p2 =p3 =NULL;

    p = strrchr(buf,'\"');
    if(!p) return 0;
    *p = '\0';

    p = strrchr(buf,'\"');
    if(!p) return 0;

    p3 = p + 1; //id:921150...
    *p = '\0';

    p = strrchr(buf,'\"');
    if(!p) return 0;
    *p = '\0';

    //p = strrchr(buf,'\"');
    p = strstr(buf,"\"@");
    if(!p)
    {    
        p = strstr(buf,"\"!");
        if(!p)    
            return 0;
    }

    p2 = p + 1; //!@rx [\n\r]

    
    p = strchr(buf,' ');
    if(!p) return 0;

    p1 = p + 1; //ARGS_NAMES

    p = strchr(p1,' ');
    if(!p) return 0;
    *p = '\0';

    
    
    //printf("p1=%s,p2=%s,p3=%s\n",p1,p2,p3);
    //printf("p1=%s,p2=%s\n",p1,p2);
    add_rules(cf,p1,p2,p3,main_cf);
    return count;
}


void read_modsecurity_config_file(const char *config_dir,char *file)
{
    
    char filename[MAX_LEN+1] = {0};
    char path[MAX_LEN+1] = {0};
    char name[16] = {0};
    char line[2048],rule_str[4096];
    char *p;
    
    unsigned int len = 0;    
    FILE *fp = NULL;
    
    if(config_dir == NULL) 
    {
        if(-1 == get_executable_path(path,name,sizeof(path)))
            return;
        
        snprintf(filename,MAX_LEN,"%s%s",path,file);
    }
    else
        snprintf(filename,MAX_LEN,"%s%s",config_dir,file);
    

    fp = fopen(filename,"r");
    if(!fp)    return;

    while (read_line(line, sizeof(line), fp))
    {
        p = line;
         /* ignore whitespace */
        while(isspace(*p) && *p != '\0')
            p++;    
        if (*p == '\0')
            continue;
        

        if(*p == '#')
        {
            if(len > 0)
                parse_modsecurity_rule(rule_str);
            len = 0;            
            continue;
        }

        parse_global_var(line);
        
        if(memcmp(p,"SecRule",sizeof("SecRule")-1)==0)        
        {
            if(len > 0)
                parse_modsecurity_rule(rule_str);
            len = snprintf(rule_str,sizeof(rule_str)-1,"%s",p);
        }
        else
        {
            if(strrchr(line,'\\') || strrchr(line,'\"'))
            {
                if(len > 0 && len < sizeof(rule_str))
                {
                    len += snprintf(rule_str + len,sizeof(rule_str)-len,"%s",p);
                    
                }
            }
        }
    }


    if(len > 0)
        parse_modsecurity_rule(rule_str);

    fclose(fp);    


}


/*
MainRule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" \
"msg:sql keywords" \
"mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" \
"s:$SQL:4" id:1000;
*/     
    
int parse_naxsi_rule(char *buf)
{
    char *index;
    int z,ret,valid;
    ngx_http_rule_t        rule;
    ngx_http_rule_t *current_rule;
    ngx_str_t value;
    
    
    //cf->pool = cf_pool;
    memset(&rule, 0, sizeof(ngx_http_rule_t));
    valid = 0;
    current_rule = &rule;
    current_rule->type = BR;
    current_rule->br = ngx_pcalloc(cf->pool, sizeof(ngx_http_basic_rule_t));
    if (!current_rule->br)
      return (NGX_CONF_ERROR);
    
    for (index = strtok(buf, "\""); index; index = strtok(NULL, "\""))
    {
        /* ignore whitespace */
        while(isspace(*index)) index++;
        if (*index == '\0') continue;
        if(strlen(index)>3)
        {
            printf("%s\n",index);    
            
            value.data = index;
            value.len  = strlen(index);
            
            
             for (z = 0; rule_parser[z].pars; z++) 
             {
                 if (!strncmp(index, rule_parser[z].prefix,  strlen(rule_parser[z].prefix))) 
                  {
                    ret = rule_parser[z].pars(cf, &value,  current_rule);
            
                }
                valid = 1;
              }
        }            
        
    }
}

void read_naxsi_config_file(const char *config_dir,char *file)
{
    
    char filename[MAX_LEN+1] = {0};
    char path[MAX_LEN+1] = {0};
    char name[16] = {0};
    char line[512],rule_str[1024];
    char *p;
    int z,ret;
    
    unsigned int len = 0;    
    FILE *fp = NULL;
    
    if(config_dir == NULL) 
    {
        if(-1 == get_executable_path(path,name,sizeof(path)))
            return;
        
        snprintf(filename,MAX_LEN,"%s%s",path,file);
    }
    else
        snprintf(filename,MAX_LEN,"%s%s",config_dir,file);
    

    fp = fopen(filename,"rb");
    if(!fp)    return;

    while (read_line(line, sizeof(line), fp))
    {
        p = line;
         /* ignore whitespace */
        while(isspace(*p) && *p != '\0')
            p++;    
        if (*p == '\0')
            continue;
        

        if(*p == '#')                
            continue;    

        parse_global_var(line);

        snprintf(rule_str,sizeof(rule_str)-1,"%s",p);//printf("\n%s\n",p);

         for (z = 0; rule_keywords[z].pars; z++) 
         {
             if (!strncasecmp(rule_str, rule_keywords[z].prefix,  strlen(rule_keywords[z].prefix))) 
              {
                //ret = rule_keywords[z].pars(cf,rule_str,conf);                printf("%s\n",line);
                ret = rule_keywords[z].pars(cf,rule_str,main_cf);
            
              }
                
          }            
        
    }


    
    fclose(fp);
        
        
    init_naxsi_rules();

}

int init_pools(void)
{

    memset(&gvar,0,sizeof(gvar));

    gvar.log  = 0;  
    gvar.action = ALERT;
    gvar.rule_dir.data = NULL;
    gvar.rule_dir.len  = 0;
    gvar.www_dir.data = NULL;
    gvar.www_dir.len  = 0;
    gvar.request_args_limit = 128;
    
    gvar.denied_url.data = NGX_HTTP_200;
    gvar.denied_url.len  = strlen(NGX_HTTP_200);
    
    cf_pool = ngx_create_pool(1024);
    if(cf_pool == NULL)     return 0;

    cf = calloc(1,sizeof(ngx_conf_t));
    if(cf == NULL)        return 0;

    cf->pool = cf_pool; 
    main_cf  = ngx_http_dummy_create_main_conf(cf);
    if(main_cf == NULL)        return 0;

    conf  =  ngx_http_dummy_create_loc_conf(cf);
    if(conf == NULL)        return 0;



    return 1;
}

void free_pool(void)
{
    
    if(cf_pool)
        ngx_destroy_pool(cf_pool);
    if(cf)
        free(cf);

}


void get_pid(void)
{
    FILE *fp;
    int pid;
    char tmp[16];

    pid=getpid();
    if(pid<=0)
        return;

    fp=fopen("/hihttps/pid/hihttps.pid","w+");
    if(fp)
    {
        snprintf(tmp,sizeof(tmp)-1,"%d",pid);
        fputs(tmp,fp);
        fclose(fp);
    }    
    //printf("PID=%d ",pid);
}

void init_rules()
{
    
    DIR *dir;
    struct dirent *ptr;    
    char rule_dir[MAX_LEN+1],exe_dir[MAX_LEN+1];
    char name[16];    
    
    init_pools();
    get_pid();

    snprintf(exe_dir,sizeof(exe_dir) - 1,"/hihttps/");
    if(-1 == get_executable_path(exe_dir,name,sizeof(exe_dir)))
    {
            printf("get_executable_path:err!\n");
            exit(0);
            return;
    }

   
    /*
    printf("request_header_limit=%d,request_args_limit=%d,request_body_limit=%d,rule_dir=%s\n",
             gvar.request_header_limit,gvar.request_args_limit,gvar.request_body_limit,
              exe_dir);*/
    /*machine learing cfg */
    read_naxsi_config_file(exe_dir,"ml.cfg");
    
    printf("The OWASP ModSecurity Core Rule Set (CRS) is a set of generic attack detection rules for use with ModSecurity or compatible web application firewalls. \n");    

    snprintf(rule_dir,MAX_LEN,"%srules/",exe_dir);
    if ((dir = opendir(rule_dir)) == NULL)
    {
        perror("Open rule dir error...");
        printf("Not found any rules,Please visit https://github.com/SpiderLabs/owasp-modsecurity-crs to download the OWASP ModSecurity Core Rule...\n\n");
        return;
    }
    
    while ((ptr = readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".") == 0 || strcmp(ptr->d_name,"..") == 0)    ///current dir OR parrent dir
            continue;
        else if(ptr->d_type == 8)
        {
            
            if(strstr(ptr->d_name,".conf") && !strstr(ptr->d_name,".bak"))          
                read_modsecurity_config_file(rule_dir,ptr->d_name);
               if(strstr(ptr->d_name,".rule") && !strstr(ptr->d_name,".bak"))          
                read_naxsi_config_file(rule_dir,ptr->d_name);
            
        }
        
    }
    closedir(dir);    

    printf("The OWASP ModSecurity Core Rule Set is distributed under Apache Software License (ASL) version 2. For More Rules Please visit https://github.com/SpiderLabs/owasp-modsecurity-crs/\n\n");
    init_simhash_from_atkfile();
    init_cc_ddos();
    read_www_files(gvar.www_dir.data);
    read_white_url(rule_dir);
    read_black_url(rule_dir);
    init_atk_log();
    open_log_socket();        
    ai_file_train_init(exe_dir);//20191201
    
}



