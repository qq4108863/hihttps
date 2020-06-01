#ifndef __RULES_H__
#define __RULES_H__

#include "ssl_array.h"
#include "ssl_hash.h"
#include "ssl_regex.h"
#include "httpx.h"
#include "mqtt.h"





#ifndef __NAXSI_DEBUG
#define __NAXSI_DEBUG
#define NX_DEBUG(FEATURE, DEF, LOG, ST, ...) printf(" ")
#endif

#ifndef __NAXSI_LOG_DEBUG
#define __NAXSI_LOG_DEBUG
#define NX_LOG_DEBUG(FEATURE, DEF, LOG, ST, ...) printf("")
#endif


#define ngx_conf_log_error(FEATURE, DEF, LOG, ST, ...) printf("ngx_conf_log_error")


#define ALLOW 0
#define DROP 1
#define ALERT 2
#define REQ_CNT 8



enum ATK_TYPE {
  ATK_NONE = 0,
  ATK_UTF8,
  ATK_NO_WWW,
  ATK_ERR_HEAD,
  ATK_OTHER
};


/*
** basic rule can have 4 (so far) kind of matching mechanisms
** RX
** STR
** LIBINJ_XSS
** LIBINJ_SQL
*/
enum DETECT_MECHANISM  {
  NONE = -1,
  RX,
  STR,
  STRFROMFILE,
  BEGINWITH,
  ENDWITH,
  LIBINJ_XSS,
  LIBINJ_SQL
};

enum MATCH_TYPE {
  URI_ONLY=0,
  NAME_ONLY,
  MIXED
};

enum DUMMY_MATCH_ZONE {
  HEADERS=0,
  URL,
  ARGS,
  ARGS_GET,
  ARGS_POST,
  BODY,
  RAW_BODY,
  FILE_EXT,
  COOKIE,
  DDOS,
  UNKNOWN,
  C_MQTT_LOGIN,
  C_MQTT_PUBLISH,
  C_MQTT_SUBSCRIBE
};


/*
** struct used to store a specific match zone
** in conf : MATCH_ZONE:[GET_VAR|HEADER|POST_VAR]:VAR_NAME:
*/
typedef struct
{
  /* match in [name] var of body */
  ngx_flag_t		body_var:1;
  /* match in [name] var of headers */
  ngx_flag_t		headers_var:1;
  /* match in [name] var of args */
  ngx_flag_t		args_var:1;
  /* match on URL [name] */
  ngx_flag_t		specific_url:1;
  ngx_str_t		target;
  /* to be used for regexed match zones */
  ngx_regex_compile_t	*target_rx;
  ngx_uint_t		hash;
  
} ngx_http_custom_rule_location_t;


/*
** WhiteList Rules Definition :
** A whitelist contains :
** - an URI
**
** - one or several sets containing :
**	- an variable name ('foo') associated with a zone ($GET_VAR:foo)
**	- one or several rules id to whitelist
*/

typedef struct
{
  /* match in full body (POST DATA) */
  ngx_flag_t		body:1;
  /* match in [name] var of body */
  ngx_flag_t		body_var:1;
  /* match in all headers */
  ngx_flag_t		headers:1;
  /* match in [name] var of headers */
  ngx_flag_t		headers_var:1;
  /* match in URI */
  ngx_flag_t		url:1;
  /* match in args (bla.php?<ARGS>) */
  ngx_flag_t		args:1;
  /* match in [name] var of args */
  ngx_flag_t		args_var:1;
  /* match on a global flag : weird_request, big_body etc. */
  ngx_flag_t		flags:1;
  /* match on file upload extension */
  ngx_flag_t		file_ext:1;
  /* set if defined "custom" match zone (GET_VAR/POST_VAR/...)  */
  ngx_array_t		*ids;
  ngx_str_t		*name;
} ngx_http_whitelist_location_t;


/* 
** this struct is used to aggregate all whitelist 
** that point to the same URI or the same VARNAME 
** all the "subrules" will then be stored in the "whitelist_locations"
*/
typedef struct
{
  /*ngx_http_whitelist_location_t **/
  ngx_array_t			*whitelist_locations; 
  /* zone to wich the WL applies */
  enum DUMMY_MATCH_ZONE		zone;
  /* if the "name" is only an url, specify it */
  int				uri_only:1;
  /* does the rule targets the name 
     instead of the content ?*/
  int				target_name;
  
  ngx_str_t			*name;
  ngx_int_t			hash;
  ngx_array_t			*ids;
} ngx_http_whitelist_rule_t;






/* basic rule */
typedef struct
{
  ngx_str_t		*str; // string
  ngx_regex_compile_t   *rx;  // or regex
  ngx_array_t	*str_file;
  /*
  ** basic rule can have 4 (so far) kind of matching mechanisms :
  ** RX, STR, LIBINJ_XSS, LIBINJ_SQL
  */
  enum DETECT_MECHANISM match_type;
  /* is the match zone a regex or a string (hashtable) */
  ngx_int_t		rx_mz; 
  /* ~~~~~ match zones ~~~~~~ */
  ngx_int_t		zone;
  /* match in full body (POST DATA) */
  ngx_flag_t		body:1;
  ngx_flag_t		raw_body:1;
  ngx_flag_t		body_var:1;
  /* match in all headers */
  ngx_flag_t		headers:1;
  ngx_flag_t		headers_var:1;
  /* match in URI */
  ngx_flag_t		url:1;
  /* match in args (bla.php?<ARGS>) */
  ngx_flag_t		args:1;
  ngx_flag_t		args_var:1;
  /* match on flags (weird_uri, big_body etc. */
  ngx_flag_t		flags:1;
  /* match on file upload extension */
  ngx_flag_t		file_ext:1;
  /* set if defined "custom" match zone (GET_VAR/POST_VAR/...)  */
  ngx_flag_t		custom_location:1;
  ngx_int_t		custom_location_only;
  /* does the rule targets variable name instead ? */
  ngx_int_t		target_name;

  ngx_int_t     cookies:1;
  ngx_int_t     user_agent:1;
  ngx_int_t     post_args:1;
  ngx_int_t     get_args:1;
  ngx_int_t     ddos:1;
  
  ngx_str_t     name;  
   
  /* custom location match zones list (GET_VAR/POST_VAR ...) */
  ngx_array_t		*custom_locations;
  /* ~~~~~~~ specific flags ~~~~~~~~~ */
  ngx_flag_t		negative:1;
} ngx_http_basic_rule_t;



/* define for RULE TYPE in rule_t */
#define BR 1 

/* flags used for 'custom match rules', like $XSS > 7 */
#define SUP 1
#define SUP_OR_EQUAL 2
#define INF 3
#define INF_OR_EQUAL 4

/*
** This struct is used to store custom scores at runtime.
**  ie : $XSS = 7
** tag is the $XSS and sc_score is 7
*/
typedef struct
{
  ngx_str_t	*sc_tag;
  ngx_int_t	sc_score;
  ngx_flag_t	block:1;
  ngx_flag_t	allow:1;
  ngx_flag_t	drop:1;
  ngx_flag_t	log:1;
} ngx_http_special_score_t;

/*
** This one is very related to the previous one,
** it's used to store a score rule comparison.
** ie : $XSS > 7
*/
typedef struct
{
  ngx_str_t	sc_tag;
  ngx_int_t	sc_score;
  ngx_int_t	cmp;
  ngx_flag_t	block:1;
  ngx_flag_t	allow:1;
  ngx_flag_t	drop:1;
  ngx_flag_t	log:1;
} ngx_http_check_rule_t;

/*DDOS && CC threshold*/
typedef struct
{
	ngx_int_t			burst_time_slice;
	ngx_int_t			counter_threshold;
	ngx_int_t			block_timeout;
}ngx_ddos_rule_t;


/* TOP level rule structure */
typedef struct
{
  /* type of the rule */
  ngx_int_t			type;
  /* simply put a flag if it's a wlr, 
     wl_id array will be used to store the whitelisted IDs */
  ngx_flag_t			whitelist:1;
  ngx_array_t			*wlid_array;
  /* "common" data for all rules */
  ngx_int_t			rule_id;
  ngx_int_t		    severity;
  ngx_str_t			*log_msg; // a specific log message
  ngx_int_t			score; //also handles DENY and ALLOW
  ngx_ddos_rule_t   ddos;
  
  /* List of scores increased on rule match. */
  ngx_array_t			*sscores;
  ngx_flag_t			sc_block:1; //
  ngx_flag_t			sc_allow:1; //
  // end of specific score tag stuff
  ngx_flag_t			block:1;
  ngx_flag_t			allow:1;
  ngx_flag_t			drop:1;
  ngx_flag_t			log:1;
  /* pointers on specific rule stuff */
  ngx_http_basic_rule_t		*br;
} ngx_http_rule_t;

typedef struct
{
  ngx_str_t 	denied_url;                     //replace 404 not found page if set drop to prevent hackers   
  ngx_str_t 	denied_url2;
  ngx_str_t 	www_dir;                        //www dir
  ngx_str_t 	rule_dir;                       //default ./rules 	
  ngx_int_t 	err_is_attack;			        //Error HTTP header or body is attack
  ngx_int_t 	request_header_limit;			//MAX HTTP header size  default is 8k
  ngx_int_t 	request_body_limit;             //MAX HTTP post body size ,default is 8k (not include file upload)
  ngx_int_t 	request_args_limit;             //MAX url args numbers (such as a=1&b=2&c=3)
  ngx_flag_t	action;             			//default is alert ,set drop to prevent hackers 
  ngx_flag_t	log;              				//default no log to file, because write file too slow if too many attacks. 
 												//Our advanced version have logcenter to process hug attack logs.

} ngx_global_var;

ngx_global_var gvar;



typedef struct
{
  ngx_array_t	*get_rules; /*ngx_http_rule_t*/
  ngx_array_t	*body_rules;
  ngx_array_t	*header_rules;
  ngx_array_t	*generic_rules; 
  ngx_array_t	*raw_body_rules;
  ngx_array_t	*cookies_rules;
  ngx_array_t	*user_agent_rules;
  ngx_array_t	*args_get_rules;
  ngx_array_t	*args_post_rules;
  ngx_array_t	*args_rules;
  ngx_array_t	*file_rules;
  ngx_array_t	*ddos_rules;

  
  ngx_array_t	*locations; /*ngx_http_dummy_loc_conf_t*/
  //ngx_log_t	*log;
  
} ngx_http_dummy_main_conf_t;


/* TOP level configuration structure */
typedef struct
{
  /*
  ** basicrule / mainrules, sorted by target zone
  */
  ngx_array_t	*get_rules;
  ngx_array_t	*body_rules;
  ngx_array_t	*raw_body_rules;
  ngx_array_t	*header_rules;
  ngx_array_t	*generic_rules;
  ngx_array_t	*check_rules;
  ngx_array_t	*cookie_rules;
  ngx_array_t	*user_agent_rules;
  /* raw array of whitelisted rules */
  ngx_array_t   *whitelist_rules;
  /* raw array of transformed whitelists */
  ngx_array_t	*tmp_wlr;
  /* raw array of regex-mz whitelists */
  ngx_array_t   *rxmz_wlr;
  /* hash table of whitelisted URL rules */
  ngx_hash_t	*wlr_url_hash;
  /* hash table of whitelisted ARGS rules */
  ngx_hash_t	*wlr_args_hash;
  /* hash table of whitelisted BODY rules */
  ngx_hash_t	*wlr_body_hash;
  /* hash table of whitelisted HEADERS rules */
  ngx_hash_t	*wlr_headers_hash;
  /* rules that are globally disabled in one location */
  ngx_array_t	*disabled_rules;
  /* counters for both processed requests and
     blocked requests, used in naxsi_fmt */
  size_t	request_processed;
  size_t	request_blocked;
  ngx_int_t	error;
  ngx_array_t	*persistant_data;
  ngx_flag_t	extensive:1;
  ngx_flag_t	learning:1;
  ngx_flag_t	enabled:1;
  ngx_flag_t	force_disabled:1;
  ngx_flag_t	pushed:1;
  ngx_flag_t	libinjection_sql_enabled:1;
  ngx_flag_t	libinjection_xss_enabled:1;
  ngx_str_t	*denied_url;
  /* precomputed hash for dynamic variable lookup, 
     variable themselves are boolean */
  ngx_uint_t	flag_enable_h;
  ngx_uint_t	flag_learning_h;
  ngx_uint_t	flag_post_action_h;
  ngx_uint_t	flag_extensive_log_h;
  /* precomputed hash for 
     libinjection dynamic flags */
  ngx_uint_t	flag_libinjection_xss_h;
  ngx_uint_t	flag_libinjection_sql_h;
  
} ngx_http_dummy_loc_conf_t;


/*
** used to store sets of matched rules during runtime
*/
typedef struct
{
  /* matched in [name] var of body */
  ngx_flag_t		body_var:1;
  /* matched in [name] var of headers */
  ngx_flag_t		headers_var:1;
  /* matched in [name] var of args */
  ngx_flag_t		args_var:1;
  /* matched on URL */
  ngx_flag_t		url:1;
  /* matched in filename [name] of args*/
  ngx_flag_t		file_ext:1;
  /* matched within the 'NAME' */
  ngx_flag_t		target_name:1;
  
  ngx_str_t		*name;
  ngx_http_rule_t	*rule;
} ngx_http_matched_rule_t;

/*
** Context structure
*/
typedef struct
{
  ngx_array_t	*special_scores;
  ngx_int_t	score;
  /* blocking flags */
  ngx_flag_t	log:1;
  ngx_flag_t	block:1;
  ngx_flag_t	allow:1;
  ngx_flag_t	drop:1;
  /* state */
  ngx_flag_t	wait_for_body:1;
  ngx_flag_t	ready:1;
  ngx_flag_t	over:1;
  /* matched rules */
  ngx_array_t	*matched;
  /* runtime flags (modifiers) */
  ngx_flag_t	learning:1;
  ngx_flag_t	enabled:1;
  ngx_flag_t	post_action:1;
  ngx_flag_t	extensive_log:1;
  /* did libinjection sql/xss matched ? */
  ngx_flag_t	libinjection_sql:1;
  ngx_flag_t	libinjection_xss:1;
} ngx_http_request_ctx_t;

/*
** this structure is used only for json parsing.

typedef struct ngx_http_nx_json_s {
  ngx_str_t	json;
  u_char	*src;
  ngx_int_t	off, len;
  u_char	c;
  int		depth;
  //ngx_http_request_t *r;
  ngx_http_request_ctx_t *ctx;
  ngx_str_t	ckey;
  ngx_http_dummy_main_conf_t	*main_cf;
  ngx_http_dummy_loc_conf_t	*loc_cf;
} ngx_json_t;

*/


#define TOP_DENIED_URL_T	"DeniedUrl"
#define TOP_LEARNING_FLAG_T	"LearningMode"
#define TOP_ENABLED_FLAG_T	"SecRulesEnabled"
#define TOP_DISABLED_FLAG_T	"SecRulesDisabled"
#define TOP_CHECK_RULE_T	"CheckRule"
#define TOP_BASIC_RULE_T	"BasicRule"
#define TOP_MAIN_BASIC_RULE_T	"MainRule"
#define TOP_LIBINJECTION_SQL_T	"LibInjectionSql"
#define TOP_LIBINJECTION_XSS_T	"LibInjectionXss"

/* nginx-style names */
#define TOP_DENIED_URL_N	"denied_url"
#define TOP_LEARNING_FLAG_N	"learning_mode"
#define TOP_ENABLED_FLAG_N	"rules_enabled"
#define TOP_DISABLED_FLAG_N	"rules_disabled"
#define TOP_CHECK_RULE_N	"check_rule"
#define TOP_BASIC_RULE_N	"basic_rule"
#define TOP_MAIN_BASIC_RULE_N	"main_rule"
#define TOP_LIBINJECTION_SQL_N	"libinjection_sql"
#define TOP_LIBINJECTION_XSS_N	"libinjection_xss"


/*possible 'tokens' in rule */
#define ID_T "id:"
#define SCORE_T "s:"
#define MSG_T "msg:"
#define RX_T "rx:"
#define STR_T "str:"
#define MATCH_ZONE_T "mz:"
#define WHITELIST_T "wl:"
#define LIBINJ_XSS_T "d:libinj_xss"
#define LIBINJ_SQL_T "d:libinj_sql"
#define NEGATIVE_T  "negative"

/* 
** name of hardcoded variables to 
** change behavior of naxsi at runtime 
*/
#define RT_EXTENSIVE_LOG "naxsi_extensive_log"
#define RT_ENABLE "naxsi_flag_enable"
#define RT_LEARNING "naxsi_flag_learning"
#define RT_POST_ACTION "naxsi_flag_post_action"
#define RT_LIBINJECTION_SQL "naxsi_flag_libinjection_sql"
#define RT_LIBINJECTION_XSS "naxsi_flag_libinjection_xss"


/*
** To avoid getting DoS'ed, define max depth
** for JSON parser, as it is recursive
*/
//#define JSON_MAX_DEPTH 10


ngx_http_rule_t *nx_int__libinject_sql; /*ID:17*/
ngx_http_rule_t *nx_int__libinject_xss; /*ID:18*/

int chk_all_rules(ngx_str_t *name,enum DUMMY_MATCH_ZONE,http_waf_msg *req);
int chk_mqtt_rules(ngx_str_t *name, enum DUMMY_MATCH_ZONE	zone,mqtt_waf_msg *req);

void init_rules();



#endif
