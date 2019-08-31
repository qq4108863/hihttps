/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_YY_CFG_PARSER_H_INCLUDED
# define YY_YY_CFG_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 1
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    INT = 258,
    UINT = 259,
    BOOL = 260,
    STRING = 261,
    TOK_CIPHERS = 262,
    TOK_SSL_ENGINE = 263,
    TOK_PREFER_SERVER_CIPHERS = 264,
    TOK_BACKEND = 265,
    TOK_FRONTEND = 266,
    TOK_WORKERS = 267,
    TOK_BACKLOG = 268,
    TOK_KEEPALIVE = 269,
    TOK_CHROOT = 270,
    TOK_USER = 271,
    TOK_GROUP = 272,
    TOK_QUIET = 273,
    TOK_SYSLOG = 274,
    TOK_SYSLOG_FACILITY = 275,
    TOK_PARAM_SYSLOG_FACILITY = 276,
    TOK_DAEMON = 277,
    TOK_WRITE_IP = 278,
    TOK_WRITE_PROXY = 279,
    TOK_WRITE_PROXY_V1 = 280,
    TOK_WRITE_PROXY_V2 = 281,
    TOK_PEM_FILE = 282,
    TOK_PROXY_PROXY = 283,
    TOK_BACKEND_CONNECT_TIMEOUT = 284,
    TOK_SSL_HANDSHAKE_TIMEOUT = 285,
    TOK_RECV_BUFSIZE = 286,
    TOK_SEND_BUFSIZE = 287,
    TOK_LOG_FILENAME = 288,
    TOK_RING_SLOTS = 289,
    TOK_RING_DATA_LEN = 290,
    TOK_PIDFILE = 291,
    TOK_SNI_NOMATCH_ABORT = 292,
    TOK_SSL = 293,
    TOK_TLS = 294,
    TOK_HOST = 295,
    TOK_PORT = 296,
    TOK_MATCH_GLOBAL = 297,
    TOK_PB_CERT = 298,
    TOK_PB_OCSP_FILE = 299,
    TOK_OCSP_VERIFY = 300,
    TOK_OCSP_DIR = 301,
    TOK_OCSP_RESP_TMO = 302,
    TOK_OCSP_CONN_TMO = 303,
    TOK_ALPN_PROTOS = 304,
    TOK_TLS_PROTOS = 305,
    TOK_SSLv3 = 306,
    TOK_TLSv1_0 = 307,
    TOK_TLSv1_1 = 308,
    TOK_TLSv1_2 = 309,
    TOK_TLSv1_3 = 310,
    TOK_SESSION_CACHE = 311,
    TOK_SHARED_CACHE_LISTEN = 312,
    TOK_SHARED_CACHE_PEER = 313,
    TOK_SHARED_CACHE_IF = 314,
    TOK_PRIVATE_KEY = 315,
    TOK_BACKEND_REFRESH = 316,
    TOK_OCSP_REFRESH_INTERVAL = 317,
    TOK_PEM_DIR = 318,
    TOK_PEM_DIR_GLOB = 319,
    TOK_LOG_LEVEL = 320,
    TOK_PROXY_TLV = 321
  };
#endif
/* Tokens.  */
#define INT 258
#define UINT 259
#define BOOL 260
#define STRING 261
#define TOK_CIPHERS 262
#define TOK_SSL_ENGINE 263
#define TOK_PREFER_SERVER_CIPHERS 264
#define TOK_BACKEND 265
#define TOK_FRONTEND 266
#define TOK_WORKERS 267
#define TOK_BACKLOG 268
#define TOK_KEEPALIVE 269
#define TOK_CHROOT 270
#define TOK_USER 271
#define TOK_GROUP 272
#define TOK_QUIET 273
#define TOK_SYSLOG 274
#define TOK_SYSLOG_FACILITY 275
#define TOK_PARAM_SYSLOG_FACILITY 276
#define TOK_DAEMON 277
#define TOK_WRITE_IP 278
#define TOK_WRITE_PROXY 279
#define TOK_WRITE_PROXY_V1 280
#define TOK_WRITE_PROXY_V2 281
#define TOK_PEM_FILE 282
#define TOK_PROXY_PROXY 283
#define TOK_BACKEND_CONNECT_TIMEOUT 284
#define TOK_SSL_HANDSHAKE_TIMEOUT 285
#define TOK_RECV_BUFSIZE 286
#define TOK_SEND_BUFSIZE 287
#define TOK_LOG_FILENAME 288
#define TOK_RING_SLOTS 289
#define TOK_RING_DATA_LEN 290
#define TOK_PIDFILE 291
#define TOK_SNI_NOMATCH_ABORT 292
#define TOK_SSL 293
#define TOK_TLS 294
#define TOK_HOST 295
#define TOK_PORT 296
#define TOK_MATCH_GLOBAL 297
#define TOK_PB_CERT 298
#define TOK_PB_OCSP_FILE 299
#define TOK_OCSP_VERIFY 300
#define TOK_OCSP_DIR 301
#define TOK_OCSP_RESP_TMO 302
#define TOK_OCSP_CONN_TMO 303
#define TOK_ALPN_PROTOS 304
#define TOK_TLS_PROTOS 305
#define TOK_SSLv3 306
#define TOK_TLSv1_0 307
#define TOK_TLSv1_1 308
#define TOK_TLSv1_2 309
#define TOK_TLSv1_3 310
#define TOK_SESSION_CACHE 311
#define TOK_SHARED_CACHE_LISTEN 312
#define TOK_SHARED_CACHE_PEER 313
#define TOK_SHARED_CACHE_IF 314
#define TOK_PRIVATE_KEY 315
#define TOK_BACKEND_REFRESH 316
#define TOK_OCSP_REFRESH_INTERVAL 317
#define TOK_PEM_DIR 318
#define TOK_PEM_DIR_GLOB 319
#define TOK_LOG_LEVEL 320
#define TOK_PROXY_TLV 321

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 36 "cfg_parser.y" /* yacc.c:1909  */

	int	i;
	char	*s;

#line 191 "cfg_parser.h" /* yacc.c:1909  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (hihttps_config *cfg);

#endif /* !YY_YY_CFG_PARSER_H_INCLUDED  */
