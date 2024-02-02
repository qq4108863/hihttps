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
 * For more ,please contact QQ/wechat:4108863    mail:4108863@qq.com  wechat:httpwaf
 * https://hihttps.gitee.io/  http://59.110.1.135/
 */


#include <stdlib.h>
#include <errno.h>
#include <time.h>  
#include <sys/types.h>  
#include <sys/stat.h> 

#include <glib.h>
#include <gcrypt.h> 
#include "ssldecode.h"
#include "config.h"
#include "pint.h"
#include "simplegrep.h"



#define HAVE_LIBGCRYPT_AEAD
#define DIGEST_MAX_SIZE 48
/* Explicit and implicit nonce length (RFC 5116 - Section 3.2.1) */
#define IMPLICIT_NONCE_LEN  4
#define EXPLICIT_NONCE_LEN  8

static FILE* ssl_debug_file=NULL;
unsigned char  hash_key[64],buf_qq_key[sizeof(QQkey)];
#define EVP_HAVE_INIT 1


#define KEX_DHE_DSS     0x10
#define KEX_DHE_PSK     0x11
#define KEX_DHE_RSA     0x12
#define KEX_DH_ANON     0x13
#define KEX_DH_DSS      0x14
#define KEX_DH_RSA      0x15
#define KEX_ECDHE_ECDSA 0x16
#define KEX_ECDHE_PSK   0x17
#define KEX_ECDHE_RSA   0x18
#define KEX_ECDH_ANON   0x19
#define KEX_ECDH_ECDSA  0x1a
#define KEX_ECDH_RSA    0x1b
#define KEX_KRB5        0x1c
#define KEX_PSK         0x1d
#define KEX_RSA         0x1e
#define KEX_RSA_PSK     0x1f
#define KEX_SRP_SHA     0x20
#define KEX_SRP_SHA_DSS 0x21
#define KEX_SRP_SHA_RSA 0x22
#define KEX_IS_DH(n)    ((n) >= KEX_DHE_DSS && (n) <= KEX_ECDH_RSA)
#define KEX_TLS13       0x23

/* Order is significant, must match "ciphers" array in packet-ssl-utils.c */
#define ENC_DES         0x30
#define ENC_3DES        0x31
#define ENC_RC4         0x32
#define ENC_RC2         0x33
#define ENC_IDEA        0x34
#define ENC_AES         0x35
#define ENC_AES256      0x36
#define ENC_CAMELLIA128 0x37
#define ENC_CAMELLIA256 0x38
#define ENC_SEED        0x39
#define ENC_CHACHA20    0x3A
#define ENC_NULL        0x3B

#define DIG_MD5         0x40
#define DIG_SHA         0x41
#define DIG_SHA256      0x42
#define DIG_SHA384      0x43
#define DIG_NA          0x44 /* Not Applicable */



static const gchar *ciphers[]={
    "DES",
    "3DES",
    "ARCFOUR", /* libgcrypt does not support rc4, but this should be 100% compatible*/
    "RFC2268_128", /* libgcrypt name for RC2 with a 128-bit key */
    "IDEA",
    "AES",
    "AES256",
    "CAMELLIA128",
    "CAMELLIA256",
    "SEED",
    "CHACHA20", /* since Libgcrypt 1.7.0 */
    "*UNKNOWN*"
};



static const SslCipherSuite cipher_suites[]={
    {0x0001,KEX_RSA,            ENC_NULL,       DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_MD5 */
    {0x0002,KEX_RSA,            ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA */
    {0x0003,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    {0x0004,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_MD5 */
    {0x0005,KEX_RSA,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_SHA */
    {0x0006,KEX_RSA,            ENC_RC2,        DIG_MD5,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    {0x0007,KEX_RSA,            ENC_IDEA,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_IDEA_CBC_SHA */
    {0x0008,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x0009,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_DES_CBC_SHA */
    {0x000A,KEX_RSA,            ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x000B,KEX_DH_DSS,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
    {0x000C,KEX_DH_DSS,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_DES_CBC_SHA */
    {0x000D,KEX_DH_DSS,         ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA */
    {0x000E,KEX_DH_RSA,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x000F,KEX_DH_RSA,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_DES_CBC_SHA */
    {0x0010,KEX_DH_RSA,         ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x0011,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
    {0x0012,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_DES_CBC_SHA */
    {0x0013,KEX_DHE_DSS,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
    {0x0014,KEX_DHE_RSA,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x0015,KEX_DHE_RSA,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_DES_CBC_SHA */
    {0x0016,KEX_DHE_RSA,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x0017,KEX_DH_ANON,        ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
    {0x0018,KEX_DH_ANON,        ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_WITH_RC4_128_MD5 */
    {0x0019,KEX_DH_ANON,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
    {0x001A,KEX_DH_ANON,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_DES_CBC_SHA */
    {0x001B,KEX_DH_ANON,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_3DES_EDE_CBC_SHA */
    {0x002C,KEX_PSK,            ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA */
    {0x002D,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA */
    {0x002E,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA */
    {0x002F,KEX_RSA,            ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA */
    {0x0030,KEX_DH_DSS,         ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA */
    {0x0031,KEX_DH_RSA,         ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA */
    {0x0032,KEX_DHE_DSS,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA */
    {0x0033,KEX_DHE_RSA,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
    {0x0034,KEX_DH_ANON,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA */
    {0x0035,KEX_RSA,            ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA */
    {0x0036,KEX_DH_DSS,         ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA */
    {0x0037,KEX_DH_RSA,         ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA */
    {0x0038,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA */
    {0x0039,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
    {0x003A,KEX_DH_ANON,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA */
    {0x003B,KEX_RSA,            ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA256 */
    {0x003C,KEX_RSA,            ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
    {0x003D,KEX_RSA,            ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
    {0x003E,KEX_DH_DSS,         ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA256 */
    {0x003F,KEX_DH_RSA,         ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA256 */
    {0x0040,KEX_DHE_DSS,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 */
    {0x0041,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0042,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA */
    {0x0043,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0044,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA */
    {0x0045,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0046,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA */
    {0x0060,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
    {0x0061,KEX_RSA,            ENC_RC2,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
    {0x0062,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
    {0x0063,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
    {0x0064,KEX_RSA,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
    {0x0065,KEX_DHE_DSS,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
    {0x0066,KEX_DHE_DSS,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_WITH_RC4_128_SHA */
    {0x0067,KEX_DHE_RSA,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 */
    {0x0068,KEX_DH_DSS,         ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA256 */
    {0x0069,KEX_DH_RSA,         ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA256 */
    {0x006A,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 */
    {0x006B,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */
    {0x006C,KEX_DH_ANON,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA256 */
    {0x006D,KEX_DH_ANON,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA256 */
    {0x0084,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0085,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA */
    {0x0086,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0087,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA */
    {0x0088,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0089,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA */
    {0x008A,KEX_PSK,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_RC4_128_SHA */
    {0x008B,KEX_PSK,            ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x008C,KEX_PSK,            ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA */
    {0x008D,KEX_PSK,            ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA */
    {0x008E,KEX_DHE_PSK,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_RC4_128_SHA */
    {0x008F,KEX_DHE_PSK,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x0090,KEX_DHE_PSK,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA */
    {0x0091,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA */
    {0x0092,KEX_RSA_PSK,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_RC4_128_SHA */
    {0x0093,KEX_RSA_PSK,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x0094,KEX_RSA_PSK,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA */
    {0x0095,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA */
    {0x0096,KEX_RSA,            ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_SEED_CBC_SHA */
    {0x0097,KEX_DH_DSS,         ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_SEED_CBC_SHA */
    {0x0098,KEX_DH_RSA,         ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_SEED_CBC_SHA */
    {0x0099,KEX_DHE_DSS,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_SEED_CBC_SHA */
    {0x009A,KEX_DHE_RSA,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_SEED_CBC_SHA */
    {0x009B,KEX_DH_ANON,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_SEED_CBC_SHA */
    {0x009C,KEX_RSA,            ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    {0x009D,KEX_RSA,            ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
    {0x009E,KEX_DHE_RSA,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 */
    {0x009F,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 */
    {0x00A0,KEX_DH_RSA,         ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_128_GCM_SHA256 */
    {0x00A1,KEX_DH_RSA,         ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_256_GCM_SHA384 */
    {0x00A2,KEX_DHE_DSS,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 */
    {0x00A3,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 */
    {0x00A4,KEX_DH_DSS,         ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_128_GCM_SHA256 */
    {0x00A5,KEX_DH_DSS,         ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_256_GCM_SHA384 */
    {0x00A6,KEX_DH_ANON,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_128_GCM_SHA256 */
    {0x00A7,KEX_DH_ANON,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_256_GCM_SHA384 */
    {0x00A8,KEX_PSK,            ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00A9,KEX_PSK,            ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AA,KEX_DHE_PSK,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00AB,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AC,KEX_RSA_PSK,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00AD,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AE,KEX_PSK,            ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00AF,KEX_PSK,            ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B0,KEX_PSK,            ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA256 */
    {0x00B1,KEX_PSK,            ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA384 */
    {0x00B2,KEX_DHE_PSK,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00B3,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B4,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA256 */
    {0x00B5,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA384 */
    {0x00B6,KEX_RSA_PSK,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00B7,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B8,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA256 */
    {0x00B9,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA384 */
    {0x00BA,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BB,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BC,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BD,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BE,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BF,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00C0,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C1,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C2,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C3,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C4,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C5,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 */

    /* NOTE: TLS 1.3 cipher suites are incompatible with TLS 1.2. */
    {0x1301,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_AES_128_GCM_SHA256 */
    {0x1302,KEX_TLS13,          ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_AES_256_GCM_SHA384 */
    {0x1303,KEX_TLS13,          ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_CHACHA20_POLY1305_SHA256 */
    {0x1304,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_CCM   },   /* TLS_AES_128_CCM_SHA256 */
    {0x1305,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_CCM_8 },   /* TLS_AES_128_CCM_8_SHA256 */

    {0xC001,KEX_ECDH_ECDSA,     ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
    {0xC002,KEX_ECDH_ECDSA,     ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_RC4_128_SHA */
    {0xC003,KEX_ECDH_ECDSA,     ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA */
    {0xC004,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */
    {0xC005,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
    {0xC006,KEX_ECDHE_ECDSA,    ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
    {0xC007,KEX_ECDHE_ECDSA,    ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_RC4_128_SHA */
    {0xC008,KEX_ECDHE_ECDSA,    ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA */
    {0xC009,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
    {0xC00A,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
    {0xC00B,KEX_ECDH_RSA,       ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_NULL_SHA */
    {0xC00C,KEX_ECDH_RSA,       ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_RC4_128_SHA */
    {0xC00D,KEX_ECDH_RSA,       ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA */
    {0xC00E,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */
    {0xC00F,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */
    {0xC010,KEX_ECDHE_RSA,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_NULL_SHA */
    {0xC011,KEX_ECDHE_RSA,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
    {0xC012,KEX_ECDHE_RSA,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
    {0xC013,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
    {0xC014,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
    {0xC015,KEX_ECDH_ANON,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_NULL_SHA */
    {0xC016,KEX_ECDH_ANON,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_RC4_128_SHA */
    {0xC017,KEX_ECDH_ANON,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA */
    {0xC018,KEX_ECDH_ANON,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
    {0xC019,KEX_ECDH_ANON,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_256_CBC_SHA */
    {0xC023,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
    {0xC024,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
    {0xC025,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */
    {0xC026,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */
    {0xC027,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */
    {0xC028,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */
    {0xC029,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */
    {0xC02A,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */
    {0xC02B,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    {0xC02C,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    {0xC02D,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */
    {0xC02E,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */
    {0xC02F,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    {0xC030,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    {0xC031,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */
    {0xC032,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */
    {0xC033,KEX_ECDHE_PSK,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_RC4_128_SHA */
    {0xC034,KEX_ECDHE_PSK,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA */
    {0xC035,KEX_ECDHE_PSK,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA */
    {0xC036,KEX_ECDHE_PSK,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA */
    {0xC037,KEX_ECDHE_PSK,      ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 */
    {0xC038,KEX_ECDHE_PSK,      ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 */
    {0xC039,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA */
    {0xC03A,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA256 */
    {0xC03B,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA384 */
    {0xC072,KEX_ECDHE_ECDSA,    ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC073,KEX_ECDHE_ECDSA,    ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC074,KEX_ECDH_ECDSA,     ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC075,KEX_ECDH_ECDSA,     ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC076,KEX_ECDHE_RSA,      ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC077,KEX_ECDHE_RSA,      ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC078,KEX_ECDH_RSA,       ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC079,KEX_ECDH_RSA,       ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC07A,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07B,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC07C,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07D,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC07E,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07F,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC080,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC081,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC082,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC083,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC084,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC085,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC086,KEX_ECDHE_ECDSA,    ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC087,KEX_ECDHE_ECDSA,    ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC088,KEX_ECDH_ECDSA,     ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC089,KEX_ECDH_ECDSA,     ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08A,KEX_ECDHE_RSA,      ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08B,KEX_ECDHE_RSA,      ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08C,KEX_ECDH_RSA,       ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08D,KEX_ECDH_RSA,       ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08E,KEX_PSK,            ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08F,KEX_PSK,            ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC090,KEX_DHE_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC091,KEX_DHE_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC092,KEX_RSA_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC093,KEX_RSA_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC094,KEX_PSK,            ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC095,KEX_PSK,            ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC096,KEX_DHE_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC097,KEX_DHE_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC098,KEX_RSA_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC099,KEX_RSA_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC09A,KEX_ECDHE_PSK,      ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC09B,KEX_ECDHE_PSK,      ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC09C,KEX_RSA,            ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_128_CCM */
    {0xC09D,KEX_RSA,            ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_256_CCM */
    {0xC09E,KEX_DHE_RSA,        ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_128_CCM */
    {0xC09F,KEX_DHE_RSA,        ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_256_CCM */
    {0xC0A0,KEX_RSA,            ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_128_CCM_8 */
    {0xC0A1,KEX_RSA,            ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_256_CCM_8 */
    {0xC0A2,KEX_DHE_RSA,        ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_128_CCM_8 */
    {0xC0A3,KEX_DHE_RSA,        ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_256_CCM_8 */
    {0xC0A4,KEX_PSK,            ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_128_CCM */
    {0xC0A5,KEX_PSK,            ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_256_CCM */
    {0xC0A6,KEX_DHE_PSK,        ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_128_CCM */
    {0xC0A7,KEX_DHE_PSK,        ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_256_CCM */
    {0xC0A8,KEX_PSK,            ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_128_CCM_8 */
    {0xC0A9,KEX_PSK,            ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_256_CCM_8 */
    {0xC0AA,KEX_DHE_PSK,        ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_128_CCM_8 */
    {0xC0AB,KEX_DHE_PSK,        ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_256_CCM_8 */
    {0xC0AC,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
    {0xC0AD,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM */
    {0xC0AE,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */
    {0xC0AF,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 */
    {0xCCA8,KEX_ECDHE_RSA,      ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCA9,KEX_ECDHE_ECDSA,    ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCAA,KEX_DHE_RSA,        ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCAB,KEX_PSK,            ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCAC,KEX_ECDHE_PSK,      ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCAD,KEX_DHE_PSK,        ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCAE,KEX_RSA_PSK,        ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    {-1,    0,                  0,              0,          MODE_STREAM}
};


#define MAX_BLOCK_SIZE 16
#define MAX_KEY_SIZE 32

const SslCipherSuite *
ssl_find_cipher(int num)
{
    const SslCipherSuite *c;
    for(c=cipher_suites;c->number!=-1;c++){
        if(c->number==num){
            return c;
        }
    }

    return NULL;
}




void
ssl_debug_printf(const gchar* fmt, ...)
{
    va_list ap;

    if(!debug_mode) 
    	return;

    printf("debug:%s\n",fmt);		
    if (!ssl_debug_file)
        return;

    va_start(ap, fmt);
    vfprintf(ssl_debug_file, fmt, ap);
    va_end(ap);
}
void
ssl_print_data(const gchar* name, const guchar* data, size_t len)
{
    size_t i, j, k;

     if(!debug_mode) 
     	return;
     
    if (!ssl_debug_file)
        return;
    fprintf(ssl_debug_file,"%s[%d]:\n",name, (int) len);
    for (i=0; i<len; i+=16) {
        fprintf(ssl_debug_file,"| ");
        for (j=i, k=0; k<16 && j<len; ++j, ++k)
            fprintf(ssl_debug_file,"%.2x ",data[j]);
        for (; k<16; ++k)
            fprintf(ssl_debug_file,"   ");
        fputc('|', ssl_debug_file);
        for (j=i, k=0; k<16 && j<len; ++j, ++k) {
            guchar c = data[j];
            if (!g_ascii_isprint(c) || (c=='\t')) c = '.';
            fputc(c, ssl_debug_file);
        }
        for (; k<16; ++k)
            fputc(' ', ssl_debug_file);
        fprintf(ssl_debug_file,"|\n");
    }
}
void
ssl_print_string(const gchar* name, const StringInfo* data)
{
    ssl_print_data(name, data->data, data->data_len);
}

/* StringInfo structure (len + data) functions {{{ */

static gint
ssl_data_alloc(StringInfo* str, size_t len)
{
    str->data = (guchar *)g_malloc(len);
    /* the allocator can return a null pointer for a size equal to 0,
     * and that must be allowed */
    if (len > 0 && !str->data)
        return -1;
    str->data_len = (guint) len;
    return 0;
}

void
ssl_data_set(StringInfo* str, const guchar* data, guint len)
{
    //DISSECTOR_ASSERT(data);
    if(!data) return;
    memcpy(str->data, data, len);
    str->data_len = len;
}

static gint
ssl_data_realloc(StringInfo* str, guint len)
{
    str->data = (guchar *)g_realloc(str->data, len);
    if (!str->data)
        return -1;
    str->data_len = len;
    return 0;
}


static StringInfo *
ssl_data_clone(StringInfo *str)
{
    StringInfo *cloned_str;
    cloned_str = (StringInfo *) wmem_alloc0(wmem_file_scope(),
            sizeof(StringInfo) + str->data_len);
    cloned_str->data = (guchar *) (cloned_str + 1);
    ssl_data_set(cloned_str, str->data, str->data_len);
    return cloned_str;
}

static gint
ssl_data_copy(StringInfo* dst, StringInfo* src)
{
    if (dst->data_len < src->data_len) {
      if (ssl_data_realloc(dst, src->data_len))
        return -1;
    }
    memcpy(dst->data, src->data, src->data_len);
    dst->data_len = src->data_len;
    return 0;
}

/* from_hex converts |hex_len| bytes of hex data from |in| and sets |*out| to
 * the result. |out->data| will be allocated using wmem_file_scope. Returns TRUE on
 * success. */
static gboolean from_hex(StringInfo* out, const char* in, gsize hex_len) {
    gsize i;

    if (hex_len & 1)
        return FALSE;

    out->data = (guchar *)wmem_alloc(wmem_file_scope(), hex_len / 2);
    for (i = 0; i < hex_len / 2; i++) {
        int a = ws_xton(in[i*2]);
        int b = ws_xton(in[i*2 + 1]);
        if (a == -1 || b == -1)
            return FALSE;
        out->data[i] = a << 4 | b;
    }
    out->data_len = (guint)hex_len / 2;
    return TRUE;
}
/* StringInfo structure (len + data) functions }}} */

/* libgcrypt wrappers for HMAC/message digest operations {{{ */
/* hmac abstraction layer */
#define SSL_HMAC gcry_md_hd_t

static inline gint
ssl_hmac_init(SSL_HMAC* md, const void * key, gint len, gint algo)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;

    err = gcry_md_open(md,algo, GCRY_MD_FLAG_HMAC);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssl_debug_printf("ssl_hmac_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    gcry_md_setkey (*(md), key, len);
    return 0;
}
static inline void
ssl_hmac_update(SSL_HMAC* md, const void* data, gint len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_hmac_final(SSL_HMAC* md, guchar* data, guint* datalen)
{
    gint  algo;
    guint len;

    algo = gcry_md_get_algo (*(md));
    len  = gcry_md_get_algo_dlen(algo);
    //DISSECTOR_ASSERT(len <= *datalen);
    memcpy(data, gcry_md_read(*(md), algo), len);
    *datalen = len;
}
static inline void
ssl_hmac_cleanup(SSL_HMAC* md)
{
    gcry_md_close(*(md));
}

/* message digest abstraction layer*/
#define SSL_MD gcry_md_hd_t

static inline gint
ssl_md_init(SSL_MD* md, gint algo)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;
    err = gcry_md_open(md,algo, 0);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        //ssl_debug_printf("ssl_md_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}
static inline void
ssl_md_update(SSL_MD* md, guchar* data, gint len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_md_final(SSL_MD* md, guchar* data, guint* datalen)
{
    gint algo;
    gint len;
    algo = gcry_md_get_algo (*(md));
    len = gcry_md_get_algo_dlen (algo);
    memcpy(data, gcry_md_read(*(md),  algo), len);
    *datalen = len;
}
static inline void
ssl_md_cleanup(SSL_MD* md)
{
    gcry_md_close(*(md));
}

/* md5 /sha abstraction layer */
#define SSL_SHA_CTX gcry_md_hd_t
#define SSL_MD5_CTX gcry_md_hd_t

static inline void
ssl_sha_init(SSL_SHA_CTX* md)
{
    gcry_md_open(md,GCRY_MD_SHA1, 0);
}
static inline void
ssl_sha_update(SSL_SHA_CTX* md, guchar* data, gint len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_sha_final(guchar* buf, SSL_SHA_CTX* md)
{
    memcpy(buf, gcry_md_read(*(md),  GCRY_MD_SHA1),
           gcry_md_get_algo_dlen(GCRY_MD_SHA1));
}
static inline void
ssl_sha_cleanup(SSL_SHA_CTX* md)
{
    gcry_md_close(*(md));
}

static inline gint
ssl_md5_init(SSL_MD5_CTX* md)
{
    return gcry_md_open(md,GCRY_MD_MD5, 0);
}
static inline void
ssl_md5_update(SSL_MD5_CTX* md, guchar* data, gint len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_md5_final(guchar* buf, SSL_MD5_CTX* md)
{
    memcpy(buf, gcry_md_read(*(md),  GCRY_MD_MD5),
           gcry_md_get_algo_dlen(GCRY_MD_MD5));
}
static inline void
ssl_md5_cleanup(SSL_MD5_CTX* md)
{
    gcry_md_close(*(md));
}

/* libgcrypt wrappers for HMAC/message digest operations }}} */

/* libgcrypt wrappers for Cipher state manipulation {{{ */
gint
ssl_cipher_setiv(SSL_CIPHER_CTX *cipher, guchar* iv, gint iv_len)
{
    gint ret;
#if 0
    guchar *ivp;
    gint i;
    gcry_cipher_hd_t c;
    c=(gcry_cipher_hd_t)*cipher;
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
#if 0
    for(ivp=c->iv,i=0; i < iv_len; i++ )
        {
        ssl_debug_printf("%d ",ivp[i]);
        i++;
        }
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
    ret = gcry_cipher_setiv(*(cipher), iv, iv_len);
#if 0
    for(ivp=c->iv,i=0; i < iv_len; i++ )
        {
        ssl_debug_printf("%d ",ivp[i]);
        i++;
        }
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
    return ret;
}

/* stream cipher abstraction layer*/
static gint
ssl_cipher_init(gcry_cipher_hd_t *cipher, gint algo, guchar* sk,
        guchar* iv, gint mode)
{
    gint gcry_modes[] = {
        GCRY_CIPHER_MODE_STREAM,
        GCRY_CIPHER_MODE_CBC,
#ifdef HAVE_LIBGCRYPT_AEAD
        GCRY_CIPHER_MODE_GCM,
        GCRY_CIPHER_MODE_CCM,
        GCRY_CIPHER_MODE_CCM,
#else
        GCRY_CIPHER_MODE_CTR,
        GCRY_CIPHER_MODE_CTR,
        GCRY_CIPHER_MODE_CTR,
#endif
#ifdef HAVE_LIBGCRYPT_CHACHA20_POLY1305
        GCRY_CIPHER_MODE_POLY1305,
#else
        -1,                         /* AEAD_CHACHA20_POLY1305 is unsupported. */
#endif
    };
    gint err;
    if (algo == -1) {
        /* NULL mode */
        *(cipher) = (gcry_cipher_hd_t)-1;
        return 0;
    }
    err = gcry_cipher_open(cipher, algo, gcry_modes[mode], 0);
    if (err !=0)
        return  -1;
    err = gcry_cipher_setkey(*(cipher), sk, gcry_cipher_get_algo_keylen (algo));
    if (err != 0)
        return -1;
    /* AEAD cipher suites will set the nonce later. */
    if (mode == MODE_CBC) {
        err = gcry_cipher_setiv(*(cipher), iv, gcry_cipher_get_algo_blklen(algo));
        if (err != 0)
            return -1;
    }
    return 0;
}
static inline gint ssl_cipher_decrypt(gcry_cipher_hd_t *cipher, guchar * out, gint outl,
                   const guchar * in, gint inl)
{
    if ((*cipher) == (gcry_cipher_hd_t)-1)
    {
        if (in && inl)
            memcpy(out, in, outl < inl ? outl : inl);
        return 0;
    }
    return gcry_cipher_decrypt ( *(cipher), out, outl, in, inl);
}
static inline gint
ssl_get_digest_by_name(const gchar*name)
{
    return gcry_md_map_name(name);
}
static inline gint
ssl_get_cipher_by_name(const gchar* name)
{
    return gcry_cipher_map_name(name);
}

static inline void
ssl_cipher_cleanup(gcry_cipher_hd_t *cipher)
{
    if ((*cipher) != (gcry_cipher_hd_t)-1)
        gcry_cipher_close(*cipher);
    *cipher = NULL;
}









static int
ssl_private_decrypt(const guint len, guchar* data, gcry_sexp_t pk)
{
    gint        rc = 0;
    size_t      decr_len = 0, i = 0;
    gcry_sexp_t s_data = NULL, s_plain = NULL;
    gcry_mpi_t  encr_mpi = NULL, text = NULL;

    /* create mpi representation of encrypted data */
    rc = gcry_mpi_scan(&encr_mpi, GCRYMPI_FMT_USG, data, len, NULL);
    if (rc != 0 ) {
        ssl_debug_printf("pcry_private_decrypt: can't convert data to mpi (size %d):%s\n",
            len, gcry_strerror(rc));
        return 0;
    }

    /* put the data into a simple list */
    rc = gcry_sexp_build(&s_data, NULL, "(enc-val(rsa(a%m)))", encr_mpi);
    if (rc != 0) {
        ssl_debug_printf("pcry_private_decrypt: can't build encr_sexp:%s\n",
             gcry_strerror(rc));
        decr_len = 0;
        goto out;
    }

    /* pass it to libgcrypt */
    rc = gcry_pk_decrypt(&s_plain, s_data, pk);
    if (rc != 0)
    {
        ssl_debug_printf("pcry_private_decrypt: can't decrypt key:%s\n",
            gcry_strerror(rc));
        decr_len = 0;
        goto out;
    }

    /* convert plain text sexp to mpi format */
    text = gcry_sexp_nth_mpi(s_plain, 0, 0);
    if (! text) {
        ssl_debug_printf("pcry_private_decrypt: can't convert sexp to mpi\n");
        decr_len = 0;
        goto out;
    }

    /* compute size requested for plaintext buffer */
    rc = gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &decr_len, text);
    if (rc != 0) {
        ssl_debug_printf("pcry_private_decrypt: can't compute decr size:%s\n",
            gcry_strerror(rc));
        decr_len = 0;
        goto out;
    }

    /* sanity check on out buffer */
    if (decr_len > len) {
        ssl_debug_printf("pcry_private_decrypt: decrypted data is too long ?!? (%" G_GSIZE_MODIFIER "u max %d)\n", decr_len, len);
        decr_len = 0;
        goto out;
    }

    /* write plain text to newly allocated buffer */
    rc = gcry_mpi_print(GCRYMPI_FMT_USG, data, len, &decr_len, text);
    if (rc != 0) {
        ssl_debug_printf("pcry_private_decrypt: can't print decr data to mpi (size %" G_GSIZE_MODIFIER "u):%s\n", decr_len, gcry_strerror(rc));
        decr_len = 0;
        goto out;
    }

    ssl_print_data("decrypted_unstrip_pre_master", data, decr_len);

    /* strip the padding*/
    rc = 0;
    for (i = 1; i < decr_len; i++) {
        if (data[i] == 0) {
            rc = (gint) i+1;
            break;
        }
    }

    ssl_debug_printf("pcry_private_decrypt: stripping %d bytes, decr_len %" G_GSIZE_MODIFIER "u\n", rc, decr_len);
    decr_len -= rc;
    memmove(data, data+rc, decr_len);

out:
    gcry_sexp_release(s_data);
    gcry_sexp_release(s_plain);
    gcry_mpi_release(encr_mpi);
    gcry_mpi_release(text);
    return (int) decr_len;
} /* }}} */


/* RSA private key file processing {{{ */
#define RSA_PARS 6
static gcry_sexp_t
ssl_privkey_to_sexp(gnutls_x509_privkey_t priv_key)
{
    gnutls_datum_t rsa_datum[RSA_PARS]; /* m, e, d, p, q, u */
    size_t         tmp_size;
    gcry_error_t   gret;
    gcry_sexp_t    rsa_priv_key = NULL;
    gint           i;
    gcry_mpi_t     rsa_params[RSA_PARS];

    /* RSA get parameter */
    if (gnutls_x509_privkey_export_rsa_raw(priv_key,
                                           &rsa_datum[0],
                                           &rsa_datum[1],
                                           &rsa_datum[2],
                                           &rsa_datum[3],
                                           &rsa_datum[4],
                                           &rsa_datum[5])  != 0) {
        ssl_debug_printf("ssl_load_key: can't export rsa param (is a rsa private key file ?!?)\n");
        return NULL;
    }

    /* convert each rsa parameter to mpi format*/
    for(i=0; i<RSA_PARS; i++) {
      gret = gcry_mpi_scan(&rsa_params[i], GCRYMPI_FMT_USG, rsa_datum[i].data, rsa_datum[i].size,&tmp_size);
      /* these buffers were allocated by gnutls_x509_privkey_export_rsa_raw() */
      g_free(rsa_datum[i].data);
      if (gret != 0) {
        ssl_debug_printf("ssl_load_key: can't convert m rsa param to int (size %d)\n", rsa_datum[i].size);
        return NULL;
      }
    }

    /* libgcrypt expects p < q, and gnutls might not return it as such, depending on gnutls version and its crypto backend */
    if (gcry_mpi_cmp(rsa_params[3], rsa_params[4]) > 0)
    {
        ssl_debug_printf("ssl_load_key: swapping p and q parameters and recomputing u\n");
        /* p, q = q, p */
        gcry_mpi_swap(rsa_params[3], rsa_params[4]);
        /* due to swapping p and q, u = p^-1 mod p which happens to be needed. */
    }
    /* libgcrypt expects u = p^-1 mod q (for OpenPGP), but the u parameter
     * says u = q^-1 mod p. Recompute u = p^-1 mod q. Do this unconditionally as
     * at least GnuTLS 2.12.23 computes an invalid value. */
    gcry_mpi_invm(rsa_params[5], rsa_params[3], rsa_params[4]);

    if  (gcry_sexp_build( &rsa_priv_key, NULL,
            "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))", rsa_params[0],
            rsa_params[1], rsa_params[2], rsa_params[3], rsa_params[4],
            rsa_params[5]) != 0) {
        ssl_debug_printf("ssl_load_key: can't build rsa private key s-exp\n");
        return NULL;
    }

    for (i=0; i< 6; i++)
        gcry_mpi_release(rsa_params[i]);
    return rsa_priv_key;
}



/**
 * Load a RSA private key from a PKCS#12 file.
 * @param fp the file that contains the key data.
 * @param cert_passwd password to decrypt the PKCS#12 file.
 * @param[out] err error message upon failure; NULL upon success.
 * @return a pointer to the loaded key on success; NULL upon failure.
 */
static gnutls_x509_privkey_t
ssl_load_pkcs12(FILE* fp, const gchar *cert_passwd, char** err) {

    int                       i, j, ret;
    int                       rest;
    unsigned char            *p;
    gnutls_datum_t            data;
    gnutls_pkcs12_bag_t       bag = NULL;
    gnutls_pkcs12_bag_type_t  bag_type;
    size_t                    len;

    gnutls_pkcs12_t       ssl_p12  = NULL;
    gnutls_x509_privkey_t ssl_pkey = NULL;

    gnutls_x509_privkey_t     priv_key = NULL;
    *err = NULL;

    rest = 4096;
    data.data = (unsigned char *)g_malloc(rest);
    data.size = rest;
    p = data.data;
    while ((len = fread(p, 1, rest, fp)) > 0) {
        p += len;
        rest -= (int) len;
        if (!rest) {
            rest = 1024;
            data.data = (unsigned char *)g_realloc(data.data, data.size + rest);
            p = data.data + data.size;
            data.size += rest;
        }
    }
    data.size -= rest;
    ssl_debug_printf("%d bytes read\n", data.size);
    if (!feof(fp)) {
        *err = g_strdup("Error during certificate reading.");
        ssl_debug_printf("%s\n", *err);
        g_free(data.data);
        return 0;
    }

    ret = gnutls_pkcs12_init(&ssl_p12);
    if (ret < 0) {
        *err = g_strdup_printf("gnutls_pkcs12_init(&st_p12) - %s", gnutls_strerror(ret));
        ssl_debug_printf("%s\n", *err);
        g_free(data.data);
        return 0;
    }

    /* load PKCS#12 in DER or PEM format */
    ret = gnutls_pkcs12_import(ssl_p12, &data, GNUTLS_X509_FMT_DER, 0);
    if (ret < 0) {
        *err = g_strdup_printf("could not load PKCS#12 in DER format: %s", gnutls_strerror(ret));
        ssl_debug_printf("%s\n", *err);
        g_free(*err);

        ret = gnutls_pkcs12_import(ssl_p12, &data, GNUTLS_X509_FMT_PEM, 0);
        if (ret < 0) {
            *err = g_strdup_printf("could not load PKCS#12 in PEM format: %s", gnutls_strerror(ret));
            ssl_debug_printf("%s\n", *err);
        } else {
            *err = NULL;
        }
    }
    g_free(data.data);
    if (ret < 0) {
        return 0;
    }

    ssl_debug_printf( "PKCS#12 imported\n");

    /* TODO: Use gnutls_pkcs12_simple_parse, since 3.1.0 (August 2012) */
    for (i=0; ; i++) {

        ret = gnutls_pkcs12_bag_init(&bag);
        if (ret < 0) break;

        ret = gnutls_pkcs12_get_bag(ssl_p12, i, bag);
        if (ret < 0) break;

        for (j=0; j<gnutls_pkcs12_bag_get_count(bag); j++) {

            ret = gnutls_pkcs12_bag_get_type(bag, j);
            if (ret < 0) goto done;
            bag_type = (gnutls_pkcs12_bag_type_t)ret;
            if (bag_type >= GNUTLS_BAG_UNKNOWN) goto done;
            ssl_debug_printf( "Bag %d/%d: %s\n", i, j, BAGTYPE(bag_type));
            if (bag_type == GNUTLS_BAG_ENCRYPTED) {
                ret = gnutls_pkcs12_bag_decrypt(bag, cert_passwd);
                if (ret == 0) {
                    ret = gnutls_pkcs12_bag_get_type(bag, j);
                    if (ret < 0) goto done;
                    bag_type = (gnutls_pkcs12_bag_type_t)ret;
                    if (bag_type >= GNUTLS_BAG_UNKNOWN) goto done;
                    ssl_debug_printf( "Bag %d/%d decrypted: %s\n", i, j, BAGTYPE(bag_type));
                }
            }

            ret = gnutls_pkcs12_bag_get_data(bag, j, &data);
            if (ret < 0) goto done;

            switch (bag_type) {

                case GNUTLS_BAG_PKCS8_KEY:
                case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:

                    ret = gnutls_x509_privkey_init(&ssl_pkey);
                    if (ret < 0) {
                        *err = g_strdup_printf("gnutls_x509_privkey_init(&ssl_pkey) - %s", gnutls_strerror(ret));
                        ssl_debug_printf("%s\n", *err);
                        goto done;
                    }
                    ret = gnutls_x509_privkey_import_pkcs8(ssl_pkey, &data, GNUTLS_X509_FMT_DER, cert_passwd,
                                                           (bag_type==GNUTLS_BAG_PKCS8_KEY) ? GNUTLS_PKCS_PLAIN : 0);
                    if (ret < 0) {
                        *err = g_strdup_printf("Can not decrypt private key - %s", gnutls_strerror(ret));
                        ssl_debug_printf("%s\n", *err);
                        goto done;
                    }

                    if (gnutls_x509_privkey_get_pk_algorithm(ssl_pkey) != GNUTLS_PK_RSA) {
                        *err = g_strdup("ssl_load_pkcs12: private key public key algorithm isn't RSA");
                        ssl_debug_printf("%s\n", *err);
                        goto done;
                    }

                    /* Private key found, return it. */
                    priv_key = ssl_pkey;
                    goto done;

                default: ;
            }
        }  /* j */
        if (bag) { gnutls_pkcs12_bag_deinit(bag); bag = NULL; }
    }  /* i */

done:
    if (!priv_key && ssl_pkey)
        gnutls_x509_privkey_deinit(ssl_pkey);
    if (bag)
        gnutls_pkcs12_bag_deinit(bag);

    return priv_key;
}
/*
unsigned char client_random[32]=
{
0x5a,0xb0,0x75,0xf6,0x01,0x38,0x8e,0xdb,0x10,0xd0,0x8b,0xd6,0x7b,0x2c,0xc3,0x8c,
0x4f,0xed,0x5c,0xa3,0xb4,0x7f,0x53,0x48,0x6a,0x23,0x28,0x86,0x35,0xb0,0x85,0x06
};
unsigned char server_random[32]=
{
0x5a,0xb0,0x75,0xf7,0xaa,0x27,0xdd,0x9a,0x9f,0x87,0x53,0xe9,0xba,0x88,0xd0,0xf5,
0x8b,0xf1,0x89,0x40,0xa2,0x0c,0x67,0xcb,0xdb,0x28,0x39,0xaa,0x37,0xa6,0x3f,0x6c
};
unsigned char client_random2[32]=
{
0x5a,0xb0,0x75,0xfe,0x8d,0x43,0xdf,0x0c,0x75,0x34,0x34,0xd3,0xef,0x0e,0x8a,0xee,
0xa8,0xea,0x34,0xc6,0xa3,0xf9,0x15,0x66,0xdd,0x02,0xbf,0x04,0x3a,0x91,0xb9,0xdb
};
unsigned char server_random2[32]=
{
0x5a,0xb0,0x75,0xff,0x57,0xc3,0xc5,0x8a,0xa8,0x6f,0xf7,0x6d,0xe0,0x1a,0x31,0xe4,
0x15,0x11,0x70,0x5b,0x08,0x1b,0x56,0x32,0x07,0xe0,0x8a,0xdb,0xc4,0x5f,0xb6,0x39
};
unsigned char encrypted_data[128]=
{
0xa5,0xe6,0x73,0x6e,0x50,0xf8,0x9e,0x3a,0x41,0x78,0x88,0x48,0xb7,0xd4,0xfb,0x6d,
0xba,0x3c,0x83,0x0b,0xa7,0xcb,0x7a,0x5e,0x1c,0x4a,0xac,0xaa,0x0a,0x2a,0x46,0x6f,
0xde,0x51,0x9e,0x86,0x01,0x49,0xc8,0x34,0x2b,0xf6,0x81,0xa4,0x07,0x96,0x9d,0xee,
0xc5,0xdc,0x0c,0x7d,0xcc,0x69,0xf2,0x09,0x95,0xb1,0x0a,0x8c,0xde,0x4a,0x36,0xcc,
0x50,0x6a,0x69,0x4a,0x15,0xf6,0x5f,0x42,0x7f,0xe9,0xe5,0xc6,0xcd,0x37,0x07,0xa3,
0x0e,0xa8,0x71,0x75,0x75,0x67,0x1d,0x78,0x74,0xfd,0x71,0x2d,0x79,0x56,0xab,0x38,
0xde,0xc1,0xba,0xf8,0x27,0xa7,0xf3,0x4a,0xf2,0x57,0xdb,0xae,0x68,0xc0,0x9d,0xdf,
0xa6,0x5d,0x6b,0x89,0xa0,0xb2,0xac,0xd3,0x34,0x89,0xe2,0x27,0x35,0x52,0xfa,0x48
};*/
unsigned char  pre_master_secret[48]={0};

#define ws_statb64	struct stat
#define ws_fstat64 fstat	/* AC_SYS_LARGEFILE should make off_t 64-bit */
#define ws_fileno  fileno

/** Load an RSA private key from specified file
 @param fp the file that contain the key data
 @return a pointer to the loaded key on success, or NULL */
static gnutls_x509_privkey_t
ssl_load_key(FILE* fp)
{
    /* gnutls makes our work much harder, since we have to work internally with
     * s-exp formatted data, but PEM loader exports only in "gnutls_datum_t"
     * format, and a datum -> s-exp convertion function does not exist.
     */
    gnutls_x509_privkey_t priv_key;
    gnutls_datum_t        key;
    ws_statb64            statbuf;   
    gint                  ret;
    guint                 bytes;

    if (ws_fstat64(ws_fileno(fp), &statbuf) == -1) {
        ssl_debug_printf("ssl_load_key: can't ws_fstat64 file\n");
        return NULL;
    }
    /*if (S_ISDIR(statbuf.st_mode)) {
        ssl_debug_printf("ssl_load_key: file is a directory\n");
        errno = EISDIR;
        return NULL;
    }
    if (S_ISFIFO(statbuf.st_mode)) {
        ssl_debug_printf("ssl_load_key: file is a named pipe\n");
        errno = EINVAL;
        return NULL;
    }
    if (!S_ISREG(statbuf.st_mode)) {
        ssl_debug_printf("ssl_load_key: file is not a regular file\n");
        errno = EINVAL;
        return NULL;
    }*/
    /* XXX - check for a too-big size */
    /* load all file contents into a datum buffer*/
    key.data = (unsigned char *)g_malloc((size_t)statbuf.st_size);
    key.size = (int)statbuf.st_size;
    bytes = (guint) fread(key.data, 1, key.size, fp);
    if (bytes < key.size) {
        ssl_debug_printf("ssl_load_key: can't read from file %d bytes, got %d\n",
            key.size, bytes);
        g_free(key.data);
        return NULL;
    }

    /* init private key data*/
    gnutls_x509_privkey_init(&priv_key);

    /* import PEM data*/
    if ((ret = gnutls_x509_privkey_import(priv_key, &key, GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS) {
        ssl_debug_printf("ssl_load_key: can't import pem data: %s\n", gnutls_strerror(ret));
        g_free(key.data);
        return NULL;
    }

    if (gnutls_x509_privkey_get_pk_algorithm(priv_key) != GNUTLS_PK_RSA) {
        ssl_debug_printf("ssl_load_key: private key public key algorithm isn't RSA\n");
        g_free(key.data);
        return NULL;
    }

    g_free(key.data);

    return priv_key;
}

StringInfo master_secret;
StringInfo  secret, rnd1, rnd2;

void init_ssl(void)
{
	memset(&ssl_stream,0,sizeof(ssl_stream));
	sindex=0;
	if (ssl_data_alloc(&secret, 48) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
        return;
        //return FALSE;
    }
      if (ssl_data_alloc(&rnd1, 32) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
         //goto free_rnd1;
    }
      if (ssl_data_alloc(&rnd2, 32) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
         //goto free_rnd2;
       	}
       if (ssl_data_alloc(&master_secret, SSL_MASTER_SECRET_LENGTH) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
         //goto free_rnd2;
       	}

}

gcry_sexp_t        private_key;
//load file from apache https server rsa private key ,see more about httpd-ssl.conf
void load_server_rsa_pri_keyfile(void)
{
   gnutls_x509_privkey_t priv_key;
   // gcry_sexp_t        private_key;
    FILE*              fp     = NULL;
    int                ret;
    size_t             key_id_len = 20;
    guchar            *key_id = NULL;

   init_ssl();

     /* try to load keys file first */
    fp = fopen("./server.key", "rb");
    if (!fp) {       
        return;
    }
    priv_key = ssl_load_key(fp);
    fclose(fp);

    if (!priv_key) {
        printf("Can't load private key from server.key\n");
        return;
    }
    
    key_id = (guchar *) g_malloc0(key_id_len);
    ret = gnutls_x509_privkey_get_key_id(priv_key, 0, key_id, &key_id_len);
    if (ret < 0) {
        printf("gnutls_x509_privkey_get_key_id error :%s\n", gnutls_strerror(ret));
        goto end;
    }
    ssl_print_data("KeyID", key_id, key_id_len);

    private_key = ssl_privkey_to_sexp(priv_key);
    if (!private_key) {
         printf("Can't  Cac private key from gnutls_x509_privkey_t\n");
        goto end;
    }
   // printf("%s: lookup result: %p\n", G_STRFUNC, (void *)private_key);
printf("Congratulations,load private key from server.key ok!!!\n");

  /* with tls key loading will fail if not rsa type, so no need to check*/
 // StringInfo encrypted_pre_master;
  guint i=0;

	/*encrypted_pre_master.data = (guchar *) wmem_alloc(wmem_file_scope(),128);	
	ssl_data_set(&encrypted_pre_master, encrypted_data, 128);
  
    ssl_print_string("pre master encrypted",&encrypted_pre_master);
    ssl_debug_printf("%s: RSA_private_decrypt\n", G_STRFUNC);
  //  i=ssl_private_decrypt(encrypted_pre_master.data_len,  encrypted_pre_master.data, private_key);*/
	
   

end:
    gnutls_x509_privkey_deinit(priv_key);
    g_free(key_id);
    
}

/* Digests, Ciphers and Cipher Suites registry }}} */


/* HMAC and the Pseudorandom function {{{ */
static void
tls_hash(StringInfo *secret, StringInfo *seed, gint md,
         StringInfo *out, guint out_len)
{
    /* RFC 2246 5. HMAC and the pseudorandom function
     * '+' denotes concatenation.
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                        HMAC_hash(secret, A(2) + seed) + ...
     * A(0) = seed
     * A(i) = HMAC_hash(secret, A(i - 1))
     */
    guint8   *ptr;
    guint     left, tocpy;
    guint8   *A;
    guint8    _A[DIGEST_MAX_SIZE], tmp[DIGEST_MAX_SIZE];
    guint     A_l, tmp_l;
    SSL_HMAC  hm;

    ptr  = out->data;
    left = out_len;

    ssl_print_string("tls_hash: hash secret", secret);
    ssl_print_string("tls_hash: hash seed", seed);
    /* A(0) = seed */
    A = seed->data;
    A_l = seed->data_len;

    while (left) {
        /* A(i) = HMAC_hash(secret, A(i-1)) */
        ssl_hmac_init(&hm, secret->data, secret->data_len, md);
        ssl_hmac_update(&hm, A, A_l);
        A_l = sizeof(_A); /* upper bound len for hash output */
        ssl_hmac_final(&hm, _A, &A_l);
        ssl_hmac_cleanup(&hm);
        A = _A;

        /* HMAC_hash(secret, A(i) + seed) */
        ssl_hmac_init(&hm, secret->data, secret->data_len, md);
        ssl_hmac_update(&hm, A, A_l);
        ssl_hmac_update(&hm, seed->data, seed->data_len);
        tmp_l = sizeof(tmp); /* upper bound len for hash output */
        ssl_hmac_final(&hm, tmp, &tmp_l);
        ssl_hmac_cleanup(&hm);

        /* ssl_hmac_final puts the actual digest output size in tmp_l */
        tocpy = MIN(left, tmp_l);
        memcpy(ptr, tmp, tocpy);
        ptr += tocpy;
        left -= tocpy;
    }
    out->data_len = out_len;

    ssl_print_string("hash out", out);
}


static gboolean
tls_prf(StringInfo* secret, const gchar *usage,
        StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, guint out_len)
{
    StringInfo  seed, sha_out, md5_out;
    guint8     *ptr;
    StringInfo  s1, s2;
    guint       i,s_l;
    size_t      usage_len, rnd2_len;
    gboolean    success = FALSE;
    usage_len = strlen(usage);
    rnd2_len = rnd2 ? rnd2->data_len : 0;

    /* initalize buffer for sha, md5 random seed*/
    if (ssl_data_alloc(&sha_out, MAX(out_len, 20)) < 0) {
        ssl_debug_printf("dtls_prf: can't allocate sha out\n");
        return FALSE;
    }
    if (ssl_data_alloc(&md5_out, MAX(out_len, 16)) < 0) {
        ssl_debug_printf("dtls_prf: can't allocate md5 out\n");
        goto free_sha;
    }
    if (ssl_data_alloc(&seed, usage_len+rnd1->data_len+rnd2_len) < 0) {
        ssl_debug_printf("dtls_prf: can't allocate rnd %d\n",
                         (int) (usage_len+rnd1->data_len+rnd2_len));
        goto free_md5;
    }

    ptr=seed.data;
    memcpy(ptr,usage,usage_len);
    ptr+=usage_len;
    memcpy(ptr,rnd1->data,rnd1->data_len);
    if (rnd2_len > 0) {
        ptr+=rnd1->data_len;
        memcpy(ptr,rnd2->data,rnd2->data_len);
        /*ptr+=rnd2->data_len;*/
    }

    /* initalize buffer for client/server seeds*/
    s_l=secret->data_len/2 + secret->data_len%2;
    if (ssl_data_alloc(&s1, s_l) < 0) {
        ssl_debug_printf("dtls_prf: can't allocate secret %d\n", s_l);
        goto free_seed;
    }
    if (ssl_data_alloc(&s2, s_l) < 0) {
        ssl_debug_printf("dtls_prf: can't allocate secret(2) %d\n", s_l);
        goto free_s1;
    }

    memcpy(s1.data,secret->data,s_l);
    memcpy(s2.data,secret->data + (secret->data_len - s_l),s_l);

    ssl_debug_printf("dtls_prf: tls_hash(md5 secret_len %d seed_len %d )\n", s1.data_len, seed.data_len);
    tls_hash(&s1, &seed, ssl_get_digest_by_name("MD5"), &md5_out, out_len);
    ssl_debug_printf("dtls_prf: tls_hash(sha)\n");
    tls_hash(&s2, &seed, ssl_get_digest_by_name("SHA1"), &sha_out, out_len);

    for (i = 0; i < out_len; i++)
        out->data[i] = md5_out.data[i] ^ sha_out.data[i];
    /* success, now store the new meaningful data length */
    out->data_len = out_len;
    success = TRUE;

    ssl_print_string("PRF out",out);
    g_free(s2.data);
free_s1:
    g_free(s1.data);
free_seed:
    g_free(seed.data);
free_md5:
    g_free(md5_out.data);
free_sha:
    g_free(sha_out.data);
    return success;
}

static gboolean
tls12_prf(gint md, StringInfo* secret, const gchar* usage,
          StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, guint out_len)
{
    StringInfo label_seed;
    size_t     usage_len, rnd2_len;
    rnd2_len = rnd2 ? rnd2->data_len : 0;

    usage_len = strlen(usage);
    if (ssl_data_alloc(&label_seed, usage_len+rnd1->data_len+rnd2_len) < 0) {
        ssl_debug_printf("tls12_prf: can't allocate label_seed\n");
        return FALSE;
    }
    memcpy(label_seed.data, usage, usage_len);
    memcpy(label_seed.data+usage_len, rnd1->data, rnd1->data_len);
    if (rnd2_len > 0)
        memcpy(label_seed.data+usage_len+rnd1->data_len, rnd2->data, rnd2->data_len);

    ssl_debug_printf("tls12_prf: tls_hash(hash_alg %s secret_len %d seed_len %d )\n", gcry_md_algo_name(md), secret->data_len, label_seed.data_len);
    tls_hash(secret, &label_seed, md, out, out_len);
    g_free(label_seed.data);
    ssl_print_string("PRF out", out);
    return TRUE;
}

/* out_len is the wanted output length for the pseudorandom function.
 * Ensure that ssl->cipher_suite is set. */
static gboolean
prf(SslCipherSuite *cipher_suite,guint version, StringInfo *secret, const gchar *usage,
    StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, guint out_len)
{
    switch (version) {
    case SSLV3_VERSION:
        return ssl3_prf(secret, usage, rnd1, rnd2, out, out_len);

    case TLSV1_VERSION:
    case TLSV1DOT1_VERSION:
    case DTLSV1DOT0_VERSION:
    case DTLSV1DOT0_OPENSSL_VERSION:
        return tls_prf(secret, usage, rnd1, rnd2, out, out_len);

    default: /* TLSv1.2 */
        //switch (ssl->cipher_suite->dig) {
        switch (cipher_suite->dig) {
        case DIG_SHA384:
            return tls12_prf(GCRY_MD_SHA384, secret, usage, rnd1, rnd2,
                             out, out_len);
        default:
            return tls12_prf(GCRY_MD_SHA256, secret, usage, rnd1, rnd2,
                             out, out_len);
        }
    }
}


gboolean
ssl_generate_master_secret(unsigned char *pre_master_secret,unsigned char *client_random,unsigned char *server_random,unsigned char *out)
{
	SslCipherSuite *cipher_suite;
	gint md;

	cipher_suite=ssl_find_cipher(ssl_stream[sindex].cipher_num);
	if(!cipher_suite)
		return FALSE;
	md=GCRY_MD_SHA256;
	if(cipher_suite->dig==DIG_SHA384)
		md=GCRY_MD_SHA384;

	 /* initalize buffer for sha, md5 random seed
    if (ssl_data_alloc(&secret, 48) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
        return FALSE;
    }
      if (ssl_data_alloc(&rnd1, 32) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
         //goto free_rnd1;
    }
      if (ssl_data_alloc(&rnd2, 32) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
         //goto free_rnd2;
       	}
       if (ssl_data_alloc(&master_secret, SSL_MASTER_SECRET_LENGTH) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
         //goto free_rnd2;
       	} */

	memcpy(secret.data,pre_master_secret,SSL_MASTER_SECRET_LENGTH);
      memcpy(rnd1.data,client_random,32);
      memcpy(rnd2.data,server_random,32);
       ssl_debug_printf("%s:PRF(pre_master_secret)\n", G_STRFUNC);
       ssl_print_string("pre master secret",&secret);
      ssl_print_string("client random",&rnd1);
      ssl_print_string("server random",&rnd2);
     /* if (!tls_prf(&secret, "master secret",
                     &rnd1,
                     &rnd2, &master_secret,
                     SSL_MASTER_SECRET_LENGTH)) {
                ssl_debug_printf("%s can't generate master_secret\n", G_STRFUNC);
                return FALSE;
            }*/

      if (!tls12_prf(md,&secret, "master secret",
                     &rnd1,
                     &rnd2, &master_secret,
                     SSL_MASTER_SECRET_LENGTH)) {
                ssl_debug_printf("%s can't generate master_secret\n", G_STRFUNC);
                return FALSE;
            }

      
        
        ssl_print_string("master secret",&master_secret);
        memcpy(out,master_secret.data,48);
        printf("Master Secret is here ,ok ,This SSL Stream %d can be decrypted!\n",sindex);
      
      /*    free_rnd2:
    		g_free(rnd2.data);
	 free_rnd1:
   	 	g_free(rnd1.data);
   	 free_secret:
   		g_free(secret.data);*/
	

    return TRUE;
    
}

/*
unsigned char in2[36]=
{
0x71,0x77,0x3f,0x5a,0x8c,0xae,0xdc,0x94,0x43,0x04,0xc6,
0x79,0x64,0x36,0x7f,0xcc,0x7b,0x72,0x06,0xd8,0x46,0xfb,0x46,0x09,0xd8,0xe3,0xd3,
0x5e,0xe4,0x40,0x2b,0x3f,0x91,0xb1,0xa8,0xe5
};

//to server ,client exchange key finished
unsigned char in[36]=
{
0x8d,0x46,0x0a,0xf9,0x99,0x5b,0xfb,0x49,0x3f,0xa8,0xd7,
0x7a,0x5c,0xc4,0xf9,0x0a,0x8a,0x8b,0xa2,0x63,0x2d,0xaf,
0x47,0x3f,0xb6,0x1f,0x01,0x2f,0x68,0x1b,0x83,0x57,0xf6,
0xeb,0x0c,0x93
};

unsigned char in_client[36]={
0x8c,0xde,0x12,0x07,0x9a,0x67,0x23,0x90,0x97,0xd7,0xff,
0xa2,0xd3,0x3d,0xde,0x75,0x0d,0x43,0x8e,0xa8,0x47,0x12,0x52,0x0e,0xc5,0xa5,0x04,
0x2f,0xfc,0xef,0x16,0xf1,0x6a,0xea,0x61,0xfc};

unsigned char testin1[382]=
	{
 0x3b,0xc1,0x06,0x0b,0x69,0x30,0x61,0xff,0x6b,0x16,0xc1,0xf0,0x04,0xc8,0xcc,0xb0,
0x59,0xa5,0xed,0xe9,0x84,0xb4,0x73,0x47,0x1b,0xbf,0x26,0xa2,0xc9,0xbc,0x0a,0xbb,
0x66,0x35,0x17,0x20,0x71,0x7e,0xf2,0x7c,0x00,0x55,0x46,0x8f,0x8b,0x65,0x1d,0x27,
0x08,0x33,0xf2,0x7e,0xa3,0xe9,0x79,0x73,0xb6,0x13,0x88,0x94,0xe5,0x8f,0x63,0x84,
0xfd,0x19,0xdf,0x52,0x6f,0x48,0x82,0x51,0x30,0x84,0x2c,0xbc,0x94,0x4f,0xd3,0xba,
0x9d,0x38,0xfc,0x35,0x6b,0x23,0x48,0xf9,0x1a,0x1c,0x41,0x01,0x57,0xe0,0xd1,0x1d,
0x12,0xa8,0x56,0xd3,0x71,0xa6,0xae,0x15,0xb4,0xa0,0xec,0x0f,0xfb,0x34,0xc9,0xff,
0x22,0x75,0x48,0x07,0xda,0x5d,0x9e,0x3b,0x75,0xd6,0x7c,0x9e,0x71,0x2f,0x9c,0xf1,
0xe7,0x11,0xe8,0x6d,0x41,0x63,0x3c,0x5c,0x6d,0xcc,0xa5,0xa0,0xfd,0x3e,0x08,0x32,
0xc3,0x0d,0x0c,0x7e,0xb8,0x0a,0xf6,0x22,0xee,0x70,0xce,0xe2,0xc2,0xdb,0x0f,0xcc,
0x9d,0x17,0xce,0x98,0xc6,0xf4,0xed,0xf8,0xf3,0x9c,0xb1,0xb1,0x9d,0xce,0xb5,0x42,
0xee,0x1e,0xe5,0xa8,0x48,0x4d,0x23,0x9b,0x96,0x26,0x95,0x72,0xa6,0xac,0xb9,0xb1,
0xa6,0x17,0xd6,0x52,0xc5,0xdd,0xe5,0xdc,0x65,0x2b,0xaa,0x5c,0xdc,0x6a,0x8d,0xaf,
0xf9,0xb4,0x99,0x0c,0x3e,0xb8,0xfb,0xd9,0xf6,0x7d,0x80,0x0b,0x7b,0x34,0x08,0xe0,
0x82,0x69,0xd5,0x97,0xec,0x7a,0xbc,0x39,0xe5,0xdc,0x53,0x9b,0x90,0xe6,0x98,0xe7,
0x7a,0x3e,0x24,0x84,0x8d,0xc8,0x31,0x98,0xaa,0xfc,0x78,0xde,0x94,0x7e,0x81,0x02,
0x3c,0x19,0x50,0x8a,0xe9,0x8f,0xa6,0xe2,0x3c,0x8e,0xf6,0x92,0x4b,0x84,0xc7,0x64,
0x33,0x35,0x53,0x2a,0xa3,0x34,0xbe,0x6e,0x06,0x68,0xf0,0xd0,0xce,0xcb,0x27,0xea,
0xa2,0x72,0xfb,0xfd,0x59,0xf1,0x00,0xba,0xa7,0xe7,0x08,0xbf,0x61,0x3d,0xd6,0xe2,
0xd2,0x7a,0xbe,0x15,0xba,0x32,0x26,0x5a,0x13,0x2f,0xc3,0x4c,0xb7,0xa1,0xc9,0x3d,
0x50,0xaf,0x54,0xc8,0x3e,0x52,0xa0,0xeb,0x22,0x78,0xf8,0x63,0x8d,0x37,0x8a,0x00,
0x0f,0x49,0x48,0x6d,0x75,0x44,0x48,0x12,0xf8,0x1a,0x34,0xb9,0xc9,0x91,0x01,0x75,
0xe2,0x60,0xe7,0x97,0xbc,0xdc,0xa9,0x7c,0xe4,0xb3,0xb2,0xf5,0xad,0x78,0xaf,0x74,
0x35,0x55,0x65,0x01,0x4f,0xf0,0xa3,0x4a,0x7b,0x93,0x8d,0xac,0x6f,0x41

};*/

static guint
ssl_get_cipher_export_keymat_size(int cipher_suite_num)
{
    switch (cipher_suite_num) {
    /* See RFC 6101 (SSL 3.0), Table 2, column Key Material. */
    case 0x0003:    /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    case 0x0006:    /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    case 0x0008:    /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
    case 0x000B:    /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
    case 0x000E:    /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
    case 0x0011:    /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
    case 0x0014:    /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    case 0x0017:    /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
    case 0x0019:    /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
        return 5;

    /* not defined in below draft, but "implemented by several vendors",
     * https://www.ietf.org/mail-archive/web/tls/current/msg00036.html */
    case 0x0060:    /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
    case 0x0061:    /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
        return 7;

    /* Note: the draft states that DES_CBC needs 8 bytes, but Wireshark always
     * used 7. Until a pcap proves 8, let's use the old value. Link:
     * https://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01 */
    case 0x0062:    /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
    case 0x0063:    /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
    case 0x0064:    /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
    case 0x0065:    /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
        return 7;

    default:
        return 0;
    }
}

/* Digests, Ciphers and Cipher Suites registry {{{ */
static const SslDigestAlgo digests[]={
    {"MD5",     16},
    {"SHA1",    20},
    {"SHA256",  32},
    {"SHA384",  48},
    {"Not Applicable",  0},
};



/* get index digest index */
static const SslDigestAlgo *
ssl_cipher_suite_dig(const SslCipherSuite *cs) {
    return &digests[cs->dig - DIG_MD5];
}
guint
ssl_get_cipher_blocksize(const SslCipherSuite *cipher_suite)
{
    gint cipher_algo;
    if (cipher_suite->mode != MODE_CBC) return 0;
    cipher_algo = ssl_get_cipher_by_name(ciphers[cipher_suite->enc - 0x30]);
    return (guint)gcry_cipher_get_algo_blklen(cipher_algo);
}

//init cipher suit..............................fuck ssl ,fucking...........by wmk 20180401.....
void wmk_decrypt_everything(SslCipherSuite *cipher_suite,unsigned char *master,unsigned char *client_random,unsigned char *server_random)
{
   StringInfo  key_block = { NULL, 0 };
    guint8      _iv_c[MAX_BLOCK_SIZE],_iv_s[MAX_BLOCK_SIZE];
    guint8      _key_c[MAX_KEY_SIZE],_key_s[MAX_KEY_SIZE];
    gint        needed;
    gint        cipher_algo = -1;   /* special value (-1) for NULL encryption */
    guint       encr_key_len, write_iv_len = 0;
    gboolean    is_export_cipher;
    guint8     *ptr, *c_iv = NULL, *s_iv = NULL;
    guint8     *c_wk = NULL, *s_wk = NULL, *c_mk = NULL, *s_mk = NULL;
    ssl_cipher_mode_t mode = cipher_suite->mode;

    gint inl, outl,pad;
	//unsigned char out[1024];

      /* Find the Libgcrypt cipher algorithm for the given SSL cipher suite ID */
    if (cipher_suite->enc != ENC_NULL) {
        const char *cipher_name = ciphers[cipher_suite->enc-0x30];
        ssl_debug_printf("%s CIPHER: %s\n", G_STRFUNC, cipher_name);
        cipher_algo = ssl_get_cipher_by_name(cipher_name);
        if (cipher_algo == 0) {
            ssl_debug_printf("%s can't find cipher %s\n", G_STRFUNC, cipher_name);
            return -1;
        }
    }

      /* Export ciphers consume less material from the key block. */
    encr_key_len = ssl_get_cipher_export_keymat_size(cipher_suite->number);
    is_export_cipher = encr_key_len > 0;
    if (!is_export_cipher && cipher_suite->enc != ENC_NULL) {
        encr_key_len = (guint)gcry_cipher_get_algo_keylen(cipher_algo);
    }
    
 	if (cipher_suite->mode == MODE_CBC) {
        write_iv_len = (guint)gcry_cipher_get_algo_blklen(cipher_algo);
    } else if (cipher_suite->mode == MODE_GCM || cipher_suite->mode == MODE_CCM || cipher_suite->mode == MODE_CCM_8) {
        /* account for a four-byte salt for client and server side (from
         * client_write_IV and server_write_IV), see GCMNonce (RFC 5288) */
        write_iv_len = 4;
    } else if (cipher_suite->mode == MODE_POLY1305) {
        /* RFC 7905: SecurityParameters.fixed_iv_length is twelve bytes */
        write_iv_len = 12;
    }	

    /* Compute the key block. First figure out how much data we need */
    needed = ssl_cipher_suite_dig(cipher_suite)->len*2;     /* MAC key  */
    needed += 2 * encr_key_len;                             /* encryption key */
    needed += 2 * write_iv_len;                             /* write IV */
	
     key_block.data = (guchar *)g_malloc(needed);
    ssl_debug_printf("%s sess key generation\n", G_STRFUNC);
    
   /* printf(" encr_key_len=%d,is_export_cipher=%d,write_iv_len=%d,needed=%d mode=%d,cipher_algo=%d\n",encr_key_len,is_export_cipher,write_iv_len,
    	needed,cipher_suite->mode ,cipher_algo);
    
      if (!prf(ssl_session, &ssl_session->master_secret, "key expansion",
            &ssl_session->server_random,&ssl_session->client_random,
            &key_block, needed))*/

       memcpy(rnd1.data,client_random,32);
       memcpy(rnd2.data,server_random,32);
       memcpy(master_secret.data,master,48);

	//tls1.0 not support
      /* if (!tls_prf(&master_secret, "key expansion",
                     &rnd2,   &rnd1, 
                     &key_block, needed) ){
                ssl_debug_printf("%s can't generate key_block\n", G_STRFUNC);
                 goto fail;
            }*/

	gint md;	
	md=GCRY_MD_SHA256;
	if(cipher_suite->dig==DIG_SHA384)
		md=GCRY_MD_SHA384;
      if (!tls12_prf(md,&master_secret, "key expansion",
                     &rnd2,   &rnd1, 
                     &key_block, needed) ){
                ssl_debug_printf("%s can't generate key_block\n", G_STRFUNC);
                 goto fail;
            }

                             
 	ssl_print_string("key expansion", &key_block);

    ptr=key_block.data;
    /* client/server write MAC key (for non-AEAD ciphers) */
    if (cipher_suite->mode == MODE_STREAM || cipher_suite->mode == MODE_CBC) {
        c_mk=ptr; ptr+=ssl_cipher_suite_dig(cipher_suite)->len;
        s_mk=ptr; ptr+=ssl_cipher_suite_dig(cipher_suite)->len;
    }
    /* client/server write encryption key */
    c_wk=ptr; ptr += encr_key_len;
    s_wk=ptr; ptr += encr_key_len;
    /* client/server write IV (used as IV (for CBC) or salt (for AEAD)) */
    if (write_iv_len > 0) {
        c_iv=ptr; ptr += write_iv_len;
        s_iv=ptr; /* ptr += write_iv_len; */
    }

         /* show key material info */
    if (c_mk != NULL) {
        ssl_print_data("Client MAC key",c_mk,ssl_cipher_suite_dig(cipher_suite)->len);
        ssl_print_data("Server MAC key",s_mk,ssl_cipher_suite_dig(cipher_suite)->len);
    }
    ssl_print_data("Client Write key", c_wk, encr_key_len);
    ssl_print_data("Server Write key", s_wk, encr_key_len);
    /* used as IV for CBC mode and the AEAD implicit nonce (salt) */
    if (write_iv_len > 0) {
        ssl_print_data("Client Write IV", c_iv, write_iv_len);
        ssl_print_data("Server Write IV", s_iv, write_iv_len);
    }  

 	
   	 if(write_iv_len>48)
    		goto fail;

	if (mode == MODE_GCM || mode == MODE_CCM || mode == MODE_CCM_8 || mode == MODE_POLY1305) 
	{
	    memcpy(ssl_stream[sindex].client_mac_key_or_write_iv,c_iv,write_iv_len);
	    memcpy(ssl_stream[sindex].server_mac_key_or_write_iv,s_iv,write_iv_len);
	}

   if (ssl_stream[sindex].evp_client)
        ssl_cipher_cleanup(&ssl_stream[sindex].evp_client);
   
 ssl_stream[sindex].evp_state=0;
 if (ssl_cipher_init(&ssl_stream[sindex].evp_client,cipher_algo,c_wk, c_iv,cipher_suite->mode) < 0) {
        ssl_debug_printf("%s: can't create cipher id:%d mode:%d\n", G_STRFUNC,
            cipher_algo, cipher_suite->mode);
       return;
    }
 ssl_stream[sindex].evp_state=EVP_HAVE_INIT;
 ssl_stream[sindex].aad_seq=0;
 /* if (ssl_cipher_init(&evp_server[0],cipher_algo,s_wk, s_iv,cipher_suite->mode) < 0) {
        ssl_debug_printf("%s: can't create cipher id:%d mode:%d\n", G_STRFUNC,
            cipher_algo, cipher_suite->mode);
       return;
    }*/


  

 

     g_free(key_block.data); 
    return ;
    

    fail:
    g_free(key_block.data);
    return;

}





void init_decode()
{
	

	load_server_rsa_pri_keyfile();
	 if(!debug_mode) return;
	  ssl_debug_file = fopen("ssl_debug.txt" ,"w");


   
}

void ssl_get_pre_master_secret_key(unsigned char *encrypted_data,int len)
{
	int i;
	SslCipherSuite *cipher;
	
	i=ssl_private_decrypt(len,  encrypted_data, private_key);
    if (i!=48) {
        ssl_debug_printf("%s wrong pre_master_secret length (%d, expected "
                         "%d)\n", G_STRFUNC, i, 48);
       return;
    }

    memcpy(pre_master_secret,encrypted_data,48);
    printf("Pre_Master_Key decrypted ok! Next to generate MasterKey %x-%x-%x-%x\n",pre_master_secret[0],pre_master_secret[1],pre_master_secret[2],pre_master_secret[3]);
  
   // if(wifi_mac_status)
    {
    		QQkey *ssl_sesstion_id=NULL;
    		
    		
   	 	memcpy(ssl_stream[sindex].pre_master_secret,encrypted_data,48);
   	 	if(ssl_generate_master_secret(&pre_master_secret,ssl_stream[sindex].client_random,ssl_stream[sindex].server_random,ssl_stream[sindex].master_secret))
   	 	 { 	   	 	 		
			ssl_stream[sindex].state |= SSL_MASTER_SECRET;
			memcpy(ssl_stream[sindex].master_secret,master_secret.data,48);
			//write ssesstion to hash ,save pre_master_secret
	   	 	 snprintf(hash_key,60,"%.2x%.2x%.2x%.2x",ssl_stream[sindex].session_id[0],ssl_stream[sindex].session_id[1],ssl_stream[sindex].session_id[2],ssl_stream[sindex].session_id[3]);
	   	 	 memset(buf_qq_key,0,sizeof(QQkey));	
			hashmap_put_qqkey(&hash_qq_key, hash_key, 0,(char *)&buf_qq_key, 0);	
			ssl_sesstion_id=(QQkey *)hashmap_get(&hash_qq_key,hash_key,0);
			if(ssl_sesstion_id)
			{
				memcpy(ssl_sesstion_id->master_secret,master_secret.data,48);
				memcpy(ssl_sesstion_id->pre_master_secret,pre_master_secret,48);
				//printf("save to hashmap sesstion id=%s for restore\n",hash_key);
			}
			
   	 	 }
    }
    
	return;	
}

static gboolean
tls_decrypt_aead_record(SslCipherSuite *cipher_suite,  const guchar *in, guint16 inl, guchar  *out, guint *outl)
{
    gcry_error_t    err;
    const guchar   *explicit_nonce = NULL, *ciphertext;
    guint           ciphertext_len, auth_tag_len;
    guchar          nonce[12];
    const ssl_cipher_mode_t cipher_mode = cipher_suite->mode;
    const guchar   *auth_tag_wire;
    guchar          auth_tag_calc[16];
    guchar aad[13];

	auth_tag_len=0;
	switch (cipher_mode) {
    case MODE_GCM:
    case MODE_CCM:
    case MODE_POLY1305:
        auth_tag_len = 16;
        break;
    case MODE_CCM_8:
        auth_tag_len = 8;
        break;
    default:
        ssl_debug_printf("%s unsupported cipher!\n", G_STRFUNC);
        return FALSE;
    }

        /* Parse input into explicit nonce (TLS 1.2 only), ciphertext and tag. */
    if ( cipher_mode != MODE_POLY1305) {
        if (inl < EXPLICIT_NONCE_LEN + auth_tag_len) {
            ssl_debug_printf("%s input %d is too small for explicit nonce %d and auth tag %d\n",
                    G_STRFUNC, inl, EXPLICIT_NONCE_LEN, auth_tag_len);
            return FALSE;
        }
        explicit_nonce = in;
        ciphertext = explicit_nonce + EXPLICIT_NONCE_LEN;
        ciphertext_len = inl - EXPLICIT_NONCE_LEN - auth_tag_len;
    } else if (cipher_mode == MODE_POLY1305) {
        if (inl < auth_tag_len) {
            ssl_debug_printf("%s input %d has no space for auth tag %d\n", G_STRFUNC, inl, auth_tag_len);
            return FALSE;
        }
        ciphertext = in;
        ciphertext_len = inl - auth_tag_len;
    } else {
        //ssl_debug_printf("%s Unexpected TLS version %#x\n", G_STRFUNC, version);
        return FALSE;
    }

     auth_tag_wire = ciphertext + ciphertext_len;

	//20180408 BY WMK ,only for AES GCM,fuck https ............
       if ( cipher_mode != MODE_GCM) 
       	return FALSE;

       

        /* Implicit (4) and explicit (8) part of nonce. */
        memcpy(nonce, ssl_stream[sindex].client_mac_key_or_write_iv, IMPLICIT_NONCE_LEN);
        memcpy(nonce + IMPLICIT_NONCE_LEN, explicit_nonce, EXPLICIT_NONCE_LEN);

	 gcry_cipher_reset(ssl_stream[sindex].evp_client);
	 ssl_print_data("nonce", nonce, 12);
	 err = gcry_cipher_setiv(ssl_stream[sindex].evp_client, nonce, 12);
	  if (err) {
	        ssl_debug_printf("%s failed to set nonce: %s\n", G_STRFUNC, gcry_strerror(err));
	        return FALSE;
    		}

	memset(aad,0,sizeof(aad));
       phton64(aad, ssl_stream[sindex].aad_seq); 
       ssl_stream[sindex].aad_seq++;
      // aad[8] = ct;                        /* TLSCompressed.type */
       // phton16(aad + 9, record_version);   /* TLSCompressed.version */
       phton16(aad + 9, 0x0303); 
        phton16(aad + 11, ciphertext_len);  /* TLSCompressed.length */
        ssl_print_data("AAD", aad, sizeof(aad));
        err = gcry_cipher_authenticate(ssl_stream[sindex].evp_client, aad, sizeof(aad));
        if (err) {
            ssl_debug_printf("%s failed to set AAD: %s\n", G_STRFUNC, gcry_strerror(err));
            return FALSE;
        }

            /* Decrypt now that nonce and AAD are set. */
    err = gcry_cipher_decrypt(ssl_stream[sindex].evp_client, out,outl, ciphertext, ciphertext_len);
    if (err) {
        ssl_debug_printf("%s decrypt failed: %s\n", G_STRFUNC, gcry_strerror(err));
        return FALSE;
    }
      ssl_print_data("Plaintext", out, ciphertext_len);
    *outl = ciphertext_len;
    return TRUE;
    

}

gint wmk_decrypt( guchar * out, gint outl,  guchar * in, gint inl)
{

gint pad,maclen;
guint worklen=0;

SslCipherSuite *cipher_suite;

 //if(ssl_stream[sindex].evp_state!=EVP_HAVE_INIT	)
 	//return;
  if (!ssl_stream[sindex].evp_client)
  	return -1;
cipher_suite=ssl_find_cipher(ssl_stream[sindex].cipher_num);
if(!cipher_suite)
	return -1;

if(cipher_suite->mode == MODE_GCM )
{
	 if (!tls_decrypt_aead_record( cipher_suite,in, inl, out, &worklen)) {
            //decryption failed 
            return -1;
        }
	 return 1;
}

maclen = ssl_cipher_suite_dig(cipher_suite)->len;
  /* (TLS 1.1 and later, DTLS) Extract explicit IV for GenericBlockCipher */
   if (cipher_suite->mode == MODE_CBC) 
	{
        guint blocksize = 0;

       
            blocksize = ssl_get_cipher_blocksize(cipher_suite);
            if (inl < blocksize) {
                ssl_debug_printf("ssl_decrypt_record failed: input %d has no space for IV %d\n",
                        inl, blocksize);
                return -1;
            }
            pad = gcry_cipher_setiv(ssl_stream[sindex].evp_client, in, blocksize);
            if (pad != 0) {
                ssl_debug_printf("ssl_decrypt_record failed: failed to set IV: %s %s\n",
                        gcry_strsource (pad), gcry_strerror (pad));
            }

            inl -= blocksize;
            in += blocksize;

       // printf("MODE_CBC ......maclen=%d......inl=%d\n",maclen,inl);

        /* Encrypt-then-MAC for (D)TLS (RFC 7366) */
        /*
        if (ssl->state & SSL_ENCRYPT_THEN_MAC) {
      
            if (inl < maclen) {
                ssl_debug_printf("%s failed: input %d has no space for MAC %d\n",
                                 G_STRFUNC, inl, maclen);
                return -1;
            }
            inl -= maclen;
            mac = (guint8 *)in + inl;
            mac_frag = (guint8 *)in - blocksize;
            mac_fraglen = blocksize + inl;
        }*/
    }


ssl_print_data("Encrypt In", in, inl);
 if ((pad = ssl_cipher_decrypt(&ssl_stream[sindex].evp_client, out, outl, in, inl))!= 0) {
        ssl_debug_printf("wmk_decrypt failed: ssl_cipher_decrypt: %s %s\n", gcry_strsource (pad),
                    gcry_strerror (pad));
        return 0;
    }
 if(debug_mode)
 {
	printf("wmk_decrypt ok..............");
	fflush(ssl_debug_file);
 }
ssl_print_data("PlaintextOut", out, outl);

return 1;
}


