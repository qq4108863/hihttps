#include <assert.h>
#include <stdio.h>
#include <stdlib.h>	
#include <string.h>	
#include "base64.h"
		
// base64 tables	
static char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";	
#define CHAR64(c)  (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])

	
static signed char index_64[128] = {	
	    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,	
	    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,	
	    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,	
	    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,	
	    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,	
	    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,	
	    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,	
	    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1	
} ;
	
char *base64_encode(const unsigned char *value, int vlen) {
	unsigned char oval = 0 ; 	
        char *result = (char *)malloc((vlen * 4) / 3 + 5) ;	
        char *out = result;	
	while (vlen >= 3) {	
        	*out++ = basis_64[value[0] >> 2];	
        	*out++ = basis_64[((value[0] << 4) & 0x30) | (value[1] >> 4)];	
        	*out++ = basis_64[((value[1] << 2) & 0x3C) | (value[2] >> 6)];	
        	*out++ = basis_64[value[2] & 0x3F];	
        	value += 3;	
       		vlen -= 3;	
    	}
	if (vlen > 0) {	
	        *out++ = basis_64[value[0] >> 2];	
	        oval = (value[0] << 4) & 0x30 ;	
	        if (vlen > 1) oval |= value[1] >> 4;	
	        *out++ = basis_64[oval];	
	        *out++ = (vlen < 2) ? '=' : basis_64[(value[1] << 2) & 0x3C];	
	        *out++ = '=';	
	}	
	*out = '\0';		
	return result;	
}	

unsigned char *base64_decode(const char *value, int *rlen)	
{		
	int c1, c2, c3, c4;	        	
        int vlen = strlen(value);	
	unsigned char *result =(unsigned char *)malloc((vlen * 3) / 4 + 1);	
	unsigned char *out = result;	
	
	*rlen = 0;
	
	while (1) {	
		if (value[0]==0) {
			*out = '\0' ; 
			return result;	
		}
	        c1 = value[0];	
                if (CHAR64(c1) == -1) goto base64_decode_error;
	             c2 = value[1];	
	             if (CHAR64(c2) == -1) goto base64_decode_error;
	             c3 = value[2];	
	             if ((c3 != '=') && (CHAR64(c3) == -1)) goto base64_decode_error;
	             c4 = value[3];	
	             if ((c4 != '=') && (CHAR64(c4) == -1)) goto base64_decode_error;	
                     value += 4;	
	             *out++ = (CHAR64(c1) << 2) | (CHAR64(c2) >> 4);	
	             *rlen += 1;	
	             if (c3 != '=') {	
	             	*out++ = ((CHAR64(c2) << 4) & 0xf0) | (CHAR64(c3) >> 2);	
	                *rlen += 1;	
	                if (c4 != '=') {	
	                	*out++ = ((CHAR64(c3) << 6) & 0xc0) | CHAR64(c4);	
	                        *rlen += 1;	
	                }
	             }	
	}	
	base64_decode_error:	
	        *result = 0;	
	        *rlen = 0;	
	        return result;	
}

const char HEX2DEC[256] = 
{
    /*       0  1  2  3   4  5  6  7   8  9  A  B   C  D  E  F */
    /* 0 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 1 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 2 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 3 */  0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,
    
    /* 4 */ -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 5 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 6 */ -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 7 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    
    /* 8 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 9 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* A */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* B */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    
    /* C */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* D */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* E */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* F */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
};
    
/*void uri_decode(const char * psrc, const int len, char * pres, int * plen)
{
    // Note from RFC1630:  "Sequences which start with a percent sign
    // but are not followed by two hexadecimal characters (0-9, A-F) are reserved
    // for future extension"
    const int SRC_LEN = len ; 
    const unsigned char * const SRC_END = psrc + SRC_LEN ;
    const unsigned char * const SRC_LAST_DEC = SRC_END - 2;   // last decodable '%' 

    char * const pstart = (char *)malloc(SRC_LEN) ;
    char * pend = pstart ;

    while (psrc < SRC_LAST_DEC) {
       if (*psrc == '%') {
            char dec1, dec2;
            if (-1 != (dec1 = HEX2DEC[*(psrc + 1)])
                && -1 != (dec2 = HEX2DEC[*(psrc + 2)]))  {
                *pend++ = (dec1 << 4) + dec2;
                psrc += 3;
                continue;
            }
        }
        *pend++ = *psrc++;
    }

    // the last 2- chars
    while (psrc < SRC_END) *pend++ = *psrc++;
    *plen = (pend - pstart) ; 
    memcpy(pres, pstart, *plen) ; 
    free(pstart) ;
}*/

// Only alphanum is safe.
char SAFE[256] =
{
    /*      0 1 2 3  4 5 6 7  8 9 A B  C D E F */
    /* 0 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 1 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 2 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 3 */ 1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0,
    
    /* 4 */ 0,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
    /* 5 */ 1,1,1,1, 1,1,1,1, 1,1,1,0, 0,0,0,0,
    /* 6 */ 0,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
    /* 7 */ 1,1,1,1, 1,1,1,1, 1,1,1,0, 0,0,0,0,
    
    /* 8 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 9 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* A */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* B */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    
    /* C */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* D */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* E */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* F */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};

/*void uri_encode(const char * psrc, const int len, char * pres, int * plen)
{
    
    const char DEC2HEX[16 + 1] = "0123456789ABCDEF";
    const int SRC_LEN = len ; 
    unsigned char * const pstart = (unsigned char *)malloc(SRC_LEN * 3) ;
    unsigned char * pend = pstart;
    const unsigned char * const SRC_END = psrc + SRC_LEN;
    for (; psrc < SRC_END; ++psrc) {
       if (SAFE[*psrc]) {
	*pend++ = *psrc;
       } else {
            // escape this char
            *pend++ = '%';
            *pend++ = DEC2HEX[*psrc >> 4];
            *pend++ = DEC2HEX[*psrc & 0x0F];
       }
    }
    *plen = pend - pstart ; 
    memcpy(pres, pstart, *plen) ; 
    free(pstart) ;
}*/

/*int main(int argc, char * argv[]) 
{
  char s1[] = "http://www.google.com"; 
  int len1 = strlen(s1) ; 
  char s2[100] ; 
  int len2 = 0 ; 
  char s3[100] ; 
  int len3 = 0 ; 
  char * pbase64 = NULL ; 
  int len_base64 = 0 ; 
  char * pbase64_dec = NULL ; 
  int len_base64_dec = 0 ; 
  
  memset(s2, 0, sizeof(s2)) ; 
  memset(s3, 0, sizeof(s3)) ;  
  
  printf("original : %s\n", s1) ; 
  uri_encode(s1, len1, s2, &len2) ; 
  printf("uri encode : %s\n", s2) ;
  pbase64 = base64_encode(s2, len2) ; 
  printf("base64 encode : %s\n", pbase64) ;
  len_base64 = strlen(pbase64) ; 
  pbase64_dec = base64_decode(pbase64, &len_base64_dec) ; 
  printf("base64 decode : %s\n", pbase64_dec) ;
  uri_decode(pbase64_dec, len_base64_dec, s3, &len3) ; 
  printf("uri decode : %s\n", s3) ; 
  return 0 ; 
}*/
