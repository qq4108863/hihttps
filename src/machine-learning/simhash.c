/*
 * Fowler/Noll/Vo hash
 *
 * FNV hashes are designed to be fast while maintaining a low
 * collision rate. The FNV speed allows one to quickly hash lots
 * of data while maintaining a reasonable collision rate.  See:
 *
 *   http://www.isthe.com/chongo/tech/comp/fnv/index.html
 *
 * for more details as well as other forms of the FNV hash.
 *
 */

#if defined(__i386__) || defined (__x86_64__)
#define FNV_AVOID_MUL 1
#else
#define FNV_AVOID_MUL 0
#endif

#include <sys/types.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>     
#include <unistd.h>

#include "simhash.h"

#include "../waf/ssl_array.h"
#include "../waf/wwwfiles.h"





/*TODO: make hamdist work outside GCC, sample code below (slower) */
#define hamdist(x, y) __builtin_popcountll((x)^(y))

#define FNV_INIT  ((uint64_t)0xcbf29ce484222325ULL)
#define FNV_PRIME ((uint64_t)0x100000001b3ULL)


inline static uint64_t fnv_pass(uint64_t hval, char octet)
{
	/* xor the bottom with the current octet */
	hval ^= (uint64_t) octet;

	/* multiply by the 64 bit FNV magic prime mod 2^64 */
	if (FNV_AVOID_MUL)
		hval += (hval << 1) + (hval << 4) + (hval << 5) +
			(hval << 7) + (hval << 8) + (hval << 40);
	else
		hval *= FNV_PRIME;

	return hval;
}

/*
 * fnv_64a_buf - perform a 64 bit Fowler/Noll/Vo FNV-1a hash on a buffer
 *
 * input:
 *	buf	- start of buffer to hash
 *	len	- length of buffer in octets
 *
 * @returns	64 bit hash as a static hash type
 */
inline static uint64_t fnv_buf(const char *buf, size_t len)
{
	const char *bp = buf;
	const char *be = bp + len;

	uint64_t hval = FNV_INIT;

	/*
	 * FNV-1a hash each octet of the buffer
	 */
	while (bp < be) {
		hval = fnv_pass(hval, *bp++);
	}

	return hval;
}


/*
 * fnv_64a_str - perform a 64 bit Fowler/Noll/Vo FNV-1a hash on a buffer
 *
 * input:
 *	buf	- start of buffer to hash
 *
 * @returns	64 bit hash as a static hash type
 */
inline static uint64_t fnv_str(const char *str)
{
	uint64_t hval = FNV_INIT;

	/*
	 * FNV-1a hash each octet of the string
	 */
	while (*str) {
		hval = fnv_pass(hval, *str++);
	}

	return hval;
}


#define SIMHASH_BIT 64


uint64_t sh_simhash(const char *tokens[], unsigned int length)
{
    float hash_vector[SIMHASH_BIT];
    memset(&hash_vector, 0, SIMHASH_BIT * sizeof(float));
    uint64_t token_hash = 0;
    uint64_t simhash = 0;
    int current_bit = 0 ,i,j;

    for(i=0; i<length; i++) {
        token_hash = fnv_buf(tokens[i], strlen(tokens[i]));
        for( j=SIMHASH_BIT-1; j>=0; j--) {
            current_bit = token_hash & 0x1;
            if(current_bit == 1) {
                hash_vector[j] += 1;
            } else {
                hash_vector[j] -= 1;
            }
            token_hash = token_hash >> 1;
        }
    }

    for(i=0; i<SIMHASH_BIT; i++) {
        if(hash_vector[i] > 0) {
            simhash = (simhash << 1) + 0x1;
        } else {
            simhash = simhash << 1;
        }
    }

    return simhash;
}


static char	*
strnchr(const char *s, int c, int len)
{
  int	cpt;
  for (cpt = 0; cpt < len && s[cpt]; cpt++)
    if (s[cpt] == c) 
      return ((char *) s+cpt);
  return (NULL);
}


static int read_line(char *buf, int len, FILE *fp)
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


static void split_args(char *args,char *url)
{

	ngx_str_t	name, val;
    char		*eq, *ev, *orig,*str;
	int		    len, full_len;
	int         nullbytes = 0,count = 0;

	str = args;
	orig = str;
    full_len = strlen(orig);
	while (str < (orig+full_len) && *str) 
	{
	    if (*str == '&') {			
	      str++;
	      continue;
	    }
		eq = strchr(str, '=');
    	ev = strchr(str, '&');
		
		if ((!eq && !ev) /*?foobar */ ||	(eq && ev && eq > ev)) /*?foobar&bla=test*/ 
		{		
		      if (!ev)
			  	ev = str+strlen(str);
		      /* len is now [name] */
		      len = ev - str;
		      val.data = (unsigned char *) str;
		      val.len = ev - str;
		      name.data = (unsigned char *) NULL;
		      name.len = 0;
    	}
		 /* ?&&val | ?var&& | ?val& | ?&val | ?val&var */
	    else if (!eq && ev) 
		{ 
	     
		      if (ev > str) /* ?var& | ?var&val */ 
			  {
				val.data = (unsigned char *) str;
				val.len = ev - str;
				name.data = (unsigned char *) NULL;
				name.len = 0;
				len = ev - str;
			  }
			  else /* ?& | ?&&val */ 
			  {
				val.data = name.data = NULL;
				val.len = name.len = 0;
				len = 1;
		      }
	    }
		else /* should be normal like ?var=bar& ..*/ 
		{
		      if (!ev) /* ?bar=lol */
			  	ev = str+strlen(str);
		      /* len is now [name]=[content] */
		      len = ev - str;
		      eq = strnchr(str, '=', len);
		      if (!eq) /*malformed url, possible attack*/
			  {	
				return ;
		      }
		      eq++;
		      val.data = (unsigned char *) eq;
		      val.len = ev - eq;
		      name.data = (unsigned char *) str;
		      name.len = eq - str - 1;
    	}

     
		if (val.len > 3) 
		{
      		nullbytes = naxsi_unescape(&val);
      		val.data[val.len] = '\0';
             hashmap_put(&hash_files, (char *)val.data, 0,url, 0);
            //printf("%s  ",val.data);

		}
      	

		str += len; 
		str++;

		
	}
	
	//printf("\n");
}



void  check_simhash(char *val,char *sim_url,http_waf_msg *req) {
    int dist ;
    char *url;

       
    if(url = (char *)hashmap_get(&hash_files,val,0)) {
        
        dist = hamdist(fnv_str(sim_url), fnv_str(url));

        // printf("found  val=%s url =%s  dist=%d\n",val,sim_url,dist);

        if (dist < 8 ) { 
    	      req->str_matched = sim_url;
    	      req->log_msg     = "simhash detect attack...";   
              req->rule_id     = SIMHASH_RULE_ID;
        }      
              
    }

    


}


void init_simhash_from_atkfile(void) {
    FILE *fp;
    char *p,*args ,line[2048],url[2048];
    int  len,i = 0;

    hashmap_open(&hash_files, 65521);	
	
  
    fp = fopen("./rules/webattack.txt","r");
    if(!fp)    return ; 

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
        if(len < 5 || len > 2000)
            continue;
        i++;

       
        
        sprintf(url,"%s",line);    
        args = NULL;
        p = strchr(line,'?');
        if(p) {
            args = p + 1;
            *p   = '\0';          
            split_args(args,url);
        }

        hashmap_put(&hash_files, line, 0,url, 0);
        

		
		
	}	

    fclose(fp);
  

    //hashmap_dump(&hash_files);

}
