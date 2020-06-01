

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */
#ifndef __WWW_FILES_H__
#define __WWW_FILES_H__

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/dir.h>
#include "hashmap.h"
#include "httpx.h"

Hashmap hash_white_url,hash_black_url;
static int if_find = 1;

#define BLACK_RULEID 101
#define NO_WWWFILE_RULEID 102



int read_one_line(char *buf, int len, FILE *fp)
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

void read_white_url(char *dir)
{
	FILE *fp = NULL;
    char filename[256],line[256],*p;
    int len,i;

	snprintf(filename,sizeof(filename)-1,"%s/white_url.data",dir);
    fp = fopen(filename,"r");
    if(!fp)    return;
	while (read_one_line(line, sizeof(line)-1, fp))
	{
		p = line;
		 /* ignore whitespace */
        while(isspace(*p) && *p != '\0')
			p++;    
		if (*p == '\0')
			continue;
		if (*p == '#')
			continue;
		len = strlen(p); 
		for (i = 0; i < len; i++)
		    p[i] = tolower(p[i]);	
		hashmap_put(&hash_white_url, p, 0,p, 0);
	}	

	fclose(fp);

	//hashmap_dump(&hash_white_url);

}


void read_black_url(char *dir)
{
	FILE *fp = NULL;
    char filename[256],line[256],*p;
    int len,i;

	snprintf(filename,sizeof(filename)-1,"%s/black_url.data",dir);
    fp = fopen(filename,"r");
    if(!fp)    return;
	while (read_one_line(line, sizeof(line)-1, fp))
	{
		p = line;
		 /* ignore whitespace */
        while(isspace(*p) && *p != '\0')
			p++;    
		if (*p == '\0')
			continue;
		if (*p == '#')
			continue;
		len = strlen(p); 
		for (i = 0; i < len; i++)
		    p[i] = tolower(p[i]);	
		hashmap_put(&hash_black_url, p, 0,p, 0);
	}	

	fclose(fp);

	//hashmap_dump(&hash_black_url);

}

int find_white_url(char *url,http_waf_msg *req)
{
	if(hashmap_get(&hash_white_url,url,0))
	{
		
		req->white_url = 1;
		return 1;
	}


	return 0;
}


int find_black_url(char *url,http_waf_msg *req)
{
	if(hashmap_get(&hash_black_url,url,0))
	{
		
		snprintf(http_log_msg,sizeof(http_log_msg)-1,"Black URL");
		req->black_url = 1;
		req->log_msg     = http_log_msg;
		req->rule_id     = BLACK_RULEID;
		
		return 1;
	}


	return 0;
}


int find_www_file(char *filename,http_waf_msg *req)
{
	if(1 == find_white_url(filename,req))
		return 1;
	if(1 == find_black_url(filename,req))
		return 1;


	return 0;
}

	
void read_www_files(char *dirname)
{
	int len = 0 ,off = 0;
	char *p,*dir;

	hashmap_open(&hash_white_url, 509);
	hashmap_open(&hash_black_url, 509);


    dir = dirname;

	if(dir == NULL)
	{
		if_find = 0;
		return;
	}
	
	len = strlen(dir);

    if (len < 2)
        return;

  
	
	
}



#endif


