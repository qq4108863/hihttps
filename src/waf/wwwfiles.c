

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

Hashmap hash_files,hash_white_url,hash_black_url;
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




int read_file_list(char *basePath,int len)
{
    DIR *dir;
    struct dirent *ptr;
    char base[1024],filename[1024];
	int i;

    if ((dir=opendir(basePath)) == NULL)
    {
        perror("Open dir error...");
        return 0;
    }

    while ((ptr=readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0)    ///current dir OR parrent dir
            continue;
        else if(ptr->d_type == 8)    ///file
        {
          
			 snprintf(filename,1000,"%s/%s",basePath + len,ptr->d_name);
			 //printf("		%s\n",filename);
			 
			 for (i = 0; i < strlen(filename); i++)
    			filename[i] = tolower(filename[i]);			
			 hashmap_put(&hash_files, filename, 0,filename, 0);
			
        }
        else if(ptr->d_type == 10)    ///link file
            printf("link file d_name:%s%s\n",basePath,ptr->d_name);
        else if(ptr->d_type == 4)    ///dir
        {
            memset(base,'\0',sizeof(base));
            strcpy(base,basePath);
            strcat(base,"/");
            strcat(base,ptr->d_name);
			//printf("	%s\n",base + len);			
            read_file_list(base,len);
			
			for (i = 0; i < strlen(base); i++)
    			base[i] = tolower(base[i]);
			hashmap_put(&hash_files, base + len, 0,base + len, 0);
			strcat(base,"/");
			hashmap_put(&hash_files, base + len, 0,base + len, 0);
        }
    }
    closedir(dir);
    return 1;
}

int find_white_url(char *url,http_waf_msg *req)
{
	if(hashmap_get(&hash_white_url,url,0))
	{
		//printf("find_white_url =%s\n",url);
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
		//printf("%s find_black_url =%s\n",req->log_msg,url);
		return 1;
	}


	return 0;
}


int find_www_file(char *filename,http_waf_msg *req)
{
	if(1 == find_white_url(filename,req))
		return 0;
	if(1 == find_black_url(filename,req))
		return 0;

	if(if_find == 0)
		return 0;
	if(!hashmap_get(&hash_files,filename,0))
	{
		
		snprintf(http_log_msg,sizeof(http_log_msg)-1,"URL file not exist in www dir.");
		req->no_www_file = 1;
		req->log_msg     = http_log_msg;
		req->rule_id     = NO_WWWFILE_RULEID;
		return 1;
	}


	return 0;
}

	
void read_www_files(char *dir)
{
	int len;
	char *p;

	hashmap_open(&hash_white_url, 509);
	hashmap_open(&hash_black_url, 509);
	hashmap_open(&hash_files, 65521);	
	hashmap_put(&hash_files, "/", 0,"/", 0);
	

	if(dir == NULL)
	{
		if_find = 0;
		return;
	}
	
	len = strlen(dir);
	p = dir + len -1;
	
	if(*p == '\\')
		*p = '\0';
	
	if(*p  == '/')
		*p = '\0';
	
	read_file_list(dir,len);
	printf("DIR %s,Total file numbers =%d\n",dir,((Hashmap *)&hash_files)->used_slots);
	//hashmap_dump(&hash_files);
	
	
}



#endif


