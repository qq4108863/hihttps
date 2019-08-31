

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */
#ifndef __WWW_FILES_H__
#define __WWW_FILES_H__

#include "httpx.h"
	
void read_www_files(char *dir);

int find_www_file(char *filename,http_waf_msg *req);
void read_white_url(char *dir);
void read_black_url(char *dir);



#endif


