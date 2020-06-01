//  Copyright 2013 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.


#ifndef _HISIMHASH_H
#define _HISIMHASH_H
#include "../waf/hashmap.h"
#include "../waf/httpx.h"

#define SIMHASH_RULE_ID 105


Hashmap hash_files;

void init_simhash_from_atkfile(void);

void  check_simhash(char *val,char *sim_url,http_waf_msg *req);




#endif
