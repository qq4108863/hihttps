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
 * http://www.hihttps.com
 */




#include <sys/dir.h>
#include <math.h>
#include "machine-learning.h"
#include "ngx_crc32.h"
#include "gemm.h"
#include "matrix.h"
#include "cnn.h"
#include "word2vec.h"
#include "../waf/hashmap.h"







#define MAX_TRAIN_SAVE           2048
#define MAX_TRAIN_SIZE           8192

#define MAX_NAME_LEN             128
#define MAX_VALUE_LEN            1024

#define MAX_PARAM_NUM            256

#define MAX_TRAIN_SAMPLE         1000
#define MIN_TRAIN_SAMPLE         500

#define SAVE_TRAIN_TIMEOUT       300




#define TRAIN_TOKEN              "\r\nHI"
#define STR_HTTP_MT_GET          "_GET_"
#define STR_HTTP_MT_POST         "_POST_"
#define INT_HTTP_MT_POST         8


static  u_char                     *delim = ".\0";
static  char                     GAN_FILE[256],TRAIN_LOG_DIR[256];



static int                      g_http_mt    = 0;
static uint32_t                 g_count_file = 0;
static ngx_open_file_cache_t    *cache;
static unsigned char            g_save_train[MAX_TRAIN_SAVE][MAX_TRAIN_SIZE + 128];
static ngx_list_t               *g_train_list = NULL;
static char                     filename[1024];

FILE                            *fp_train = NULL;
Hashmap                          hash_ip_urls;




static long long max_size = 256;         // max length of strings
static long long N = 3;                  // number of closest words that will be shown
static long long max_w = 50;              // max length of vocabulary entries






ngx_int_t
ai_json_array(ai_json_t *js);

ngx_int_t
ai_json_obj(ai_json_t *js);



static void
ngx_open_file_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t       **p;
    ngx_cached_open_file_t    *file, *file_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            file = (ngx_cached_open_file_t *) node;
            file_temp = (ngx_cached_open_file_t *) temp;

            p = (ngx_strcmp(file->name, file_temp->name) < 0)
                    ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_cached_open_file_t *
ngx_open_file_lookup(ngx_open_file_cache_t *cache, ngx_str_t *name,
    uint32_t hash)
{
    ngx_int_t                rc;
    ngx_rbtree_node_t       *node, *sentinel;
    ngx_cached_open_file_t  *file;

    node = cache->rbtree.root;
    sentinel = cache->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        file = (ngx_cached_open_file_t *) node;

        rc = ngx_strcmp(name->data, file->name);

        if (rc == 0) {
            return file;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}



ngx_int_t
ngx_insert_file(ngx_open_file_cache_t *cache,ngx_str_t *name,uint32_t      hash)
{
    ngx_cached_open_file_t           *file;

    
    file = ngx_alloc(sizeof(ngx_cached_open_file_t));
    if (file == NULL) {
            return NGX_ERROR;
    }
    
    file->name = ngx_alloc(name->len + 1);

    if (file->name == NULL) {
        ngx_free(file);
        file = NULL;
        return NGX_ERROR;
    }

    ngx_cpystrn(file->name, name->data, name->len + 1);

    file->node.key   = hash;
    file->uses       = 0;
    file->offset     = 0;
    file->gan        = 0;
    file->num        = 0;
    file->accessed   = 0;
    memset(&file->uri_rule, 0, sizeof(ai_http_rule_t));
    file->args_rule  = NULL;
    file->vocab      = NULL;
    file->words      = 0;
    
    g_count_file++;    
    if (g_count_file < MAX_TRAIN_SAVE)
        file->uses   = g_count_file;

    ngx_rbtree_insert(&cache->rbtree, &file->node);
    
    return NGX_OK;
}


ngx_uint_t last_key = 0 ,count_key = 0;


static void 
inorder(ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t       *sentinel;
    
    sentinel = cache->rbtree.sentinel;
    
    if(node != sentinel)
    {
          
        inorder(node->left);
      

        count_key++; 
        

        last_key = node->key;
        
        inorder(node->right);
    }

}

void 
inorder_rbtree(ngx_rbtree_t *rbtree) 
{
    if (rbtree)
        inorder(rbtree->root);
}    

/*
 * 打印"红黑树"
 *
 * tree       -- 红黑树的节点
 * key        -- 节点的键值 
 * direction  --  0，表示该节点是根节点;
 *               -1，表示该节点是它的父结点的左孩子;
 *                1，表示该节点是它的父结点的右孩子。
 */
static void 
rbtree_print(ngx_rbtree_node_t *node, ngx_rbtree_key_t key, int direction)
{
    if(node != NULL)
    {
        if(direction==0)    // tree是根节点
            printf("%u(B) is root\n", node ->key);
        else                // tree是分支节点
            printf("%u(%s) is %u's %6s child\n", node ->key, ngx_rbt_is_red(node)?"R":"B", key, direction==1?"right" : "left");
 
        rbtree_print(node ->left, node ->key, -1);
        rbtree_print(node ->right,node ->key,  1);
    }
}
 
void 
print_rbtree(ngx_rbtree_t *rbtree)
{
    if (rbtree != NULL && rbtree->root != NULL)
        rbtree_print(rbtree->root, rbtree->root->key, 0);

}


/*
 * 销毁红黑树
 */
static void rbtree_destroy(ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t       *sentinel;
    
    sentinel = cache->rbtree.sentinel;
    
    if(node != sentinel) {

         rbtree_destroy(node->left);
         rbtree_destroy(node->right);
         free(node);
    }


    return;
        

    if (node == NULL)
        return ;
 
    if (node->left != NULL)
        rbtree_destroy(node->left);
    if (node->right != NULL)
        rbtree_destroy(node->right);
 
    free(node);
}
 
void destroy_rbtree(ngx_rbtree_t *rbtree)
{
    if (rbtree != NULL)
        rbtree_destroy(rbtree->root);
 
    free(rbtree);

}



//插入排序  从小到大
void node_sort_big(ngx_uint_t *a,int len) 
{ 
   int i,j;
   ngx_uint_t temp;
   
  for(i = 1;i < len;i++)
  { 
     j = i-1; 
      
     temp = a[i];//需要插入的数据 
    
      
    while(temp < a[j] && j >= 0)//当插入的数据小于前面的数据时 
    { 
      a[j+1] = a[j];//将插入的数据的前面的数据向后移动 
          
      j--; 
    } 
  
    a[++j] = temp;//插入数据 

  } 

/*
  printf("node_sort_big:");
  for (i = 0; i < len; i++)  {
    printf("%d--",a[i]);
    }
  printf("\n");*/
} 


void node_sort_small(double *a,int len) 
{ 
   int i,j;
   double temp;
   
  for(i = 1;i < len;i++)
  { 
     j = i-1; 
      
     temp = a[i];//需要插入的数据 
    
      
    while(temp > a[j] && j >= 0)//当插入的数据小于前面的数据时 
    { 
      a[j+1] = a[j];//将插入的数据的前面的数据向后移动 
          
      j--; 
    } 
  
    a[++j] = temp;//插入数据 

  } 
} 

static size_t
parse_number(ngx_str_t * sf)
{
  
    const char *cs = sf->data;
    const size_t slen = sf->len;
    size_t pos = 0;
 


    while (pos < slen && ISDIGIT(cs[pos])) {
        pos += 1;
    }

    if (pos == slen) {        
        return 1;  
     }
    else
        return 0;
}

static void
calc_gauss_sigma2(ngx_uint_t *a,ngx_uint_t max,ngx_uint_t min,int line,ngx_cached_open_file_t  *file)
{
    double                 sum   = 0;
    double                 mean  = 0;
    double                 var   = 0;
    double                 sigma = 0; 
    int                    i,total = 0;

    for (i = 0 ;i < line ;i++) {             
        if (i >= MAX_TRAIN_SAMPLE)
            break;
         if (a[i] < min || a[i] > max)
            continue;
         
         sum += a[i];
         total++;

    }

    if (total < MIN_TRAIN_SAMPLE) 
        return;

    mean = sum / total; //求平均值


    for (i = 0 ;i < line ;i++) {             
        if (i >= MAX_TRAIN_SAMPLE)
            break;
         if (a[i] < min || a[i] > max)
            continue;
         
         var += pow(a[i] - mean,2);

    }


    var /= total; //求方差

    sigma = pow(var,0.5);//求标准差

    if (sigma < 1.0) sigma = 1.0;
    
    file->uri_rule.mean  = mean;
    file->uri_rule.sigma = sigma;
    file->uri_rule.num   = total;
   

}

double 
calc_gauss_sigma(ngx_train_node_t       *lnode)
{
    double                 sum   = 0;
    double                 mean  = 0;
    double                 var   = 0;
    double                 sigma = 0; 
    int                    i,total = 0;

    ngx_train_node_t       *node;
    ngx_uint_t             max,min,count,param[MAX_TRAIN_SAMPLE];
    
    node = lnode;
    while (node != NULL) {        
        if (total >= MAX_TRAIN_SAMPLE)
            break;
        param[total]= node->len; //求和
        total++; 
        node = node ->next;
    }

    if (total < MIN_TRAIN_SAMPLE) 
        return 0;

    
    node_sort_big(param,total);
    i    = (total * 93 / 100) - 1; //printf(" total=%d imax=%d ",total,i);
    max  = param[i];
    i    = (total * 3 / 100)  + 1;// printf("imin=%d  ",i);
    min  = param[i];              //printf("max=%d  min=%d\n",max,min);
    

    total = 0;
    node  = lnode;
    while (node != NULL) {  
        
        if (node->len >= min && node->len <= max) {            
            sum += node->len; //求和
            total++;
        }
        
        node = node ->next;
    }

     if (total < MIN_TRAIN_SAMPLE) 
        return 0;
    
    mean = sum / total; //求平均值

    node = lnode;
    while (node != NULL) {   
        
        if (node->len >= min && node->len <= max) {  
            var += pow(node->len - mean,2);
        }
        
        node = node ->next;
    }

    var /= total; //求方差

    sigma = pow(var,0.5);//求标准差

    if (sigma < 1.0) sigma = 1.0;
    
  
    return sigma;
}


double 
calc_gauss_mean(ngx_train_node_t       *lnode)
{
    double                 sum   = 0;
    double                 mean  = 0;
    double                 var   = 0;
    double                 sigma = 0; 
    int                    i,total = 0;

    ngx_train_node_t       *node;
    ngx_uint_t             max,min,count,param[MAX_TRAIN_SAMPLE];
    
    node = lnode;
    while (node != NULL) {        
        if (total >= MAX_TRAIN_SAMPLE)
            break;
        param[total]= node->len; //求和
        total++; 
        node = node ->next;
    }

    if (total < MIN_TRAIN_SAMPLE) 
        return 0;

    
    node_sort_big(param,total);
    i    = (total * 93 / 100) - 1; 
    max  = param[i];
    i    = (total * 3 / 100)  + 1;
    min  = param[i];             
    

    total = 0;
    node  = lnode;
    while (node != NULL) {  
        
        if (node->len >= min && node->len <= max) {            
            sum += node->len; //求和
            total++;
        }
        
        node = node ->next;
    }

     if (total < MIN_TRAIN_SAMPLE) 
        return 0;
    
    mean = sum / total; //求平均值

    return mean;
}

ngx_uint_t
calc_dim_number(ngx_train_node_t       *lnode) 
{
    ngx_train_node_t        *node;
    ngx_uint_t              ret = 0 ,total = 0;
    ngx_str_t               val;


    node = lnode;
    while (node != NULL) {        
        if (total >= MAX_TRAIN_SAMPLE)
            break;
        val.data = node->data;
        val.len  = node->len; 

        ret = parse_number(&val);
        if (0 == ret)
            return 0;
        
        total++; 
        node = node ->next;
    }

    return ret;

}




ngx_train_node_t *
node_insert(ngx_str_t *val)
{
    ngx_train_node_t *new_node = calloc(1,sizeof(ngx_train_node_t));

    if (new_node == NULL)
        return NULL;
    
    new_node->data = val->data;
    new_node->len  = val->len;
    new_node->next = NULL;


    return new_node;
}

ngx_list_t *
list_insert(u_char *val)
{
    ngx_list_t *new_list = calloc(1,sizeof(ngx_list_t));

    if (new_list == NULL)
        return NULL;
    
    new_list->data = val;
    new_list->next = NULL;
    new_list->num  = 0;


    return new_list;
}





static void 
print_train_list_head(void)
{
    ngx_list_t               *l;
    ngx_train_node_t         *node;

    printf("print_train_list_head:");
    l = g_train_list;
    while (l != NULL) {
        if (l->data)    
           printf("%s==>",l->data);
        l = l->next;
    }
    printf("\n");    



}


static void 
calc_train_list(void)
{
    ngx_list_t               *l;
    ngx_train_node_t         *node;
    ngx_int_t                 count; 

  
    
    l = g_train_list;
    while (l != NULL) {
       

        node = l->node;
        count = 0;
        while (node != NULL) {
                    
           node = node ->next;
           count ++;
        }
    
        

        l->sigma      =  calc_gauss_sigma(l->node);
        l->mean       =  calc_gauss_mean(l->node);
        l->is_number  =  calc_dim_number(l->node);
        
        l = l->next;
    }
    

}

static void 
ngx_train_list_insert(ngx_str_t *n,ngx_str_t *v)
{
    ngx_list_t               *l,*plist;
    ngx_train_node_t         *node,*pnode;
    ngx_uint_t               found = 0;
    ngx_str_t                name,val;

    
    name.len  =  n->len;
    name.data =  ngx_alloc(n->len + 1);
    if (name.data == NULL) {
        return;
    }

    val.len  =  v->len;
    val.data =  ngx_alloc(v->len + 1);
    if (val.data == NULL) {
        free(name.data);
        return;
    }
    

    ngx_cpystrn(name.data, n->data, n->len + 1);
    ngx_cpystrn(val.data,  v->data, v->len + 1);

    l = g_train_list;

   
    /*
    aaaaa--->(NULL)
      |              
    node1        
    */
    if (l->data == NULL) {
        l->node = node_insert(&val);    
        if(l->node == NULL)
            return;
        l->data = name.data;
        l->num++;
   
        return;
    }
        
    while (l != NULL && l->data != NULL) {

        if (0 == ngx_strcmp(name.data, l->data)) {
          
            found = 1;
            break;

        }            
            
        l = l->next;
    }
    
    /*
    aaaaa--->(NULL)bbbb(list_insert)
      |              | 
    node1         node_insert
    */
    if (!found) {

        l = list_insert(name.data);
        if (l == NULL)
            return;        
        l->node = node_insert(&val);    
        if (l->node == NULL) {
            free(l);
            return;
        }
        l->num++;

        plist = g_train_list;
        while (plist->next != NULL) {
            plist = plist->next;
        }
        plist->next = l;
        
       
    }

    /*
    aaaaa--------->bbbb---->....
      |              | 
    node1          node1
                     |
                 node_insert
    */
    
    else {
          
        node = node_insert(&val);
        if(node == NULL)
            return;
        l->num++;
        
        pnode = l->node;
        while (pnode->next != NULL) {
           pnode = pnode->next;
        }
        pnode->next = node;
 
    }
        
        


}



ngx_list_t *make_list()
{
    ngx_train_node_t *node,*end;

    ngx_list_t *n,*p,*l = calloc(1,sizeof(ngx_list_t));
    if(l == NULL)
        return NULL;
    l->num = 0;

    return l;

}

static void print_args_rule(ngx_cached_open_file_t         *file)
{
     int                    c = 0;
     ngx_list_t            *new_list,*l;

     if (file->uri_rule.num > MIN_TRAIN_SAMPLE)
        printf("\n**********URL param : mean=%g,sigma=%g sample_num=%d****************************************************\n",file->uri_rule.mean,file->uri_rule.sigma,file->uri_rule.num);
     l = file->args_rule;
     while (l != NULL) {
            c++;
            printf("********** %d name=%-32s,mean=%-8g,sigma=%-8g,num=%-8d,is_number=%d\n",c,l->data,l->mean,l->sigma,l->num,l->is_number);
            l = l->next;
     }
     
}

static void
ai_insert_args_rule(ngx_cached_open_file_t         *file,ngx_list_t *rule)
{
     int                   len;    
     ngx_list_t            *new_list,*l;

     
    if (rule->data == NULL)
        return;
    len = strlen(rule->data);
    if (len <= 0 || len > 65535)
        return;
    
    new_list = calloc(1,sizeof(ngx_list_t));
    if (new_list == NULL)
        return;

    
    new_list->data = ngx_alloc(len + 1);

    if (new_list->data == NULL) {
        ngx_free(new_list);
        new_list = NULL;
        return;
    }

    ngx_cpystrn(new_list->data, rule->data, len + 1);
    
    
    new_list->next  = NULL;
    new_list->num   = rule->num;
    new_list->mean  = rule->mean;
    new_list->sigma = rule->sigma;
    new_list->is_number = rule->is_number;
    

    if (file->args_rule == NULL) {
        file->args_rule = new_list;
        return;
   }    

    l = file->args_rule;
    while (l->next != NULL) {
            l = l->next;
    }
    l->next = new_list;

}
static void
generate_ai_rule(ngx_cached_open_file_t         *file)
{

    ngx_list_t                 *r,*rnext;
    


    r = file->args_rule;
    while (r != NULL) {
       rnext = r->next;
       if(r->data) 
           free(r->data);
       free(r);
       r = rnext;
    }
    file->args_rule = NULL;
    
    r = g_train_list;   
    while (r != NULL) {
       if(r->num > MIN_TRAIN_SAMPLE) {        
           ai_insert_args_rule(file,r); 
        }       
       r = r->next;
    }

  }

static void
free_list(void)
{
 
   ngx_list_t                 *l,*lnext;
   ngx_train_node_t         *node,*nnext;
   int cl = 0 ,cldata = 0,cn =0 ,cnode = 0;

 
   l = g_train_list;
   
   while (l != NULL) {
       lnext = l->next;
       
       if(l->data) {
          //printf("%s==>",l->data);
          free(l->data);
          cldata++;
        }
       
       node = l->node;    
       while (node != NULL) {
          nnext = node->next;
          if (node->data) {
             free(node->data);
             cnode ++;
          }
            
          free(node);cn++;
          node = nnext;        
       }
       
       free(l);     cl ++;  
       l = lnext;
   }

   g_train_list = NULL;
  


}


static void generate_word2vec(ngx_cached_open_file_t         *file)
{
    char in[256],out[256],*p;

    if (file->name == NULL)
        return;
    
    p = strrchr((char *)file->name,'/');
    if(p) 
        p++;
    else
        p = file->name;
    


    snprintf(in,sizeof(in) - 1,"%strain.txt",TRAIN_LOG_DIR);
    snprintf(out,sizeof(out) - 1,"./vector/%u_%s.bin",file->node.key,p);
    
    word2vec(in,out,MIN_TRAIN_SAMPLE / 2);
    


}


static void read_word2vec_dim(ngx_cached_open_file_t         *file)
{

    char *p;
    FILE *f;
    char st1[max_size];
    char *bestw[N];
    char file_name[max_size], st[100][max_size];
    float dist, len, bestd[N], vec[max_size];
    long long words, size, a, b, c, d, cn, bi[100];
    float *M;
    char *vocab;

    if (file->name == NULL)
        return;
    
    p = strrchr((char *)file->name,'/');
    if(p) 
        p++;
    else
        p = file->name;   
    snprintf(file_name,sizeof(file_name) - 1,"./vector/%u_%s.bin",file->node.key,p);

    f = fopen(file_name, "rb");
    if (f == NULL) {
      //printf("Input file not found\n");
      return ;
    }
    fscanf(f, "%lld", &words);
    fscanf(f, "%lld", &size);
    
    for (a = 0; a < N; a++) bestw[a] = (char *)malloc(max_size * sizeof(char));
    M = (float *)malloc((long long)words * (long long)size * sizeof(float));
    if (M == NULL) {
      printf("Cannot allocate memory: %lld MB    %lld  %lld\n", (long long)words * size * sizeof(float) / 1048576, words, size);
      return;
    }
    vocab = (char *)malloc((long long)words * max_w * sizeof(char));
    if (vocab == NULL) {

       free(M);
       return;
    }
    
    for (b = 0; b < words; b++) {
      a = 0;
      while (1) {
        vocab[b * max_w + a] = fgetc(f);
        if (feof(f) || (vocab[b * max_w + a] == ' ')) break;
        if ((a < max_w) && (vocab[b * max_w + a] != '\n')) a++;
      }
      vocab[b * max_w + a] = 0;
      for (a = 0; a < size; a++) fread(&M[a + b * size], sizeof(float), 1, f);
      len = 0;
      for (a = 0; a < size; a++) len += M[a + b * size] * M[a + b * size];
      len = sqrt(len);
      for (a = 0; a < size; a++) M[a + b * size] /= len;
    }
    fclose(f);
   
    free(M);

    file->vocab = vocab;
    file->words = (int)words;
    printf("         word2vec dim :%s word=%d\n",file_name,words);


}


static void
ai_insert_gan_rule(ngx_cached_open_file_t         *file,char *name,double mean,double sigma,int is_number)
{
     ngx_list_t            *new_list,*l;
     int                    len;

     if (name == NULL)
        return;
     len = strlen(name);
     
     if (len <= 0 || len > 65535)
             return;
         
     new_list = calloc(1,sizeof(ngx_list_t));
     if (new_list == NULL)
           return;
     
         
     new_list->data = ngx_alloc(len + 1);
     
     if (new_list->data == NULL) {
             ngx_free(new_list);
             new_list = NULL;
             return;
      }
     
      ngx_cpystrn(new_list->data, name, len + 1);
         
         
      new_list->next  = NULL;
      //new_list->num   = rule->num;
      new_list->mean  = mean;
      new_list->sigma = sigma;
      new_list->is_number = is_number;
     
      if (file->args_rule == NULL) {
             file->args_rule = new_list;
             return;
      }    
     
      l = file->args_rule;
      while (l->next != NULL) {
                 l = l->next;
       }
       l->next = new_list;


}


static void read_gan_rule(void) 
{
      u_char                   *buf,*p,*name;
      FILE                     *fp; 
      size_t                   fsize,total;
      unsigned short           len,msg_len,arg_len,name_len;
      uint32_t                 hash;
      double                   mean = 0,sigma = 0;
      ngx_str_t                uri_name;
      ngx_cached_open_file_t   *file;
      int                      count = 0 ,param_num = 0 ,is_number = 0; 

    //snprintf(filename,sizeof(filename) - 1,GAN_DIR"gan.rule");
    
    fp = fopen(GAN_FILE,"rb+");
    if (!fp)
        return;

    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    if (fsize < 16)
        goto end;

    //buf = calloc(1,fsize + 1);
    buf = calloc(1,fsize + 1);
    if(buf == NULL)
        goto end;
    fseek(fp, 0, SEEK_SET);
    fread(buf,fsize,1,fp);

    
    p = buf;
    total = 0;
   
    
    while(total < fsize) {
        p  = buf + total;
        if (memcmp(p,"--------------------",14) != 0) {
            printf("gan rules error \n");
            break;
        }
        
        /*fixed 14 + 2 total len + name + 16 reserve + URI param
         min 2 max 2 mean 8 sigma 8*/           
        len = 14;
        msg_len = 0;    
        memcpy(&msg_len, p + len ,2);
        msg_len = ntohs(msg_len);
       
        total += msg_len;
        if(total > fsize)
            break;

        /*URI*/ 
        len += 2;
        name = p + len;   
        name_len = strlen(name);
        len += name_len;
        
        len += 16;
        
        if ((msg_len - len) < 20)
            break;
        len += 2;  //min
        len += 2 ; //max
        memcpy(&mean,p + len ,sizeof(double));
        len += sizeof(double);
        memcpy(&sigma,p + len,sizeof(double));
        len += sizeof(double);

        count++;
      
        hash = ngx_crc32_long((u_char *)name, name_len);
        uri_name.data = name;
        uri_name.len  = name_len;

       // printf("%-8d URL=%-64s  mean=%-8g   sigma=%-8g  hash=%-16u  name_len=%-8d\n",count,name,mean,sigma,hash,name_len);

        file = ngx_open_file_lookup(cache, &uri_name, hash);
        if (file) {
           printf("   GAN RULE repeat %s .......ignore it\n",name);
           continue;
        }
        
        ngx_insert_file(cache,&uri_name, hash);
        
        file = ngx_open_file_lookup(cache, &uri_name, hash);
        if (file == NULL) {
           printf("read gan error .......\n");
           continue;
         }
        file->gan = 1;
        file->num = MAX_TRAIN_SAMPLE;

            
        file->uri_rule.mean  = mean;
        file->uri_rule.sigma = sigma; 
        
    #ifdef USE_WORD2VEC 
        read_word2vec_dim( file);
    #endif

       

        param_num = 0;
      
        /*ARGS node name 2 total len + name + 2 (00 00) +check 1  + must 1+ 12 reserve 
          + min 2  + max 2 + mean 8  + sigma 8 +dimention(16bytes)*/
        /*hehe dimention calc only for commercial version ,opensource not eq free,thanks*/
        
        while (len < msg_len) {
            arg_len = 0;
            memcpy(&arg_len, p + len ,2); 
            arg_len = ntohs(arg_len);
            if(arg_len <= 32 || arg_len >= msg_len)
                break;

            name = p + len + 2;
            len += 2;
            len += strlen(name);
            
            len += 2; // 00 00
            len += 1; //check
            len += 1; //must

            len += 12; //reserve

            len += 2; //min
            len += 2; //max
         
            memcpy(&mean,p + len ,sizeof(double));
            len += sizeof(double);
            memcpy(&sigma,p + len,sizeof(double));
            len += sizeof(double); 
            
            memcpy(&is_number,p + len,sizeof(is_number));
            len += sizeof(is_number);             

            len += 12 ; //dimention reduce 

            
            param_num++;
            //printf("         param:%-16d %-44s   mean=%-8g   sigma=%-8g  len=%-8d    number=%d\n",param_num,name,mean,sigma,len,is_number); 
            ai_insert_gan_rule(file, name,mean, sigma,is_number);
                      
            if ( (msg_len - len) < 32)
                break;
          
        }

        printf("\n");
         
        if(total == fsize)
            break;
    }


end:
      fclose(fp);
      
}

static void 
ai_gen_adv_net(ngx_cached_open_file_t         *file)
{
    char                     buf[16384];
    ngx_list_t                 *l,*lnext;
    short                    len,max_len,msg_len,node_len,write_len;
    FILE                     *fp; 
    
    if (!file->name)
        return;
    
    memset(buf, 0, sizeof(buf)); 
   
    
    msg_len = sizeof(buf) - 256;
    max_len = msg_len;

    memcpy(buf ,"--------------------", 14);
    len  = 14 + 2;
    len += snprintf(buf + len,max_len,"%s",file->name);
    max_len = msg_len - len;
    if (max_len <= 0) 
        return;

    /*fixed 14 + 2 total len + name + 16 reserve + URI param
      min 2 max 2 mean 8 sigma 8*/
    len += 16;   //00 00 ....reserve 16 bytes    
    len += 2;  //URI min param num
    len += 2;  //URI max param num    
    memcpy( buf + len,&file->uri_rule.mean,sizeof(file->uri_rule.mean)); //URI praram mean
    len += sizeof(file->uri_rule.mean);
    memcpy( buf + len,&file->uri_rule.sigma,sizeof(file->uri_rule.sigma)); //URI param sigma
    len += sizeof(file->uri_rule.sigma);
    
    /*node name 2 total len + name + 2 (00 00) +check 1  + must 1+ 12 reserve 
    + min 2  + max 2 + mean 8  + sigma 8 +dimention(16bytes)*/
    l = file->args_rule;
    while (l != NULL) {
       lnext = l->next;

       node_len = 0;
       write_len = len;
       len += 2;  /*total len*/     
       
       if(l->data) {  
          node_len += snprintf(buf + len,max_len,"%s",l->data);
          len += node_len;
          max_len = msg_len - len;
          if (max_len <= 0) 
             return;

          len += 2; // 00 00 
          len += 2;//if check and must
          node_len += 4 ;

          len += 12;//reserve

          len += 2;  //min value len
          len += 2;  //max value len 

          node_len += 16 ;

          memcpy( buf + len,&l->mean,sizeof(l->mean));//value mean
          node_len += sizeof(l->mean);
          len += sizeof(l->mean);
          max_len = msg_len - len;
          if (max_len <= 0) 
             return;

          memcpy( buf + len,&l->sigma,sizeof(l->sigma));//value sigma
          node_len += sizeof(l->sigma);
          len += sizeof(l->sigma);          
          max_len = msg_len - len;
          if (max_len <= 0) 
             return;


          memcpy( buf + len,&l->is_number,sizeof(l->is_number));//is_number
          node_len += sizeof(l->is_number);
          len += sizeof(l->is_number);          
          max_len = msg_len - len;
          if (max_len <= 0) 
             return;          

          len += 12; // dimenstion reduce ,feature 
          node_len += 12;

          node_len = ntohs(node_len);
          memcpy(buf + write_len, &node_len,2);

       }
          
       l = lnext;
    }

    write_len = 16 - len % 16;
    len += write_len;
    /*write len to head ,2bytes */
    len = ntohs(len);
    memcpy(buf + 14 , &len,2);
    len = ntohs(len);

     
    //snprintf(filename,sizeof(filename) - 1,GAN_DIR"gan.rule");
    
    fp = fopen(GAN_FILE,"ab+");
    if (!fp)
       return;
    
    fwrite(buf,1,len,fp);
    printf("GAN----------------------------------------GAN---------------------%s---------------%d bytes----------OK......................\n",file->name,len);
    fclose(fp);
    file->gan = 1;
}


void 
ai_file_train_init(char *exe_dir)
{
    
    char *dir = "/usr/share/nginx/html";
    ngx_cached_open_file_t         *file;
    char                            base[1024],filename[1024];
    uint32_t                        hash;
    ngx_str_t                       name;

    time_random_matrix(10, 20, 8, 16, 8);
    hashmap_open(&hash_ip_urls, 65521);	

    snprintf(GAN_FILE,sizeof(GAN_FILE) - 1,"%srules/gan.rule",exe_dir); /* /hihttps/rules/gan.rule*/
    snprintf(TRAIN_LOG_DIR,sizeof(TRAIN_LOG_DIR) - 1,"%strain/",exe_dir); /* /hihttps/train/ */

    

    if (ngx_crc32_table_init() != NGX_OK) {
        return;
    }

    cache = calloc(1,sizeof(ngx_open_file_cache_t));
    if (cache == NULL) {
        printf("cache memory error exit ...\n");
        exit(0);
        return;
     }    

     ngx_rbtree_init(&cache->rbtree, &cache->sentinel,
                    ngx_open_file_cache_rbtree_insert_value);

     read_gan_rule();  
     inorder_rbtree(&cache->rbtree);  
     //printf("TRAIN_LOG_DIR=%s   GAN_FILE=%s rbtree insert=%d total=%d\n",TRAIN_LOG_DIR,GAN_FILE,count_key,g_count_file); 

     return;

     
   
}


static char    *
strnchr(u_char *s, int c, int len)
{
  int    cpt;
  for (cpt = 0; cpt < len && s[cpt]; cpt++)
    if (s[cpt] == c) 
      return ((char *) s+cpt);
  return (NULL);
}


 ngx_int_t 
judge_if_format(u_char *begin,int len)
{
    u_char                *p;
    int                   off = 0;

    if (len < 4)
        return NGX_ERROR;  

    p = begin;
    while ((*p == ' '  || *p == '\t' || *p == '\n' || *p == '\r') && *p !='\0' && off < (len - 1) ) {
             off++;
             p++;
      }

    if( *p  != '{') {
      
         return NGX_ERROR;       
    }

    off = 0;
    p = begin + len - 1 ;
    while ((*p == ' '  || *p == '\t' || *p == '\n' || *p == '\r') && *p !='\0' && off < (len - 1) ) {
             off++;
             p--;
      }

    if( *p  != '}') {
       
         return NGX_ERROR;       
    }
    

    return NGX_OK;
}


/* if return count = 0 ,perhaps decode error ,such as json ,xml .... bug perhaps here */

static ngx_uint_t
analyse_train_param(u_char *begin,u_char *end,ngx_uint_t line,ngx_uint_t only_count)
{

    ngx_str_t              name, val;
    u_char                  *args,*eq, *ev, *orig,*str;
    int                      len, full_len,nullbytes = 0;
    ngx_uint_t            count = 0;

    args = begin;
    if (g_http_mt == INT_HTTP_MT_POST) {
       
        /* 0x00 add the end of the json */
        len = end - begin;
        if (len < 3) /* a=b */
            return 0;

        if (NGX_OK == judge_if_format(begin,len)) {
           return 0;
         }
    }  

    /*HTTP GET 
    else { 
        args = strchr(begin,'?'); 
        if (args)  args++; 
        else 
            args = begin;
    }   */
    
    
    str = args;
    orig = str;
    full_len = end - args;//strlen(orig);
    if(full_len <= 0)
        return;
    
    while (str < (orig+full_len) && *str) 
    {
        if (*str == '&') {            
          str++;
          continue;
        }
        eq = strchr(str, '=');
        ev = strchr(str, '&');
        
        if ((!eq && !ev) /*?foobar */ ||    (eq && ev && eq > ev)) /*?foobar&bla=test*/ 
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

        if (name.len > MAX_NAME_LEN) {
             printf("arg names too long-----------------------return--------------------%d\n",name.len);
            // str++;
             return 0;
        }

        if (val.len > MAX_VALUE_LEN) {
             printf("arg value too long-------------------return------------------------%d\n",val.len);
             //str++;
            return 0;
        }

        if (!only_count) {
        if (name.len) 
        {
              nullbytes = naxsi_unescape(&name);
              name.data[name.len] = '\0';
              //printf("line :%d   %d        name=%.32s                        ",line,name.len,name.data);
        }
        if (val.len) 
        {
              nullbytes = naxsi_unescape(&val);
              val.data[val.len] = '\0';
            //chk_all_rules(&val,ARGS,req);
              //printf("%d        value=%.32s \n",val.len,val.data);
        }
         
          //printf("\n");

        if(name.len &&  val.len) {
            ngx_train_list_insert(&name,&val);
            if(fp_train != NULL) {
               fprintf(fp_train, "%s ", name.data);
            }
           }
        }
        else { //only count
            
           if(name.len &&  val.len)
               count++;
        }

        str += len; 
        str++;

        
    }

     if(fp_train != NULL) {
         fprintf(fp_train, "\n");
     }
    
    return count;    
}



static int 
filter_train_http_line(u_char *buf,size_t fsize,ngx_cached_open_file_t         *file)
{
     
    u_char                         *p,*begin,*end;
    size_t                         total;
    int                            len,line,i; 
    ngx_uint_t                     max,min,count,param[MAX_TRAIN_SAMPLE];

    p = buf;
    total = 0;
    line  = 0;
    
    while(total < fsize) {
        p  = buf + total;
        if (memcmp(p,TRAIN_TOKEN,4) != 0) {
            printf("filter train_http_line:TRAIN_TOKEN error0 :%s\n",p);    
            return NGX_ERROR;            
        }
        
        len  = atoi(p + 4);
        if ( len <= 0 || len >= fsize) {
            printf("filter train_http_line:TRAIN_TOKEN error1 :%s\n",p);    
            return NGX_ERROR;
         }
        
        total += len;        
        total += 16;

        if (total > fsize)
            break;
        if (line >= MAX_TRAIN_SAMPLE)
            break;
        
        begin  = p + 16;
        end    = p + 16 + len - 1; 
        
        param[line] = analyse_train_param(begin,end,line,1);
        line++;
        

        if (total == fsize)
            break;

    }

    if (line <= 5)
        return NGX_ERROR;

    node_sort_big(param,line);
    i    = (line * 93 / 100) - 1; //printf("total_line =%d imax=%d ",line,i);
    max  = param[i];
    i    = (line * 3 / 100)  + 1; //printf("imin=%d  ",i);
    min  = param[i];             // printf("max=%d  min=%d\n",max,min);

    calc_gauss_sigma2(param,max,min,line,file);



/* mark the filter train samplse */
   p = buf;
   total = 0;
   line  = 0;
   while(total < fsize) {
       p  = buf + total;
       if (memcmp(p,TRAIN_TOKEN,4) != 0) {
           printf("filter train_http_line:TRAIN_TOKEN error3 :%s\n",p); 
           return NGX_ERROR;           
       }
       
       len    = atoi(p + 4);
       if ( len <= 0 || len >= fsize) {
           printf("filter train_http_line:TRAIN_TOKEN error4 :%s\n",p);    
           return NGX_ERROR;
        }
       
       total += len;        
       total += 16;

       if (total > fsize)
           break;
       if (line >= MAX_TRAIN_SAMPLE)
           break;
       
       begin  = p + 16;
       end    = p + 16 + len - 1;
       
       count = analyse_train_param(begin,end,line,1);
       line++;
       
       if(count > max ||  count < min) {
           p += 13;
           *p ='#';
           printf("line %d params=%d abnomal len=%d, fliter it..\n",line * 2,count,len);
       }
        
   

       if (total == fsize)
           break;

   }



    
    file->num = line;
   
    return NGX_OK;
}





static void 
decode_train_http_line(u_char *buf,size_t fsize)
{
    u_char                         *p,*begin,*end;
    size_t                         total;
    int                            len,line; 

    snprintf(filename,sizeof(filename) - 1,"%strain.txt",TRAIN_LOG_DIR);       
    fp_train = fopen(filename,"wb");

    p = buf;
    total = 0;
    line  = 0;
    while(total < fsize) {
        p = buf + total;
        if (memcmp(p,TRAIN_TOKEN,4) != 0) {
            printf("TRAIN_TOKEN error :%s\n",p);    
            break;
        }
        
        len    = atoi(p + 4);
        if ( len <= 0 || len >= fsize)
            break;
        
        total += len;        
        total += 16;

        if (total > fsize)
            break;
         if (line >= MAX_TRAIN_SAMPLE)
            break;
        
        begin  = p + 16;
        end    = p + 16 + len - 1;

        line++;
        
        p  += 13;
        if (*p != '#')
           (void)analyse_train_param(begin,end,line,0);
        else
            printf("line = %d is ##############,skip it \n",line * 2);
        
        

        if (total == fsize)
            break;

    }


    if(fp_train != NULL) {
          fclose(fp_train);
          fp_train = NULL;
    }


}


static void
read_train_http_file(u_char *name,uint32_t key,ngx_cached_open_file_t         *file)
{
    u_char                         *p,*buf;
    FILE                           *fp;
    size_t                         fsize;


    
    p = strrchr(name,'/');
    if (!p) return;
    p++;
    
    if (g_http_mt == INT_HTTP_MT_POST)
        snprintf(filename,sizeof(filename) - 1,"%s%u%s%s.txt",TRAIN_LOG_DIR,key,STR_HTTP_MT_POST,p);
    else
        snprintf(filename,sizeof(filename) - 1,"%s%u_%s%s.txt",TRAIN_LOG_DIR,key,STR_HTTP_MT_GET,p);
    
    fp = fopen(filename,"rb+");
    if (!fp)
        return;
    
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);

    //buf = calloc(1,fsize + 1);
    buf = malloc(fsize + 1);
    if(buf == NULL)
        goto end;
    fseek(fp, 0, SEEK_SET);
    fread(buf,fsize,1,fp);
    
    
    if (NGX_ERROR == filter_train_http_line(buf,fsize,file))
        goto end;
   
    g_train_list = make_list();
    if (g_train_list == NULL)
        goto end;
    
    decode_train_http_line(buf,fsize); 
    calc_train_list();
    generate_ai_rule(file); 
  #ifdef USE_WORD2VEC  
    generate_word2vec(file);
  #endif
   #ifdef USE_CNN 
   //fuck,cnn is too slow! 
  #endif
    free_list();
    //print_args_rule(file);
end:
   fclose(fp);
   if(buf) {
          //printf("fsize = %d buf = %s\n",fsize,buf);
       free(buf);
       }
 
}


static int judge_hash_url(uint32_t  hash, unsigned int ip) 
{
   char                 buf[64];
   int                  i;

   snprintf(buf,sizeof(buf) - 1,"%u%u",hash,ip);
   if(hashmap_get(&hash_ip_urls,buf,0))
      return NGX_ERROR;
   hashmap_put(&hash_ip_urls, buf, 0,buf, 0);
   
   i=((Hashmap *)&hash_ip_urls)->used_slots;
   if (i > 30000)	{
        hashmap_close(&hash_ip_urls);
		hashmap_open(&hash_ip_urls,65521);
   }
   
   return NGX_OK;
}


static void
save_train_http_file(ngx_cached_open_file_t         *file)
{
    u_char                         *p,*name,*data;
    FILE                           *fp;
    uint32_t                       key,len;
    time_t                         t; 


    name = file->name;
    data = g_save_train[file->uses];
    key  = file->node.key;
    len  = file->offset;
    
    if (len < 16)
        return;

    p = strrchr(name,'/');
    if (!p) return;

    p++;
   if (g_http_mt == INT_HTTP_MT_POST)
        snprintf(filename,sizeof(filename) - 1,"%s%u%s%s.txt",TRAIN_LOG_DIR,key,STR_HTTP_MT_POST,p);
    else
        snprintf(filename,sizeof(filename) - 1,"%s%u_%s%s.txt",TRAIN_LOG_DIR,key,STR_HTTP_MT_GET,p);
    
    fp = fopen(filename,"ab+");
    if (!fp)
        return;

    fwrite(data,1,len,fp);
   // printf("%u--%s---------------------------save ok............................\n",key,name);
    fclose(fp);

    time(&t);
    file->accessed = t;


}


/*******保存之前应该严格检查参数*********************************/
ngx_cached_open_file_t *
save_train_http_data(u_char *uri,u_char *data,int len,int method)
{
    u_char                         tmp[18];
    uint32_t                       hash;
    ngx_cached_open_file_t         *file;
    ngx_str_t                      name;
    ngx_uint_t                     param;
    time_t                         t;
    
    
    if (len < 1 || len > MAX_TRAIN_SIZE)
        return NULL; 

    if (method == INT_HTTP_MT_POST)
        g_http_mt = INT_HTTP_MT_POST;
    else
        g_http_mt = 0; //HTTP GET

    name.data = uri;
    name.len  = strlen(uri);

   

    hash = ngx_crc32_long(name.data, name.len );
    file = ngx_open_file_lookup(cache, &name, hash);

    if (file == NULL) {

        if (g_count_file >= MAX_TRAIN_SAVE)
            return NULL;
        
        (void)ngx_insert_file(cache,&name, hash);
        
        count_key = 0;
        inorder_rbtree(&cache->rbtree);
         
        return NULL;
    }

    
 
    
    if (file) {
        
       //printf("found %s %u use = %d offset = %d sample_num = %d \n",file->name,file->node.key,file->uses,file->offset,file->num);
        

        if (file->gan)
            return file;

        if (file->num > MAX_TRAIN_SAMPLE) {
            /*generative adversarial networks */
            ai_gen_adv_net(file); 
            file->num = 0;
            if(file->gan)
               return file;
        }
    
        
        if (file->uses > 0 && file->uses < MAX_TRAIN_SAVE) { 
        
             time(&t);
             if ((t - file->accessed) > SAVE_TRAIN_TIMEOUT) {
                  save_train_http_file(file);
                  file->accessed = t;
                  file->offset = 0;        
              }

/*
           if (NGX_ERROR == judge_hash_url(hash, req->saddr)) {       
               return NULL;
           }*/
           
            if ((file->offset + len + 20) >= MAX_TRAIN_SIZE) {
                save_train_http_file(file);
                file->offset = 0;    
                              
                if ((file->offset + len + 20) >= MAX_TRAIN_SIZE) 
                    return NULL;
            }

            if (file->num % MIN_TRAIN_SAMPLE == 0) {                
                save_train_http_file(file);
                file->offset = 0;    
            
                read_train_http_file(file->name,file->node.key,file);            
            }

         
            /*calc param num*/
            param = analyse_train_param(data,data + len,0,1);
            if(0 == param || param > MAX_PARAM_NUM )
                return NULL;
                        
            memset(tmp,0x20,sizeof(tmp));
            tmp[14] = 0x0d;
            tmp[15] = 0x0a;

            /* add end of 0x00 */
            snprintf(tmp,sizeof(tmp) - 1,TRAIN_TOKEN"%d",len + 1);            
        
            memcpy(g_save_train[file->uses] + file->offset,tmp,16);
            file->offset += 16;
            
            memcpy(g_save_train[file->uses] + file->offset,data,len);
            file->offset += len;

            g_save_train[file->uses][file->offset] = '\0';
            file->offset++;    
            
            file->num++;            
          
        }
        /*else {
             printf("file->uses =%d error\n",file->uses);

        }*/    
            
    }
    
    return NULL;

}

ngx_cached_open_file_t *
save_train_http_post_data(u_char *dir,u_char *filename,u_char *data,int len,http_waf_msg *req)
{
    u_char                      uri[1024];
    ngx_cached_open_file_t      *file = NULL;
    
    if(dir == NULL || filename == NULL)
        return NULL;

    snprintf(uri,sizeof(uri) - 1,"P%s/%s",dir,filename); 
         
    file = save_train_http_data(uri,data,len,INT_HTTP_MT_POST);
       
    return file;

}

ngx_cached_open_file_t *
save_train_mqtt_data(ngx_str_t *topic,ngx_str_t *payload,http_waf_msg *req)
{
    u_char                      uri[1024];
    ngx_cached_open_file_t      *file = NULL;
    
    if (topic->len > 1000 ||  topic->len < 1)
        return NULL;    

    snprintf(uri,topic->len + 2,"M/%s",topic->data); 
         
    file = save_train_http_data(uri,payload->data,payload->len,INT_HTTP_MT_POST);
       
    return file;

}






