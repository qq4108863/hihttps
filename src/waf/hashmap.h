#ifndef HASHMAP_H
#define HASHMAP_H

/*
  Written from scratch 2001-08-02 sandro@w3.org.
  W3C license
*/
/**
   The internal structure of an iter is only relevant inside routines
   which are provided data through an iter.  
**/
struct iter_s;

/**
   The second part of the iterator structure is a pointer to its reset
   function, which iter_reset will in-turn call, if non-zero.
**/
typedef void (iter_reset_function)(struct iter_s *iter);

struct iter_s {
    void *state;
    iter_reset_function *reset;
};
/**
   Declare as "iter" each iterator you want to use, in the caller's memory.  
   Be sure to initialize it to {0,0} like:
<pre>
   iter x = {0,0};
</pre>
**/
typedef struct iter_s iter;


/**
   An iterator can be reset at any time, and must be reset if
   iteration is abandoned before complete.  (Otherwise some
   implementations will hold onto resources.)
**/
/* void iter_reset(iter *i); */

/* 
   why do/while?  see Harbison/Steele p45 -- it works in more cases 
   but maybe we don't need it with this current if/then structure.
*/
/// Implement iter_reset as a macro
#define iter_reset(i) 				\
    if ((i)->state) {				\
	if ((i)->reset) (*((i)->reset))(i);	\
    } else {					\
	(i)->state = 0;				\
    }


//#include "iter.h"

/**
   Efficient HashMap For C, supporting variable length keys and
   values, null terminated or given-end-marker, with one malloc/free
   per entry.

   Performance is pretty linear and pretty fast.
**/

/**
   This is really a variable-size structure.  It starts with two
   pointers, which is all we declare here.  The first one points to
   the next entry in this hash-bucket.  The second one points to the
   first byte of the value data.  Between the end of the second
   pointer and the start of the value data is the key data.
**/
struct hashmap_entry {
    struct hashmap_entry *next_in_bucket;
    char *value;
};

struct hashmap {
    struct hashmap_entry **table;
    unsigned used_slots;
    short table_size_index;  /* 0 is the smallest table, 1 is step larger... */
	//int table_size_index;//by wangmk
};

typedef struct hashmap Hashmap;

/**
   The hashmap must be openned with this before it can be used. 
**/
void hashmap_open(Hashmap*, unsigned int initial_size);

/**
   Close the hashmap, freeing all its memory.
**/
void hashmap_close(Hashmap*);
void* hashmap_get(Hashmap *h, char *key, char *key_end);

/**
   Look for an entry with the given key and return a pointer to its
   value (or 0 if not found).

   @parm key_end 0 for null-terminated keys, otherwise the address of
   the first byte past the end of the key data.
**/


//void* hashmap_get(Hashmap*, void *key, void *key_end);

/**
   Put the data in the table, overwriting any previous data with the
   same key.

   @parm key_end 0 for null-terminated keys, otherwise the address of
   the first byte past the end of the key data.
**/
void hashmap_put(Hashmap *h, char *key, char *key_end, 
		  char *data, char *data_end);
void hashmap_put_unique(Hashmap*, void *key, void *key_end, 
		  void *data, void *data_end);
void hashmap_put_cckey(Hashmap *h, char *key, char *key_end, 
		  char *data, char *data_end);
	
		  	  	    

/**
   A more efficent combination of get & put, where it only puts the
   data if it was not present.

   @parm key_end 0 for null-terminated keys, otherwise the address of
   the first byte past the end of the key data.

   @return same as get (value pointer, or zero)
**/
void* hashmap_get_or_put(Hashmap*, 
			    void *key, void *key_end, 
			    void *data, void *data_end);

/**
   Remove any matching entry from the table. 

   @parm key_end 0 for null-terminated keys, otherwise the address of
   the first byte past the end of the key data.

   @return 1 if the entry was there.
**/
//int hashmap_remove(Hashmap*, void *key, void *key_end);

/**
   Iterate over the entries in the hashmap, returning the entries one
   at a time.  Be sure to call iter_reset() if you quite the iteration
   before it's complete.

   @param value A pointer which, if not zero, should point to a
   pointer which will be filled in to point to the current value.

   @return the current key value 

**/
void* hashmap_iterate(Hashmap*, iter* i, void** value);
void hashmap_dump(Hashmap *h);


#endif


