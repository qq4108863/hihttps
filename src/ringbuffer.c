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
 * For more ,please contact QQ/wechat:4108863 mail:4108863@qq.com
 */

 

#include <stdlib.h>

#include "foreign/vas.h"
#include "ringbuffer.h"

/* Initialize a ringbuffer structure to empty */

void
ringbuffer_init(ringbuffer *rb, int num_slots, int data_len)
{
    rb->num_slots = num_slots ?: DEF_RING_SLOTS;
    rb->data_len = data_len ?: DEF_RING_DATA_LEN;
    rb->slots = malloc(rb->num_slots * sizeof(rb->slots[0]));
    AN(rb->slots);

    rb->buf = malloc(rb->data_len+1);
    AN(rb->buf);

    rb->head = &rb->slots[0];
    rb->tail = &rb->slots[0];
    int x;
    for (x=0; x < rb->num_slots; x++) {
        rb->slots[x].next = &(rb->slots[(x + 1) % rb->num_slots]);
        rb->slots[x].data = malloc(rb->data_len);
        AN(rb->slots[x].data);
    }
    rb->used = 0;
    rb->bytes_written = 0;
}

void
ringbuffer_cleanup(ringbuffer *rb)
{
    int x;
    for (x=0; x < rb->num_slots; x++) {
        free(rb->slots[x].data);
    }
    free(rb->buf);
    free(rb->slots);
    
}

/** READ FUNCTIONS **/

/* Return a char * that represents the current unconsumed buffer */
char *
ringbuffer_read_next(ringbuffer *rb, int * length)
{
    assert(rb->used);
    *length = rb->head->left;
    return rb->head->ptr;
}

/* Mark consumption of only part of the read head buffer */
void
ringbuffer_read_skip(ringbuffer *rb, int length)
{
    assert(rb->used);
    rb->head->ptr += length;
    rb->head->left -= length;
}

/* Pop a consumed (fully read) head from the buffer */
void
ringbuffer_read_pop(ringbuffer *rb)
{
    assert(rb->used);
    rb->head = rb->head->next;
    rb->used--;
}


/** WRITE FUNCTIONS **/

/* Return the tail ptr (current target of new writes) */
char *
ringbuffer_write_ptr(ringbuffer *rb)
{
    assert(rb->used < rb->num_slots);
    return rb->tail->data;
}

/* Mark the tail appended for `length` bytes, and move the cursor
 * to the next slot */
void
ringbuffer_write_append(ringbuffer *rb, int length)
{
    assert(rb->used < rb->num_slots);

    rb->used++;

    rb->tail->ptr = rb->tail->data;
    rb->tail->left = length;
    rb->tail = rb->tail->next;
}

/** RING STATE FUNCTIONS **/

/* Used size of the ringbuffer */
int
ringbuffer_size(ringbuffer *rb)
{
    return rb->used;
}

/* Used size of the ringbuffer */
int
ringbuffer_capacity(ringbuffer *rb)
{
    return rb->num_slots;
}

/* Is the ringbuffer completely empty (implies: no data to be written) */
int
ringbuffer_is_empty(ringbuffer *rb)
{
    return rb->used == 0;
}

/* Is the ringbuffer completely full (implies: no more data should be read) */
int
ringbuffer_is_full(ringbuffer *rb)
{
    return rb->used == rb->num_slots;
}

