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


#ifndef RINGBUFFER_H
#define RINGBUFFER_H

#include <stddef.h>

/* Tweak these for potential memory/throughput tradeoffs */
#define DEF_RING_SLOTS 3
#define DEF_RING_DATA_LEN (1024 * 32)

typedef struct bufent {
    char *data;
    char *ptr;
    size_t left;
    struct bufent *next;
} bufent;

typedef struct ringbuffer {
    bufent *slots;
    bufent *head; // reads from the head
    bufent *tail; // writes to the tail
    char   *buf; 
    int used;
    int num_slots;
    int data_len;
    size_t bytes_written;
} ringbuffer;

void ringbuffer_init(ringbuffer *rb, int num_slots, int data_len);
void ringbuffer_cleanup(ringbuffer *rb);

char * ringbuffer_read_next(ringbuffer *rb, int * length);
void ringbuffer_read_skip(ringbuffer *rb, int length);
void ringbuffer_read_pop(ringbuffer *rb);

char * ringbuffer_write_ptr(ringbuffer *rb);
void ringbuffer_write_append(ringbuffer *rb, int length);

int ringbuffer_size(ringbuffer *rb);
int ringbuffer_capacity(ringbuffer *rb);
int ringbuffer_is_empty(ringbuffer *rb);
int ringbuffer_is_full(ringbuffer *rb);

#endif /* RINGBUFFER_H */
