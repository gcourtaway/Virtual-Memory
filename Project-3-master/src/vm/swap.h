#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>

#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

/* Driven by Miranda */
/* block for swapping */
struct block *block;

/* global lock for swapping block */
struct lock swap_lock;

/* bitmap data structure for swapping block */
struct bitmap *swap_bitmap;

void swap_init();
void swap_insert(struct frame *frame);
void swap_remove(struct frame *frame, int index);

#endif /* vm/swap.h */
