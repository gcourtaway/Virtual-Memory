#include "vm/swap.h"
#include "userprog/pagedir.h"

#define FREE 0
#define USED 1

/* Driven by Elad*/
/* Calculate the secotrs per page */
int SECTORS_PER_PAGE = (PGSIZE/BLOCK_SECTOR_SIZE);

/* Initalize the swap block and bitmap for swapping */
void swap_init() {
  lock_init(&swap_lock);
  block = block_get_role(BLOCK_SWAP);
  if (!block) {
    return;
  }
  swap_bitmap = bitmap_create(block_size(block) / SECTORS_PER_PAGE);
  if (!swap_bitmap) {
    return;
  }
  bitmap_set_all(swap_bitmap, FREE);
}

/* Driven by Miguel */
/* write to disk, flip first free bit and return index
   loop through the pages per sector */
void swap_insert(struct frame *frame) {
  lock_acquire(&swap_lock);
  int index = bitmap_scan_and_flip(swap_bitmap, 0, 1, FREE);
  frame->supple_page->swapped = true;
  frame->supple_page->swap_index = index;
  if(index == BITMAP_ERROR) {
    exit(-1);
  }

  int i;
  for(i=0; i < SECTORS_PER_PAGE; i++) {
    block_write (block, i+ SECTORS_PER_PAGE*index,
                       frame->kpage + i*BLOCK_SECTOR_SIZE);
  }
  lock_release(&swap_lock);
}

/* Driven by Gage */
/* Update the bitmap, get the page back out of swap, reset dirty bit */
void swap_remove(struct frame *frame, int index) {
  lock_acquire(&swap_lock);
  bitmap_flip(swap_bitmap, index);

  int i;
  for(i=0; i < SECTORS_PER_PAGE; i++) {
    block_read(block, i+ SECTORS_PER_PAGE*index,
                      frame->kpage + i*BLOCK_SECTOR_SIZE);
  }
  frame->supple_page->swapped = false;
  pagedir_set_dirty(frame->thread->pagedir, frame->supple_page->addr, 1);
  lock_release(&swap_lock);
}
