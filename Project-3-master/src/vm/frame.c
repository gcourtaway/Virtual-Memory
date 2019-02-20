#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "threads/init.h"

/* total frames in the table allocated */
int frame_count;

/* Clock hand tracker */
/* Driven by Miranda */
int clockHand = 0;

/* Create a frame with initialized values */
/* Driven by Gage */
void frame_init(struct frame *frame) {
  frame->kpage = NULL;
  frame->supple_page = NULL;
  frame->thread = NULL;
}

/* Create the Frame table with all Pages for users to allocate */
/* Driven by Miguel */
void frame_table_init(void) {

  lock_init(&frame_table_lock);

  lock_acquire(&frame_table_lock);
  uint32_t table_index = 0;
  struct frame *i;
  for (table_index = 0; table_index < 367; table_index++)
  {
    frame_count++;
    i = malloc(sizeof(struct frame));

    frame_init(i);
    i->kpage = palloc_get_page(PAL_USER);
    if(i->kpage == NULL)
       break;
    frame_table[table_index] = i;
  }
  lock_release(&frame_table_lock);
}

/* Searches for a frame in the table, if it cannot find one, run eviction */
/* Driven by Elad */
struct frame* get_frame(struct supple_page *supple_page) {
    int frame_number;
    lock_acquire(&frame_table_lock);
    for (frame_number = 0; frame_number < frame_count; frame_number++) {
      if (frame_table[frame_number]->supple_page == NULL) {
          frame_table[frame_number]->supple_page = supple_page;
          memset(frame_table[frame_number]->kpage, 0, PGSIZE);

          /* update supple page to contain frame index */
          supple_page->frame_index = frame_number;
          frame_table[frame_number]->thread = thread_current();
          lock_release(&frame_table_lock);
          return frame_table[frame_number];
      }
    }
   /* Release lock to evict frame */
   lock_release(&frame_table_lock);
   struct frame *frame = evict_frame(supple_page);
   frame->supple_page = supple_page;
   frame->thread = thread_current();
   return frame;
}

/* Removes supplental page during eviction or process terminate
   using the clock algorithm. */
/* Driven by Miranda */
struct frame* evict_frame(struct supple_page *supple_page) {
  int frame_number = clockHand;
  lock_acquire(&frame_table_lock);
  lock_acquire(&frame_table_lock);
  while(1)
  {
    for (frame_number=clockHand; frame_number < frame_count; frame_number++)

    {
      struct frame *frame = frame_table[frame_number];
      /* if pinned, skip this page and go to the next iteration */
      if(frame->supple_page->pinned){
        continue;
      }
      /* if accessed bit is 0 and page is not dirty evict page
          and get the frame */
      if(!pagedir_is_accessed (frame->thread->pagedir,

                                  frame->supple_page->addr)) {
        if(!pagedir_is_dirty (frame->thread->pagedir,

                                frame->supple_page->addr)){
          free_frame(frame_table[frame_number]);
          supple_page->frame_index = frame_number;
          clockHand = frame_number;
          lock_release(&frame_table_lock);
          return frame;
        }
        /* If dirty send to swap */
        else {
          swap_insert(frame);
          free_frame(frame);
          supple_page->frame_index = frame_number;
          clockHand = frame_number;
          lock_release(&frame_table_lock);
          return frame;
        }
      }
      /* Otherwise set accesse bit to 0 and check next frame */
      else{
         clockHand++;
         pagedir_set_accessed(frame->thread->pagedir,

                                  frame->supple_page->addr, 0);
       }
    }
    clockHand = 0;
    /* Release lock and go back through loop */
  }
  lock_release(&frame_table_lock);
}

/* Clears the page and frame information */
/* Driven by Gage */
void free_frame(struct frame *frame) {
  pagedir_clear_page(frame->thread->pagedir, frame->supple_page->addr);
  frame->supple_page = NULL;
  frame->thread = NULL;
}
