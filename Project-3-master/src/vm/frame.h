#ifndef VM_FRAME_H
#define VM_FRAME_H


#include <stdbool.h>
#include <stdint.h>
#include <list.h>
#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/page.h"

#define MAXFRAMES 367 /* Maximum Frames in user pool */


struct frame *frame_table[MAXFRAMES]; /* arrary of frames stucts */
struct lock frame_table_lock; /* Global Struct Synchronization */

struct frame {
    uint8_t *kpage; /* Page linked to Frame */
    struct supple_page *supple_page; /* Supple Page link */
    struct thread *thread; /* owner of frame */
    };

void frame_init (struct frame *frame);
void frame_table_init(void);
struct frame* get_frame(struct supple_page *supple_page);
struct frame* evict_frame(struct supple_page *supple_page);
void free_frame(struct frame *frame);

#endif
