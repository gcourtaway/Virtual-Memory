#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "vm/frame.h"
#include <stdbool.h>
#include <stdint.h>


/* Suppple Page Structure*/
/* Driven by Elad*/
struct supple_page {
          void *page; /* Page tied to the supple_page */
          struct hash_elem supple_page_elem; /* used for hash */
          int frame_index; /* frame association */
          /* Keeps track of the swap index in order to access back the swap
            location for the page */
          int swap_index;
          int file_offset; /* Reference to the location of file */
          bool swapped; /* flag for swapped */
          bool pinned; /* dont evict if someone is using file */
          bool zero_page; /* flag for zero page */
          bool writable; /* flag for read only */
          struct file *file; /* current file */
          size_t read_bytes;
          size_t zero_bytes;

          void *addr; /* address for the supplemental page's page */
};


void supple_page_init(struct supple_page *p, struct file *file, int ofs,
      uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);

struct supple_page* find_page(const void* addr);

#endif
