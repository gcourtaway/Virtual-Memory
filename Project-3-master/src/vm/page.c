#include "vm/page.h"

/* Initializes the supple page data */
/* Driven by Miguel */
void supple_page_init(struct supple_page *p, struct file *file, int ofs,
  uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
  /* Page tied to the supple_page */
  p->frame_index = -1; /* frame association */
  p->file_offset = ofs; /* Reference to the location of file */
  p->zero_bytes = zero_bytes; /* flag for zero page */
  p->read_bytes = read_bytes;
  p->writable = writable; /* flag for read only */
  p->file = file; /* current file */
  p->swapped = 0;
  p->zero_page = false;
  p->addr = upage;
  p->swap_index = 0;
  p->pinned = 0;
}


/* Returns the page containing the given virtual address,
   or a null pointer if no such page exists. */
/* Driven by Miranda */
struct supple_page*
find_page(const void *address) {
  struct supple_page p;
  struct hash_elem *e;

  p.addr = pg_round_down(address);
  e = hash_find (thread_current()->supple_page_table, &p.supple_page_elem);
  return e != NULL ? hash_entry (e, struct supple_page,
                                    supple_page_elem) : NULL;
}
