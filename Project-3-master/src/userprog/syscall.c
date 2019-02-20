#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/string.h"
#include <console.h>
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "vm/page.h"
#include "threads/malloc.h"
#include "vm/swap.h"

#define MAX_STACK_SIZE 8388608

static void syscall_handler (struct intr_frame *);
void getArgs(int size, void *esp, int* args);
void halt(void);
void exit (int status);
bool valid_ptr(void *p);
tid_t exec (const char *cmd_line);
int open (const char *file);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
bool valid_buffer(void *buffer, unsigned size);
struct supple_page* pin_grow(uint8_t* pg, struct supple_page *p);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  uint32_t *pd;
  struct thread *cur  = thread_current();
  pd = cur->pagedir;
  uint32_t *esp = f->esp;


  /* null, outside of bounds, or unmapped, valid_ptr method at bottom */
  if (!valid_ptr(esp)) {
    exit(-1);
  }
  cur->esp = esp;
  uint32_t getCall = *esp;

  /* switch method driven and changed by all, Gage made bones of switch case */
  switch(getCall) {

    /* 0 */
    case(SYS_HALT):
      halt();
      break;

    /* 1 */
    case(SYS_EXIT):
      if (!valid_ptr(esp+1)) {
        exit(-1);
      }
      exit(*(esp+1));
      break;

    /* 2 */
    case(SYS_EXEC):
      if (!valid_ptr(esp+1)) {
        exit(-1);
      }
      f->eax = exec(*(esp+1));
      break;

    /* 3 */
    case(SYS_WAIT):
      if (!valid_ptr(esp+1)) {
        exit(-1);
      }
      f->eax = wait(*(int *)(esp+1));
      break;

    /* 4 */
    case(SYS_CREATE):
      if (!valid_ptr((esp+1)) || !valid_ptr((esp+2))) {
        exit(-1);
      }

      f->eax = create(*(esp+1),*(int *)(esp+2));
      break;

    /* 5 */
    case(SYS_REMOVE):
      if (!valid_ptr(esp+1)) {
        exit(-1);
      }

      f->eax = remove(*(esp+1));
      break;

    /* 6 */
    case(SYS_OPEN):
      if (!valid_ptr(esp+1)) {
        exit(-1);
      }

      f->eax = open(*(esp+1));
      break;

    /* 7 */
    case(SYS_FILESIZE):
      if (!valid_ptr(esp+1)) {
        exit(-1);
      }

      f->eax = filesize(*(int *)(esp+1));
      break;

    /* 8 */
    case(SYS_READ):
      if (!valid_ptr((esp+1)) || !valid_ptr((esp+2)) || !valid_ptr((esp+3))) {
        exit(-1);
      }

      f->eax = read(*(int *)(esp+1),*(int *)(esp+2),*(int *)(esp+3));
      break;

    /* 9 */
    case(SYS_WRITE):
      if (!valid_ptr((esp+1)) || !valid_ptr((esp+2)) || !valid_ptr((esp+3))) {
        exit(-1);
      }
      f->eax = write(*(int *)(esp+1),*(int *)(esp+2),*(int *)(esp+3));
      break;

    /* 10 */
    case(SYS_SEEK):
      if (!valid_ptr(esp+1) || !valid_ptr(esp+2)) {
        exit(-1);
      }
      seek(*(int *)(esp+1), *(int *)(esp+2));
      break;

    /* 11 */
    case(SYS_TELL):
      if (!valid_ptr(esp+1)) {
        exit(-1);
      }
      f->eax = tell(*(int *)(esp+1));
      break;

    /* 12 */
    case(SYS_CLOSE):
      if (!valid_ptr(esp+1)) {
        exit(-1);
      }

      close(*(int *)(esp+1));
      break;

    default:
      printf("Unknown Signal\n");
      break;
  }
  cur->esp = NULL;
  /* return not needed, but wanted */
  return;
}

/* Halts the running process */
void
halt() {
  shutdown_power_off();
}

/* exits the running process */
/* driven by Elad */
void
exit (int status) {
  struct thread *t = thread_current();
  t->exit_status = status;
  printf("%s: exit(%d)\n" ,t->name, status);
  if(lock_held_by_current_thread(&globalFilsysLock))
    lock_release(&globalFilsysLock);

  if(lock_held_by_current_thread(&swap_lock))
      lock_release(&swap_lock);


 if(lock_held_by_current_thread(&frame_table_lock))
      lock_release(&frame_table_lock);

  thread_exit();
}

/* creates a fork and execs the process if pointer is valid */
/* Driven by Gage */
tid_t
exec (const char *cmd_line) {

  if (!valid_ptr(cmd_line))
    exit(-1);

  tid_t tid = process_execute (cmd_line);

  if(tid == TID_ERROR)
    return -1;

  return tid;
}

/* Waits on the TID(PID) process to finish */
/* Driven by Gage, what a champ with this large function */
int
wait (tid_t pid) {
  return process_wait(pid);
}

/* create a file of the initial size if pointer is valid */
/* Driven by Miranda */
bool
create (const char *file, unsigned initial_size) {
  if(!valid_buffer(file, initial_size))
    exit(-1);
  if (!valid_ptr(file)) {
    exit(-1);
  }
  lock_acquire(&globalFilsysLock);
  if( filesys_create(file,initial_size)){
    lock_release(&globalFilsysLock);
    return true;
  }
  lock_release(&globalFilsysLock);
  return false;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails.
   exits if pointer is invalid */
/* Driven by Miranda */
bool
remove (const char *file) {
  if (!valid_ptr(file)) {
    exit(-1);
  }

  lock_acquire(&globalFilsysLock);
  bool removeReturn = filesys_remove(file);
  lock_release(&globalFilsysLock);

  return removeReturn;
}

/* Opens the file with the given pointer.
   Returns the fd if successful or -1
   otherwise.
   Fails if no file named NAME exists,if an internal memory
   allocation fails, or if the pointer is invalid. */
/* Driven by Elad */
int
open (const char *file) {
  if (!valid_ptr(file)) {
    exit(-1);
  }

  int i;

  lock_acquire(&globalFilsysLock);
  struct file *f = filesys_open(file);
  lock_release(&globalFilsysLock);

  struct thread *t = thread_current();

  if(f == NULL)
    return -1;

  for(i=2; i<MAX_FILES; i++) {
    if(t->used_files[i]==NULL) {
      t->used_files[i] = f;
      return i;
    }
  }
  return -1;
}

/* if fd is value, returns the size */
/* Driven by Miguel */
int
filesize (int fd) {
  struct thread *t = thread_current();
  struct file *file;
  if (t->used_files[fd] == NULL)
    return -1;
  file = t->used_files[fd];

  lock_acquire(&globalFilsysLock);
  int filesize_return = file_length(file);
  lock_release(&globalFilsysLock);

  return filesize_return;
}

/* reads file at fd location, unless takes standard input,
   if pointer is valid */
/* Driven by Elad */
int
read (int fd, void *buffer, unsigned size) {
  if(!valid_buffer(buffer,size))
    exit(-1);
  if (!valid_ptr(buffer)) {
    exit(-1);
  }

  /* invalid fd, check array size */
  if (fd < STDIN_FILENO || fd > MAX_FILES - 1) {
    exit(-1);
  }

  if (fd == STDIN_FILENO) {
    unsigned i;
    int *input_buffer = (int *)buffer;
    for(i = 0; i < size; i++)
      input_buffer[i] = input_getc();
    return size;
  }

  if(fd == STDIN_FILENO || fd == STDOUT_FILENO) {
    exit(-1);
  }

  /* Demand paging for reading a file in, and pinning the pages that will be
     read to avoid page eviction */
  /* Driven by Gage */
  struct thread *t = thread_current();
  struct file *file;
  if (t->used_files[fd] == NULL)
    return -1;

  file = t->used_files[fd];

  uint8_t *temp = (uint8_t *)buffer;
  for(; temp<=pg_round_down(buffer+size); temp+=PGSIZE) {
    struct supple_page *p = find_page(temp);
    if(!p) {
      p = pin_grow(temp, p);
    }
    else if(p->frame_index == -1) {
      struct frame *frame = get_frame(p);
      if(!install_page (p->addr, frame->kpage, p->writable)) {
        free(p);
        free_frame(frame);
        exit(-1);
      }
    }
    p->pinned = true;
  }

  /* Release the pinned pages */
  /* Driven by Miranda*/
  temp = (uint8_t *)buffer;
  lock_acquire(&globalFilsysLock);
  int read_return = file_read(file,buffer,size);
  lock_release(&globalFilsysLock);

  for(; temp<=pg_round_down(buffer+size); temp+=PGSIZE) {
    struct supple_page *p = find_page(temp);

    p->pinned = false;
  }

  return read_return;
}

/* write file at fd location, if pointer is valid */
/* Driven by Miguel */
int
write (int fd, const void *buffer, unsigned size)
{
  if (!valid_ptr(buffer)) {
    exit(-1);
  }

  /* invalid fd, check array size */
  if (fd < STDIN_FILENO || fd > MAX_FILES - 1) {
    exit(-1);
  }

  struct thread *t = thread_current();

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  }

  struct file *file;

  if (t->used_files[fd] == NULL) {
    exit(-1);
  }
  /* Demand paging for writing a file in, and pinning the pages that will be
     written to avoid page eviction */
  /* Driven by Gage */
  file = t->used_files[fd];
  uint8_t *temp = (uint8_t *)buffer;
  for(; temp<=pg_round_down(buffer+size); temp+=PGSIZE) {
    struct supple_page *p = find_page(temp);
    if(!p) {
      p = pin_grow(temp, p);
    }
    else if(p->frame_index == -1) {
      struct frame *frame = get_frame(p);

      if(!install_page (p->addr, frame->kpage, p->writable)) {
        free(p);
        free_frame(frame);
        exit(-1);
      }
    }
    p->pinned = true;
  }

  /* Release the pinned pages */
  /* Driven by Miranda*/
  lock_acquire(&globalFilsysLock);
  int write_return = file_write(file, buffer, size);
  lock_release(&globalFilsysLock);

  for(; temp<=pg_round_down(buffer+size); temp+=PGSIZE) {
    struct supple_page *p = find_page(temp);

    p->pinned = false;
  }
  
  return write_return;
}

/* Sets the current position in FILE to NEW_POS bytes from the
   start of the file. */
/* Driven by Miranda */
void
seek (int fd, unsigned position) {
  struct thread *t = thread_current();

  struct file *file;
  if (t->used_files[fd] == NULL) {
    exit(-1);
  }

  file = t->used_files[fd];
  lock_acquire(&globalFilsysLock);
  file_seek (file, position);
  lock_release(&globalFilsysLock);

}

/* Returns the current position in FILE as a byte offset from the
   start of the file. */
/* Driven by Elad */
unsigned
tell (int fd) {
  struct thread *t = thread_current();
  struct file *file;

  /* invalid fd, check array size */
  if (fd < STDIN_FILENO || fd > MAX_FILES - 1) {
    exit(-1);
  }

  if (t->used_files[fd] == NULL) {
    exit(-1);
  }

  file = t->used_files[fd];

  lock_acquire(&globalFilsysLock);
  unsigned tell_return = file_tell(file);
  lock_release(&globalFilsysLock);

  return tell_return;
}

/* closes the file at the fd index if valid, and removes from
   fd list on the thread */
/* Driven by Miranda */
void
close (int fd) {
  struct thread *t = thread_current();
  struct file *file;

  /* invalid fd, check array size */
  if (fd < STDIN_FILENO || fd > MAX_FILES - 1) {
    exit(-1);
  }

  file = t->used_files[fd];
  t->used_files[fd] = NULL;

  lock_acquire(&globalFilsysLock);
  file_close(file);
  lock_release(&globalFilsysLock);
}
/**/
bool
valid_buffer(void *buffer, unsigned size){
	char *buff_pointer = (char *)buffer;
	unsigned i;
	for(i = 0; i < (int)(size/PGSIZE); i++){
		if(!valid_ptr((void *)buff_pointer)){
			return false;
		}
		buff_pointer+=PGSIZE;
	}
	return true;
}

/* validates null, user, or unmapped pointers */
/* Driven by Gage and Miguel */
bool
valid_ptr (void *p) {
  if (p == NULL)
    return false;
  if(!is_user_vaddr(p) || (p < 0x08048000) ){
    return false;
  }
    return true;
}
/*allocate pages to faulting address for buffer*/
struct supple_page*
pin_grow(uint8_t* pg, struct supple_page *p) {
  /*check for a valid stack growth */
    if (pg < PHYS_BASE && pg >= (thread_current()->esp - 32))
  {
    if(pg < PHYS_BASE - MAX_STACK_SIZE) {
      exit(-1);
    }
  /*virtual memory allocation*/
    p = (struct supple_page*)malloc(sizeof(struct supple_page));
    struct frame *frame = get_frame(p);
    supple_page_init(p, NULL, pg_ofs(pg), pg_round_down(pg), 0, 0, true);

  /*any address lower than that must be invalid*/
    if(!install_page (p->addr, frame->kpage, p->writable)) {
      free(p);
      free_frame(frame);
      exit(-1);
    }
    else {
      hash_insert (thread_current()->supple_page_table, &p->supple_page_elem);
      return p;
    }
  }
  else
    exit(-1);
}
