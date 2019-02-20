#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/page.c"
#include "vm/frame.h"

#define MAX_ARGS 128

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);



/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy;
  char *name;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL){
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }
  strlcpy (fn_copy, file_name, PGSIZE);

  /* file name copy and parse driven by Miguel */
  name = palloc_get_page (0);
  if (name == NULL) {
    palloc_free_page (name);
    return TID_ERROR;
  }

  strlcpy (name, file_name, PGSIZE);

  struct thread *cur = thread_current();

  char *temp_name;
  char *first_arg;
  char *save_ptr;

  temp_name = name;
  first_arg = strtok_r (temp_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (first_arg, PRI_DEFAULT, start_process, fn_copy);

  sema_down(&cur->sema_exec);

  /* Success flag driven and made by Elad accross
     thread.c/.h and start process */
  if(cur->success_flag == 0) {
    cur->success_flag = 0;
    tid = TID_ERROR;
  }

  if (tid == TID_ERROR) {
    cur->fn_copy = fn_copy;
    palloc_free_page (name);
    return tid;
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  if(!success){
    thread_current()->parent->success_flag = 0;
  }
  else if(success) {
    thread_current()->parent->success_flag = 1;
  }

  sema_up(&thread_current()->parent->sema_exec);

  /* If load failed, quit. */
  /* send to parent that it successfully loaded */
  palloc_free_page (file_name);
  if (!success) {
    thread_current()->tid = TID_ERROR;
    thread_current()->parent->success_flag = 0;
    list_remove(&thread_current()->elem_child);
    thread_exit();
  }


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct thread *t = thread_current();
  struct list_elem *e;
  int temp = -1;

  if(list_empty(&t->children)){
    return temp;
  }
  struct thread *child;

  for(e = list_begin(&t->children); e != list_end(&t->children);
                                    e = list_next(e)) {
    child = list_entry(e, struct thread, elem_child);
    if(child->tid == child_tid) {

      /* call sema down from child sema */
      sema_down(&child->sema_wait);

      /* reap child */
      temp = child->exit_status;
      sema_up(&child->sema_free);
      list_remove(e);
      break;
     }
  }
  return temp;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */

     cur->pagedir = NULL;
     pagedir_activate (NULL);
     pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.printf ("load: %s: open \n",
   parse[0]); There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [Elf32_Off] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char **parse, int args);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* make copy of string for file name arg and allocate space
     for parse values */
  char *s;

  s = palloc_get_page (0);
  if (s == NULL){
    return TID_ERROR;
  }
  strlcpy (s, file_name, PGSIZE);

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL){
    goto done;
  }

  process_activate ();

  /* Malloc for the threads first supple_page and initialize the Hash */
  t->supple_page_table = (struct hash*)malloc(sizeof(struct hash));
  hash_init (t->supple_page_table, page_hash, page_less, NULL);


  /* Create variables for tokenizing*/
  char *token;
  char *save_ptr;
  char *parse[MAX_ARGS];
  int args = 0;

  /* tokenize the command line args */
  for (token = strtok_r (s, " ", &save_ptr); token != NULL;
    token = strtok_r (NULL, " ", &save_ptr)) {
      parse[args] = token;
      args++;
  }
  /* Open executable file on first parsed filename. */
  lock_acquire(&globalFilsysLock);
  file = filesys_open (parse[0]);
  lock_release(&globalFilsysLock);



  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  lock_acquire(&globalFilsysLock);
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }
  lock_release(&globalFilsysLock);

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;

  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      lock_acquire(&globalFilsysLock);
      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      lock_release(&globalFilsysLock);

      lock_acquire(&globalFilsysLock);
      file_seek (file, file_ofs);
      lock_release(&globalFilsysLock);

      lock_acquire(&globalFilsysLock);
      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      lock_release(&globalFilsysLock);

      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:

          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);

                }
              else
                {

                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }

              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable)){
                goto done;
                }
            }
          else{
            goto done;
            }
          break;
        }
    }


  /* Set up stack. */
  if (!setup_stack (esp, parse, args))
    goto done;

  /* free space used for parsing*/
  /* check */
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  file_deny_write(file);
  t->curFile = file;

 done:
  palloc_free_page (s);
  return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  lock_acquire(&globalFilsysLock);
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;
  lock_release(&globalFilsysLock);

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs.
   Creates the virual Addresses and loads Supple Page table*/
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{

  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  lock_acquire(&globalFilsysLock);
  file_seek (file, ofs);
  lock_release(&globalFilsysLock);
  int counter = 0;
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Load Supple Page Data */
      /* Driven by Gage*/
      struct supple_page *p = (struct supple_page*)
                               malloc(sizeof(struct supple_page));
      supple_page_init(p, file, ofs, upage, read_bytes, zero_bytes, writable);
      hash_insert (thread_current()->supple_page_table, &p->supple_page_elem);


      /* Advance. */
      ofs += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char *parse[], int args)
{
  /* Driven by Miranda */
  /* Load a page for the top of the stack, and add page to Supple page table */
  struct supple_page *p = (struct supple_page*)
                           malloc(sizeof(struct supple_page));

  supple_page_init(p, NULL, pg_ofs(((uint8_t *) PHYS_BASE) - PGSIZE),
                           ((uint8_t *) PHYS_BASE) - PGSIZE, 0, 0, true);

  struct frame *frame = get_frame(p);

  hash_insert (thread_current()->supple_page_table, &p->supple_page_elem);

  bool success = false;
  int totalSize = 0;
  int strLength = 0;
  int i;
  int j = 0;
  char* addr[MAX_ARGS];

  /* cast from void to char pointer */
  char* myesp = *((char **)esp);

  /* passing args driven by Elad/Miguel */
  if (frame->kpage != NULL) {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE,
                                frame->kpage, true);
    if (success) {
      myesp = PHYS_BASE;
      /* just command line not pointers */
      for(i = args-1; i >= 0; i--) {
        strLength = strlen(parse[i]) + 1;
        myesp -= strLength;
        memcpy(myesp, parse[i], strLength);
        addr[j] = myesp;
        totalSize += strLength;
        j++;
      }
      /* word allign to address pushes driven by Miranda */
      int rem;
      if((totalSize % 4) != 0) {
        rem = 4 - (totalSize % 4);
        myesp -= rem;
      }

      myesp -= 4;

      for(i = 0; i < args; i++) {
        myesp -= 4;
        memcpy(myesp, &addr[i], 4);
      }
      /* last pushes and return value push driven by gage
         parse pointer location */
      int temp = (int)myesp;
      myesp -= 4;
      memcpy(myesp, &temp, 4);


      /* add number of args */
      myesp -= 4;
      *myesp = args;

      /* add return address */
      myesp -= 4;

      *esp = myesp;
      thread_current()->esp = (int*)*esp;
    }
    else
      free_frame(frame);
  }
  return success;
}
