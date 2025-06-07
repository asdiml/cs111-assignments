#include "userprog/process.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"

static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp);
static void init_userprog_thread_fd_list (struct thread *t);


/* Starts a new thread running a user program loaded from FILENAME, 
   where the parent thread's tid_t is parent. The new thread may be
   scheduled (and may even exit) before process_execute() returns.
   Returns the new process' thread id, or TID_ERROR if the thread
   cannot be created. */
tid_t process_execute(const char *file_name) {
    char *fn_copy, *fn_first_space;
    tid_t tid;

    sema_init(&temporary, 0);
    /* Make a copy of FILE_NAME.
       Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    /* In general, we shouldn't edit dereferenced objects of const
       ptrs, but I don't think we use this for anything else other
       than the name of thread. */
    // if ((fn_first_space = strchr(file_name, ' ')))
    //    *fn_first_space = '\x00';

    /* Create another temp copy of FILE_NAME, to avoid warning from passing
       const FILE_NAME into strtok_r. */
    char *temp = palloc_get_page(0);
    if (temp == NULL) {
        palloc_free_page(fn_copy);
        return TID_ERROR;
    }
    strlcpy(temp, file_name, PGSIZE);

    /* Extract program name (eg. ls) which will be used for the thread name. */
    char *program_name, *save_ptr;
    program_name = strtok_r(temp, " ", &save_ptr);
    if (program_name == NULL) {
        palloc_free_page(temp);
        palloc_free_page(fn_copy);
        return TID_ERROR;
    }

    // printf("process_execute: file_name === %s\n", file_name);
    struct thread *cur = thread_current();

    /* Before spawning the child, clear load flags under load_lock. */
    lock_acquire(&cur->load_lock);
    cur->load_success = false;
    cur->load_done = false;
    lock_release(&cur->load_lock);
       
    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create(program_name, PRI_DEFAULT, start_process, fn_copy);
    if (tid == TID_ERROR) {
        palloc_free_page(fn_copy);
        return TID_ERROR;
    }

    palloc_free_page(temp);

    /* Parent waits for child and return child's tid if it loads process successfully. */
    /* TODO. */
    lock_acquire(&cur->load_lock);
    while (!cur->load_done)
        cond_wait(&cur->load_cond, &cur->load_lock);
    lock_release(&cur->load_lock);

    return cur->load_success ? tid : TID_ERROR;

    // return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void *file_name_) {
    // Initialize the thread's file descriptor list
    struct thread *cur = thread_current();
    init_userprog_thread_fd_list(cur);
    cur->exec_file = NULL;

    char *file_name = file_name_;
    struct intr_frame if_;
    bool success;

    /* Initialize interrupt frame and load executable. */
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(file_name, &if_.eip, &if_.esp);

    /* If load failed, quit. */
    palloc_free_page(file_name);

    /* Signal the parent whether load succeeded or failed: */
    struct thread *parent = cur->parent_tcb;
    if (parent != NULL) {
        lock_acquire(&parent->load_lock);
        parent->load_success = success;
        parent->load_done = true;
        cond_signal(&parent->load_cond, &parent->load_lock);
        lock_release(&parent->load_lock);
    }

    if (!success)
        thread_exit();

    /* Start the user process by simulating a return from an
       interrupt, implemented by intr_exit (in
       threads/intr-stubs.S).  Because intr_exit takes all of its
       arguments on the stack in the form of a `struct intr_frame',
       we just point the stack pointer (%esp) to our stack frame
       and jump to it. */
    asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
    NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t child_tid UNUSED) {
    // sema_down(&temporary);
    // return 0;

    struct thread *cur = thread_current();
    struct child_info *ci = NULL;

    /* Find the matching child_info in our children list. */
    lock_acquire(&cur->children_lock);
    for (struct list_elem *e = list_begin(&cur->children);
         e != list_end(&cur->children);
         e = list_next(e)) {
        struct child_info *entry = list_entry(e, struct child_info, elem);
        if (entry->child_tid == child_tid) {
            ci = entry;
            break;
        }
    }
    lock_release(&cur->children_lock);
    if (ci == NULL) {
        return -1;  /* Not our child or already reaped. */
    }   

    struct thread *child = ci->child_tcb;

    /* Current thread (parent) blocks until the child sets has_exited. */
    lock_acquire(&child->exit_lock);
    while (!child->has_exited)
        cond_wait(&child->exit_cond, &child->exit_lock);
    int code = child->exit_status;
    printf("Waiting on TID %d\n", child_tid);
    printf("Exit code is %d\n", child->exit_status);
    printf("We are TID %d\n\n", thread_tid());
    lock_release(&child->exit_lock);

    /* Remove this child_info so we can’t wait on it again. */
    lock_acquire(&cur->children_lock);
    list_remove(&ci->elem);
    lock_release(&cur->children_lock);
    free(ci);

    /* Orphan the child TCB so thread_schedule_tail() knows it can free it. */
    child->parent_tcb = NULL;

    return code;
}

/* Free the current process's resources. */
void process_exit(void) {
    struct thread *cur = thread_current();

    /* Close executable file and re-allow writes. */
    if (cur->exec_file != NULL) {
        file_allow_write(cur->exec_file);
        file_close(cur->exec_file);
        cur->exec_file = NULL;
    }
    
    //clean up file descriptor table
    struct list_elem *e = list_begin(&cur->file_descriptors);
    while (e != list_end(&cur->file_descriptors)) {
        struct file_descriptor_entry *fde = list_entry(e, struct file_descriptor_entry, elem);
        e = list_remove(e); // Remove from list and advance

        if (fde->file != NULL) {
            file_close(fde->file);
        }
        palloc_free_page(fde);
    }

    /* Go through the list of children and free all the allocated child_info's. */
    e = list_begin(&cur->children);
    while (e != list_end(&cur->children)) {
        struct child_info *ci = list_entry(e, struct child_info, elem);
        e = list_remove(e); // Remove from list and advance
        free(ci);
    }

    uint32_t *pd;

    /* Destroy the current process's page directory and switch back
       to the kernel-only page directory. */
    pd = cur->pagedir;
    if (pd != NULL) {
        /* Correct ordering here is crucial.  We must set
           cur->pagedir to NULL before switching page directories,
           so that a timer interrupt can't switch back to the
           process page directory.  We must activate the base page
           directory before destroying the process's page
           directory, or our active page directory will be one
           that's been freed (and cleared). */
        cur->pagedir = NULL;
        pagedir_activate(NULL);
        pagedir_destroy(pd);
    }
    // sema_up(&temporary);

    /* Wake up our process' parent (if any) so that process_wait() can return. */
    lock_acquire(&cur->exit_lock);
    cur->has_exited = true;
    cond_signal(&cur->exit_cond, &cur->exit_lock);
    lock_release(&cur->exit_lock);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void) {
    struct thread *t = thread_current();

    /* Activate thread's page tables. */
    pagedir_activate(t->pagedir);

    /* Set thread's kernel stack for use in processing
       interrupts. */
    tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0 /* Ignore. */
#define PT_LOAD 1 /* Loadable segment. */
#define PT_DYNAMIC 2 /* Dynamic linking info. */
#define PT_INTERP 3 /* Name of dynamic loader. */
#define PT_NOTE 4 /* Auxiliary info. */
#define PT_SHLIB 5 /* Reserved. */
#define PT_PHDR 6 /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp, const char *file_name);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);



/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp) {
    struct thread *t = thread_current();
    struct Elf32_Ehdr ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    char *fn_copy = NULL, *fncpy_first_space;
    bool success = false;
    int i;

    char *program_name, *save_ptr;
    /* Build copy of entire cmd (eg. ls -la). */
    char *cmd_copy = palloc_get_page(0);
    if (cmd_copy == NULL)
        goto done;
    strlcpy(cmd_copy, file_name, PGSIZE);

    /* Extract program name (first token) using the copy. */
    program_name = strtok_r(cmd_copy, " ", &save_ptr);
    if (program_name == NULL) {
        palloc_free_page(cmd_copy);
        thread_exit();
    }

    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create();
    if (t->pagedir == NULL)
        goto done;
    process_activate();
    
    // /* Quick and dirty extraction of the first space-delim string.  
    //    It does not make sense for us to parse args here. */
    // fn_copy = palloc_get_page(0);
    // if (fn_copy == NULL)
    //     goto done;
    // strlcpy(fn_copy, file_name, PGSIZE);
    // if ((fncpy_first_space = strchr(fn_copy, ' ')))
    //     *fncpy_first_space = '\x00';

    /* Open executable file. */
    file = filesys_open(program_name);
    if (file == NULL) {
        printf("load: %s: open failed\n", program_name);
        goto done;
    }
    // file = filesys_open(fn_copy);
    // if (file == NULL) {
    //     printf("load: %s: open failed\n", fn_copy);
    //     goto done;
    // }

    /* Store executable in PCB and deny writes (until process exits). */
    t->exec_file = file;
    file_deny_write(file);

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
        memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 ||
        ehdr.e_machine != 3 || ehdr.e_version != 1 ||
        ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", program_name);
        // printf("load: %s: error loading executable\n", fn_copy);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file))
            goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
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
            if (validate_segment(&phdr, file)) {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0) {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) -
                                  read_bytes);
                } else {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
                if (!load_segment(file, file_page, (void *) mem_page,
                                  read_bytes, zero_bytes, writable))
                    goto done;
            } else
                goto done;
            break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(esp, file_name))
        goto done;

    /* Start address. */
    *eip = (void (*)(void)) ehdr.e_entry;

    success = true;
    
done:
    palloc_free_page(fn_copy);
    // file_close(file);
    /* Only close the file and enable writes if load fails. */
    if (!success) {
        if (file != NULL) {
            file_allow_write(file);
            file_close(file);
        }
        t->exec_file = NULL;
    }
    return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr *phdr, struct file *file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off) file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void *) phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void *) (phdr->p_vaddr + phdr->p_memsz)))
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
   or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int) page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* setup_stack() helpers. */

typedef struct args {
    uint32_t argc;
    char **argv;
} args_t;
static bool parse_args(char *file_name, args_t *parsed_args, char **argv);
static bool place_args_on_stack(void **esp, args_t *args, uint8_t* const kpage, uint8_t* const upage);

/* Setup the stack with argv and argc by mapping a zeroed page at the top of
   user virtual memory and placing in the strings accordingly. */
// static bool setup_stack(void **esp, const char *file_name) {
//     char *fn_copy = NULL;
//     args_t parsed_args = {.argc = 0, .argv = NULL};
//     uint8_t *argv_page, *kpage;
//     bool success = false;

//     /* argv can be arbitrarily large, so we just allocate a page for it.
//        The main reason I don't want to use malloc() is because we have at most
//        10 possible sizes of chunks for it (else the memory use overhead is going to
//        become high). 

//        This may come back to bite us for extremely large-sized cmd line args, 
//        so we should KIV the possibility of segfaults due to this. */
//     parsed_args.argv = palloc_get_page(0);
//     argv_page = (uint8_t*)parsed_args.argv;
//     if (parsed_args.argv == NULL)
//         return false;

//     /* We should not modify the original file_name, which strtok_r does. 
//        Allocate a local buffer and strlcpy over.
//        Also, the pointers in parsed_args.argv will point into this string. */
//     fn_copy = malloc(strlen(file_name) + 1);
//     if (fn_copy == NULL)
//         goto done;
//     strlcpy(fn_copy, file_name, strlen(file_name) + 1);

//     /* Populate parsed_args.argc and parsed_args.argv */
//     if (!parse_args(fn_copy, &parsed_args, parsed_args.argv))
//         goto done;

//     /* ----- FOR DEBUGGING ONLY ----- */
//     // printf("argc: %u\n", parsed_args.argc);
//     // for (int i = 0; i <= parsed_args.argc; i++)
//     //     if (parsed_args.argv[i] != NULL)
//     //         printf("argv[%d] = '%s'\n", i, parsed_args.argv[i]);
//     //     else
//     //         printf("argv[%d] = null\n", i);
//     /* ----- FOR DEBUGGING ONLY ----- */

//     kpage = palloc_get_page(PAL_USER | PAL_ZERO);
//     if (kpage != NULL) {
//         success = install_page(((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true) \
//             && place_args_on_stack(esp, &parsed_args, kpage, ((uint8_t *) PHYS_BASE) - PGSIZE);
//         if (!success)
//             palloc_free_page(kpage);
//     }

// done:
//     /* We arrive here regardless of whether setup_stack is successful. */
//     palloc_free_page(argv_page);
//     free(fn_copy);
//     return success;
// }

static bool setup_stack(void **esp, const char *file_name) {
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
        if (success)
            *esp = PHYS_BASE;
        else
            palloc_free_page(kpage);
    }

    /* Copy file_name into a temporary buffer. */
    char *fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return false;
    strlcpy(fn_copy, file_name, PGSIZE); // fn_copy == "prog arg1 arg2 ..."

    /* Tokenize using strtok_r. */
    char *save_ptr = NULL;
    char *argv[128];
    int argc = 0;
    int total_bytes = 0;

    /* Copy each argument onto stack and save address. Order doesn't matter. */
    char *token = strtok_r(fn_copy, " ", &save_ptr);
    while (token != NULL) {
        size_t len = strlen(token) + 1; // include NULL
        /* Check for stack overflow: too many/too-big arguments.
           Enforce that args fit within half of the page. */
        if (((uintptr_t) *esp - len) < ((uintptr_t) PHYS_BASE - PGSIZE / 2)) {
            palloc_free_page(fn_copy);
            return false;
        }

        *esp -= len; // move the stack pointer down
        memcpy(*esp, token, len); // copy the argument string
        argv[argc++] = (char *) *esp; // record its user‐VA
        total_bytes += len;
        token = strtok_r(NULL, " ", &save_ptr);
    }

    /* Done copying all argument strings. Free the temporary fn_copy. */
    palloc_free_page(fn_copy);

    /* Compute how many bytes needed for space alignment.
       Does not include return address, only the arguments on the stack. */
    total_bytes +=
        ((argc + 1) * sizeof(char *)) + sizeof(char **) + sizeof(int);
    const size_t pad_bytes = ((uintptr_t) PHYS_BASE - total_bytes) & 0xf;

    /* Subtract space alignment bytes and pad with 0. */
    *esp -= pad_bytes;
    memset(*esp, 0, pad_bytes);

    /* Push NULL sentinel (argv[argc] = NULL). */
    *esp = (void *) ((uintptr_t) *esp - sizeof(char *));
    *((char **) *esp) = NULL;

    /* Push each argv[i] pointer in reverse order. */
    for (int i = argc - 1; i >= 0; i--) {
        *esp = (void *) ((uintptr_t) *esp - sizeof(char *));
        *((char **) *esp) = argv[i];
    }

    /* Push the char **argv pointer itself. */
    char **argv_ptr = (char **) *esp;
    *esp = (void *) ((uintptr_t) *esp - sizeof(char **));
    *((char ***) *esp) = argv_ptr;

    /* Push argc. */
    *esp = (void *) ((uintptr_t) *esp - sizeof(int));
    *((int *) *esp) = argc;

    /* Push fake return address (0). */
    *esp = (void *) ((uintptr_t) *esp - sizeof(void *));
    *((void **) *esp) = 0;

    /* Now all of _start(argc, argv) are laid out correctly,
       with 16-byte alignment for (esp + 4). */
    return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
       address, then map our page there. */
    return (pagedir_get_page(t->pagedir, upage) == NULL &&
            pagedir_set_page(t->pagedir, upage, kpage, writable));
}

/* Parse the args from file_name and place them into the args_t struct */
static bool parse_args(char *file_name, args_t *parsed_args, char **argv) {
    char *arg;

    /* Process the arguments. */
    while ((arg = strtok_r(file_name, " ", &file_name)))
        argv[parsed_args->argc++] = arg;
    argv[parsed_args->argc] = NULL;

    return true;
}

/* Place the parsed arguments on the stack while checking for a possible 
   stack overflow. */
static bool place_args_on_stack(void **esp, args_t *args, uint8_t* const kpage, uint8_t* const upage) {
    uint8_t *cur_sp = kpage + PGSIZE;
    size_t argv_arr_size;
    uint32_t i;

    /* Place the argv strings of front args first on the stack (i.e. 
       at higher addresses). Purely for implementation convenience. */
    for (i = 0; i < args->argc; i++) {
        cur_sp -= strlen(args->argv[i]) + 1;

        /* If more than half of the page is used for args, simply fail. */
        if (cur_sp < kpage + PGSIZE / 2)
            return false;

        strlcpy((char *)cur_sp, args->argv[i], strlen(args->argv[i]) + 1);
        args->argv[i] = (char *)(upage + (cur_sp - kpage));
    }

    /* Align to the 4 byte boundary and calculate the size of the argv arr. */
    cur_sp = (uint8_t*)((uint32_t)cur_sp & (uint32_t)~0x3);
    argv_arr_size = (args->argc + 1) * sizeof(char *);

    /* Place the argv array onto the stack. */
    cur_sp -= argv_arr_size;
    memcpy(cur_sp, args->argv, argv_arr_size);
    args->argv = (char **)(upage + (cur_sp - kpage));

    /* Align the stack by simply rounding down to 0x10 and subtracting
       by 0x14. The idea is that the call must occur at the 0x10 byte
       boundary, so after the return address is pushed onto the stack,
       the least significant nibble will become 0xc. */
    cur_sp = (uint8_t*)((uint32_t)cur_sp & (uint32_t)~0xf);
    cur_sp -= 0x14;

    /* We perform a final check to see if more than half the page is 
       used just to store args. */
    if (cur_sp < kpage + PGSIZE / 2)
       return false;

    /* Place argc and argv onto the stack. */
    *(uint32_t *)(cur_sp + 0x4) = args->argc;
    *(uint32_t *)(cur_sp + 0x8) = (uint32_t)args->argv;

    /* Lastly, update esp. */
    *esp = (void *)(upage + (cur_sp - kpage));
    
    return true;
}

static void init_userprog_thread_fd_list (struct thread *t){
    list_init (&t->file_descriptors);
    // adding file descriptor entries for stdin and stdout
    struct file_descriptor_entry *stdin_fde = palloc_get_page(0);
    if (stdin_fde != NULL) {
        stdin_fde->fd = 0;
        stdin_fde->file = NULL; 
        stdin_fde->is_console_fd = true;
        list_push_back(&t->file_descriptors, &stdin_fde->elem);
    } else {
        PANIC ("Failed to allocate stdin file descriptor entry");
    }

    // Example of adding stdout (fd 1):
    struct file_descriptor_entry *stdout_fde = palloc_get_page(0);
    if (stdout_fde != NULL) {
        stdout_fde->fd = 1;
        stdout_fde->file = NULL; // No actual file for stdout
        stdout_fde->is_console_fd = true;
        list_push_back(&t->file_descriptors, &stdout_fde->elem);
    } else {
        PANIC ("Failed to allocate stdout file descriptor entry");
    }

    lock_init (&t->fd_table_lock); // If you decide on per-thread FD table lock
}