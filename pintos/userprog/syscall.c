#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "threads/vaddr.h"      // for is_user_vaddr
#include "userprog/pagedir.h"   // for pagedir_get_page
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"      // for lock
#include "userprog/process.h"
#include "filesys/file.h"       // for file operations
#include "threads/palloc.h"    // for palloc 
#include "devices/input.h"     // for input_getc
#include "lib/string.h"
#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame *);
static struct lock filesys_lock; //use this to protect file system calls

bool check_user_ptr(const void *ptr);
void validate_user_vaddr (const void *vaddr);
bool validate_user_buffer(void *pointer, size_t length, bool check_writable);
bool validate_user_string(const char *string);
void exit_helper(int status);

// gets the next availible file descriptor
int get_next_fd(void); 
bool add_fd_to_table(int avail_fd, struct file *opened_file);
struct file_descriptor_entry *get_file_descriptor (int fd);
off_t get_file_size(int fd);

void syscall_init(void) {
    lock_init(&filesys_lock); //initialize the lock for file system calls
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void syscall_handler(struct intr_frame *f UNUSED) {
    //user arguments are passed via the esp pointer

    //make sure the esp pointer is valid, 4 bytes used for syscall number
    for (int i = 0; i < 4; i++) {
        if (!check_user_ptr((uint8_t *)f->esp + i)) {
            exit_helper(-1);
        }
    }
    uint32_t *args = ((uint32_t *) f->esp);

    /*
     * The following print statement, if uncommented, will print out the syscall
     * number whenever a process enters a system call. You might find it useful
     * when debugging. It will cause tests to fail, however, so you should not
     * include it in your final submission.
     */
    //testing commit 
    /* printf("System call number: %d\n", args[0]); */


    if (!check_user_ptr(args)) {
        exit_helper(-1);
    }

    switch (args[0]) {

        case SYS_EXIT:
            if (!check_user_ptr(&args[1])) {
                exit_helper(-1);
            }
            f->eax = args[1];
            // printf("%s: exit(%d)\n", thread_current()->name, args[1]);
            // thread_exit();
            /* Use exit_helper instead to set exit codes in thread. */
            exit_helper(args[1]);
            break;

        case SYS_INCREMENT:
            if (!check_user_ptr(&args[1])) {
                exit_helper(-1);
                return;
            }
            f->eax = args[1] + 1;
            break;
        //args[1] is file name and args[2] is size
        case SYS_CREATE:
            lock_acquire(&filesys_lock); 
            f->eax = -1;
            if (!validate_user_string((const void *)args[1])) {
                lock_release(&filesys_lock);
                exit_helper(-1);
            }
            f->eax = filesys_create((const char *)args[1], (unsigned)args[2]);
            lock_release(&filesys_lock);
            break;
        
        case SYS_REMOVE: 
            lock_acquire(&filesys_lock); 
            f->eax = -1; 
            if (!validate_user_string((const void *)args[1])){
                lock_release(&filesys_lock);
                exit_helper(-1);
            } 
            f->eax = filesys_remove((const char *)args[1]);
            lock_release(&filesys_lock);
            break;
        
        
        /*
            * should open file and return file descriptor attributed to file
            * need to manage a file descriptor table 
            * call current thread to get the file descriptor table, obtain lock and begin editting? 
            * create a lock for accessing the file descriptor table
            *GEMINI SHARE LINK: 
            https://g.co/gemini/share/c634e5c6d4c6
        */
        case SYS_OPEN:
            lock_acquire(&filesys_lock);
            f->eax = -1; 
            if (!validate_user_string((const void *)args[1])){
                lock_release(&filesys_lock);
                exit_helper(-1);
            }
            const char *filename = (const char *)args[1];
            if (filename == NULL || strlen(filename) == 0) {
                lock_release(&filesys_lock);
                break;
            }
            //open the file, if succesful, then obtain a fd int
            struct file *opened_file = filesys_open((const char *)filename);
            if (opened_file == NULL) {
                lock_release(&filesys_lock);
                break;
            } else {
                int fd = get_next_fd(); 
                if (add_fd_to_table(fd, opened_file)){
                    lock_release(&filesys_lock);
                    f->eax = fd; //return the file descriptor
                    break;
                } else {
                    file_close(opened_file); //close the file if we can't add it to the table
                    lock_release(&filesys_lock);
                    // exit_helper(-1); //could not add file to table
                }
            }
            break;

        case SYS_FILESIZE: 
            lock_acquire(&filesys_lock);
            f->eax = -1; 
            // if (!check_user_ptr((const void *)args[1])){
            //     lock_release(&filesys_lock);
            //     exit_helper(-1);
            // }
            off_t file_size = get_file_size(args[1]);
            if (file_size == -1) {
                f->eax = -1; //file descriptor does not exist
            } else {
                f->eax = file_size; //return the file size
            }
            lock_release(&filesys_lock);
            break;

        case SYS_READ: 
            int fd = args[1];
            void *buffer = (void *)args[2];
            unsigned size = (unsigned)args[3];
            // Validate user pointer for buffer
            if (!validate_user_buffer(buffer, size, false)) {
                exit_helper(-1);
            }

            lock_acquire(&filesys_lock);

            if (fd == 0) { // stdin
                unsigned i;
                uint8_t *buf = buffer;
                for (i = 0; i < size; i++) {
                    buf[i] = input_getc();
                }
                f->eax = size;
            } else {
                struct file_descriptor_entry *fde = get_file_descriptor(fd);
                if (fde == NULL || fde->file == NULL) {
                    f->eax = -1;
                } else {
                    // Check for EOF before reading
                    off_t pos = file_tell(fde->file);
                    off_t len = file_length(fde->file);
                    if (pos >= len) {
                        f->eax = 0; // Already at EOF
                    } else {
                        f->eax = file_read(fde->file, buffer, size);
                    }
                }
            }

            lock_release(&filesys_lock);
            break;

        case SYS_WRITE: 
            fd = args[1];
            buffer = (void *)args[2];
            size = (unsigned)args[3];
            // Validate user pointer for buffer
            if (!validate_user_buffer(buffer, size, false)) {
                exit_helper(-1);
            }
            lock_acquire(&filesys_lock);
            if (fd == STDOUT_FILENO) { // stdout
                putbuf(buffer, size);
                f->eax = size;
            } else {
                struct file_descriptor_entry *fde = get_file_descriptor(fd);
                if (fde == NULL || fde->file == NULL) {
                    f->eax = -1;  // FIXED: Return -1 instead of 5
                } else {
                    f->eax = file_write(fde->file, buffer, size);
                }
            }
            lock_release(&filesys_lock);
            break;

        case SYS_SEEK: 
            lock_acquire(&filesys_lock);
            f->eax = -1; 
            // if (!check_user_ptr((const void *)args[1])){
            //     lock_release(&filesys_lock);
            //     exit_helper(-1);
            // }
            fd = args[1];
            off_t position = (off_t)args[2];
            struct file_descriptor_entry *fde_seek = get_file_descriptor(fd);
            if (fde_seek != NULL && fde_seek->file != NULL) {
                file_seek(fde_seek->file, position);
                f->eax = 0; // Seek successful
            } else {
                f->eax = -1; // Seek failed
            }
            lock_release(&filesys_lock);
            break;
        
        case SYS_EXEC:
            /* Check every byte of args[1]. */
            // HACK: should probably do this for all arguments in a separate helper
            // for (int i = 0; i < 4; i++) {
            //     if (!check_user_ptr(args + 4 + i))
            //         exit_helper(-1);
            // }
            if (!check_user_ptr(&args[1]))
                exit_helper(-1);

            const char *cmd_line = (const char *) args[1];
            if (!validate_user_string (cmd_line))
                exit_helper(-1);

            f->eax = process_execute(cmd_line);
            break;

        case SYS_WAIT:
            tid_t pid = (tid_t) args[1];
            // if (!check_user_ptr(&args[1]))
            //     exit_helper(-1);
            f->eax = process_wait(pid);
            break;

        case SYS_HALT:
            shutdown_power_off();
            break;

        case SYS_CLOSE:  // ADDED: Missing SYS_CLOSE case
            lock_acquire(&filesys_lock);
            fd = args[1];
            struct file_descriptor_entry *fde_close = get_file_descriptor(fd);
            if (fde_close != NULL && fde_close->file != NULL) {
                file_close(fde_close->file);
                // Remove from file descriptor table
                struct thread *curr = thread_current();
                lock_acquire(&curr->fd_table_lock);
                list_remove(&fde_close->elem);
                lock_release(&curr->fd_table_lock);
                free(fde_close);
                f->eax = 0; // Success
            } else {
                f->eax = -1; // Invalid file descriptor
            }
            lock_release(&filesys_lock);
            break;
        case SYS_TELL:
            lock_acquire(&filesys_lock);
            fd = args[1];
            struct file_descriptor_entry *fde_tell = get_file_descriptor(fd);
            if (fde_tell != NULL && fde_tell->file != NULL) {
                f->eax = file_tell(fde_tell->file); // Return current position
            } else {
                f->eax = -1; // Invalid file descriptor
            }
            lock_release(&filesys_lock);
            break;
    }       
}


//check that a user pointer is valid
bool check_user_ptr(const void *ptr) {
    if (ptr == NULL) return false;
    
    uint8_t *p = (uint8_t *) ptr;
    for (int i = 0; i < sizeof(uint32_t); i++) {
        if (!is_user_vaddr(p + i) ||
            pagedir_get_page(thread_current()->pagedir, p + i) == NULL) {
            return false;
        }
    }
    // if (ptr == NULL || !is_user_vaddr(ptr) ||
    //     pagedir_get_page(thread_current()->pagedir, ptr) == NULL) {
    //     return false;
    // }
    return true;
}

//gets the next availible file descriptor from fd table
int get_next_fd(void) {
    struct thread *cur = thread_current();
    int fd = 2; // Start at 2 (0 and 1 are reserved)
    bool found;

    while (1) {
        found = false;
        struct list_elem *e;
        //go through each list entry and find next availible fd
        for (e = list_begin(&cur->file_descriptors); e != list_end(&cur->file_descriptors); e = list_next(e)) {
            struct file_descriptor_entry *fde = list_entry(e, struct file_descriptor_entry, elem);
            if (fde->fd == fd) {
                found = true;
                break;
            }
        }
        if (!found) {
            return fd;
        }
        fd++;
    }
}


bool add_fd_to_table(int avail_fd, struct file *opened_file) {

    /* Add the file to the current thread's file descriptor table. */
    if (opened_file) {
        struct thread *curr = thread_current ();
        struct file_descriptor_entry *fde = malloc(sizeof(struct file_descriptor_entry));


        if (fde) {
            fde->file = opened_file;
            fde->fd = avail_fd;
            fde->is_console_fd = false; /* Regular file */

            /* TODO: Don't use a lock around each thread's fd table, since it is not accessed by
               other threads.  */
            lock_acquire(&curr->fd_table_lock);
            list_push_back (&curr->file_descriptors, &fde->elem);
            lock_release(&curr->fd_table_lock);
            return true;
        }
    }

    /* If opened_file == NULL or fde == NULL, return false. */
    return false;
}

int get_file_size(int fd) {
    struct thread *curr = thread_current();
    struct file_descriptor_entry *fde = NULL;

    // Check if the file descriptor exists in the current thread's file descriptor table
    for (struct list_elem *e = list_begin(&curr->file_descriptors); e != list_end(&curr->file_descriptors); e = list_next(e)) {
        fde = list_entry(e, struct file_descriptor_entry, elem);
        if (fde->fd == fd) {
            return file_length(fde->file); // File descriptor exists
        }
    }
    return -1; // File descriptor does not exist
}

void validate_user_vaddr (const void *vaddr){
    if (!is_user_vaddr (vaddr) || vaddr < (void *) 0x08048000 // A common starting point for user code
        || pagedir_get_page (thread_current ()->pagedir, vaddr) == NULL)
    {
        printf ("%s: exit(%d)\n", thread_current ()->name, -1);
        process_exit ();
        thread_exit (); // Ensure the thread also exits cleanly
    }
}


bool validate_user_buffer(void *pointer, size_t length, bool check_writable) {
    if (pointer == NULL || !is_user_vaddr(pointer)) {
        return false;
    }
    size_t offset;
    // check if every page the buffer spans is valid
    for (offset = 0; offset < length; offset += PGSIZE) {
        void *addr = pg_round_down(pointer + offset);
        if (!is_user_vaddr(addr) || !pagedir_get_page(thread_current()->pagedir, addr)) {
            return false;
        }
    }
    return true;
}

bool validate_user_string(const char *string) {
    if (string == NULL || !is_user_vaddr(string)) {
        return false;
    }
    
    /* The pointer itself must be non‐NULL, lie below PHYS_BASE,
        and point to a page in cur->pagedir. */
    if (string == NULL 
        || !is_user_vaddr ((void *) string) 
        || pagedir_get_page (thread_current()->pagedir, string) == NULL) {
            return false;
    }
    
    const char *ptr = string;
    //void *prev_page = pg_round_down(ptr);
    for (; ;ptr++) {
        // check if address or page is valid
        // if (!is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, pg_round_down(ptr)) == NULL) { 
        if (!is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL) { 
            return false;
        }
        if (*ptr == '\0') {
            break;
        }
    }
    return true;
}



struct file_descriptor_entry *get_file_descriptor (int fd)
    {
    struct thread *curr = thread_current ();
    struct list_elem *e;
    lock_acquire(&curr->fd_table_lock); // Acquire lock before accessing the list
    for (e = list_begin (&curr->file_descriptors); e != list_end (&curr->file_descriptors);
        e = list_next (e))
        {
        struct file_descriptor_entry *fde = list_entry (e, struct file_descriptor_entry, elem);
        if (fde->fd == fd)
            {
            lock_release(&curr->fd_table_lock); // Release lock after accessing the list
            return fde;
            }
        }
    lock_release(&curr->fd_table_lock); // Release lock if FD not found
    return NULL; // FD not found
}

void exit_helper(int status) {
    struct thread *curr = thread_current();
    printf("%s: exit(%d)\n", curr->name, status);
    
    /* Store exit code under lock, signal any waiting parent. */
    /* We should also be able to handle this in thread_exit() instead,
       but since it doesn't take any parameters currently let's do it here. */
    lock_acquire(&curr->exit_lock);
    curr->exit_status = status;
    curr->has_exited = true;
    cond_signal(&curr->exit_cond, &curr->exit_lock);
    lock_release(&curr->exit_lock);

// #ifdef USERPROG
    /* Re‐enable writes on our executable, if kept open. */
    // if (curr->executable_file != NULL) {
    //     file_allow_write(curr->executable_file);
    //     file_close(curr->executable_file);
    //     curr->executable_file = NULL;
    // }
// #endif

    // curr->exit_status = status; 
    thread_exit(); // Exit the thread
}