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

static void syscall_handler(struct intr_frame *);
static struct lock filesys_lock; //use this to protect file system calls

bool check_user_ptr(const void *ptr);
void validate_user_vaddr (const void *vaddr);
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
    uint32_t *args = ((uint32_t *) f->esp);

    /*
     * The following print statement, if uncommented, will print out the syscall
     * number whenever a process enters a system call. You might find it useful
     * when debugging. It will cause tests to fail, however, so you should not
     * include it in your final submission.
     */
    //testing commit 
    /* printf("System call number: %d\n", args[0]); */

    switch (args[0]) {

        case SYS_EXIT:
            f->eax = args[1];
            printf("%s: exit(%d)\n", thread_current()->name, args[1]);
            thread_exit();
            break;

        case SYS_INCREMENT:
            f->eax = args[1] + 1;
            break;
        
        case SYS_WRITE:
            if (args[1] == STDOUT_FILENO)
                putbuf((char *)args[2], (size_t)args[3]);
            break;
        //args[1] is file name and args[2] is size
        case SYS_CREATE:
            lock_acquire(&filesys_lock); 
            f->eax = -1;
            if (!check_user_ptr((const void *)args[1])){
                lock_release(&filesys_lock);
                exit_helper(-1);
            }
            f->eax = filesys_create((const char *)args[1], (unsigned)args[2]);
            lock_release(&filesys_lock); 
            break;
        
        case SYS_REMOVE: 
            lock_acquire(&filesys_lock); 
            f->eax = -1; 
            if (!check_user_ptr((const void *)args[1])){
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
            if (!check_user_ptr((const void *)args[1])){
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
                    exit_helper(-1); //could not add file to table
                }
            }

        case SYS_FILESIZE: 
            lock_acquire(&filesys_lock);
            f->eax = -1; 
            if (!check_user_ptr((const void *)args[1])){
                lock_release(&filesys_lock);
                exit_helper(-1);
            }
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
            if (!check_user_ptr(buffer)) {
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
                        int bytes_read = file_read(fde->file, buffer, size);
                        f->eax = bytes_read >= 0 ? bytes_read : -1;
                    }
                }
            }

            lock_release(&filesys_lock);
            break;
    }       
}


//check that a user pointer is valid
bool check_user_ptr(const void *ptr) {
    if (ptr == NULL || !is_user_vaddr(ptr) ||
        pagedir_get_page(thread_current()->pagedir, ptr) == NULL) {
        return false;
    }
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
    /* add the file to the current thread's file descriptor table */
    if (opened_file != NULL){
        struct thread *curr = thread_current ();
        struct file_descriptor_entry *fde = palloc_get_page(PAL_ZERO);

        if (fde != NULL)
        {
            fde->file = opened_file;
            fde->fd = avail_fd; // Assign and increment FD
            fde->is_console_fd = false; // It's a regular file
            lock_acquire(&curr->fd_table_lock); // Acquire lock before modifying the list
            list_push_back (&curr->file_descriptors, &fde->elem);
            lock_release(&curr->fd_table_lock); // Release lock after modification
        }
        else
        {
            file_close (opened_file);
            palloc_free_page(fde);
            return false;
        }
        return true;
    } else {
        return false;
    }
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


struct file_descriptor_entry *get_file_descriptor (int fd)
    {
    struct thread *curr = thread_current ();
    struct list_elem *e;

    for (e = list_begin (&curr->file_descriptors); e != list_end (&curr->file_descriptors);
        e = list_next (e))
        {
        struct file_descriptor_entry *fde = list_entry (e, struct file_descriptor_entry, elem);
        if (fde->fd == fd)
            {
            return fde;
            }
        }
    return NULL; // FD not found
}

void exit_helper(int status) {
    struct thread *curr = thread_current();
    printf("%s: exit(%d)\n", curr->name, status);
    curr->exit_status = status; 
    thread_exit(); // Exit the thread
}