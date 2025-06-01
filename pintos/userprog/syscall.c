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


static void syscall_handler(struct intr_frame *);
static struct lock filesys_lock; //use this to protect file system calls

bool check_user_ptr(const void *ptr);
// gets the next availible file descriptor
int get_next_fd(void); 
bool add_fd_to_table(int avail_fd, struct file *opened_file);
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
                thread_exit();
                lock_release(&filesys_lock); 
                break;
            }
            f->eax = filesys_create((const char *)args[1], (unsigned)args[2]);
            lock_release(&filesys_lock); 
            break;
        
        case SYS_REMOVE: 
            lock_acquire(&filesys_lock); 
            f->eax = -1; 
            if (!check_user_ptr((const void *)args[1])){
                thread_exit();
                lock_release(&filesys_lock);
                break;
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
                thread_exit();
                lock_release(&filesys_lock);
                break;
            }
            //open the file, if succesful, then obtain a fd int
            struct file *opened_file = filesys_open((const char *)args[1]);

            if (opened_file == NULL) {
                thread_exit();
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
                    thread_exit();
                    break;
                }
            }


        // https://g.co/gemini/share/461faccc8dea gemini has good info for rest of syscalls
        default:
            
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
        struct file_descriptor_entry *fde = (struct file_descriptor_entry *)
                                            malloc (sizeof (struct file_descriptor_entry));

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
            return false;
        }
        return true;
    } else {
        return false;
    }
}