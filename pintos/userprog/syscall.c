#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "lib/kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
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
    
        // if (check_writable) {
        
        // }
    }
    return true;
}

bool validate_user_string(const char *string) {
    if (string == NULL || !is_user_vaddr(string)) {
        return false;
    }
    
    // iterate through the string to check if each character is valid
    const char *ptr = string;
    //void *prev_page = pg_round_down(ptr);
    for (; ;ptr) {
        // check if address or page is valid
        if (!is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, pg_round_down(ptr)) == NULL) { 
            return false;
        }
        if (*ptr == '\0') {
            break;
        }
        ptr++;
    }
    return true;
}

// helper function
static bool validate_user_ptr(const void *ptr) {
    if (ptr == NULL || !is_user_vaddr(ptr)) {
        return false;
    }
    return pagedir_get_page(thread_current()->pagedir, ptr) != NULL;
}

static void exit_with_error(void) {
    printf("%s: exit(-1)\n", thread_current()->name);
    thread_current()->exit_status = -1;
    thread_exit();
}

static void syscall_handler(struct intr_frame *f UNUSED) {
    uint32_t *args = ((uint32_t *) f->esp);
    uint32_t syscall_num;

    // validate the syscall number's pointer
    if (!validate_user_ptr(args)) {
        exit_with_error();
        return;
    }

    /*
     * The following print statement, if uncommented, will print out the syscall
     * number whenever a process enters a system call. You might find it useful
     * when debugging. It will cause tests to fail, however, so you should not
     * include it in your final submission.
     */

    /* printf("System call number: %d\n", args[0]); */

    switch (args[0]) {

        case SYS_EXIT:
            if (!validate_user_ptr(&args[1])) {
                exit_with_error();
                return;
            }   
            f->eax = args[1];
            printf("%s: exit(%d)\n", thread_current()->name, args[1]);
            thread_current()->exit_status = args[1];
            thread_exit();
            break;

        case SYS_INCREMENT:
            if (!validate_user_ptr(&args[1])) {
                exit_with_error();
                return;
            }
            f->eax = args[1] + 1;
            break;
        
        case SYS_WRITE:
            if (!validate_user_ptr(&args[1]) || 
                !validate_user_ptr(&args[2]) || 
                !validate_user_ptr(&args[3])) {
                exit_with_error();
                return;
            }
            if (args[1] == STDOUT_FILENO) {
                if (!validate_user_buffer((void *)args[2], (size_t)args[3], true)) {
                    exit_with_error();
                    return;
                }
                putbuf((char *)args[2], (size_t)args[3]);
            }
            break;

        default:
            
    }

}
