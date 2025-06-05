#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "lib/kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f UNUSED) {
    uint32_t *args = ((uint32_t *) f->esp);

    switch (args[0]) {

        case SYS_INCREMENT:
            f->eax = args[1] + 1;
            break;
        
        case SYS_WRITE:
            if (args[1] == STDOUT_FILENO)
                putbuf((char *)args[2], (size_t)args[3]);
            break;

        // File system calls
        // TODO

        // Process system calls
        case SYS_EXIT:
            f->eax = args[1];
            printf("%s: exit(%d)\n", thread_current()->name, args[1]);
            thread_exit(args[1]); // NORETURN
            break;
        
        case SYS_EXEC:

        
        
        default:
            
    }

}
