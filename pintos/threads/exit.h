#ifndef THREADS_EXIT_H
#define THREADS_EXIT_H

#include <hash.h>

struct exit_info {
    int exit_code;
    bool parent_alive;
    bool self_alive;
    struct hash_elem elem;
};

#endif /* threads/exit.h */