#ifndef THREADS_EXIT_H
#define THREADS_EXIT_H

#include <hash.h>

#include "threads/thread.h"

struct exit_info {
    tid_t tid;
    int exit_code;
    struct hash_elem elem;
};
unsigned hash_einfo(const struct hash_elem *e, void *aux);
bool hash_less_einfo(const struct hash_elem *a, const struct hash_elem *b, void *aux);

#endif /* threads/exit.h */