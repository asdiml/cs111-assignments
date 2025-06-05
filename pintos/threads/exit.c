#include "exit.h"

#include <debug.h>

#include "threads/thread.h"

/* Functions required for the hashmap of exit_info structs. */
unsigned hash_einfo(const struct hash_elem *e, void *aux UNUSED) {
    const struct exit_info* einfo = hash_entry(e, struct exit_info, elem);
    return hash_int(einfo->tid);
}
bool hash_less_einfo(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct exit_info* einfo_a = hash_entry(a, struct exit_info, elem);
    const struct exit_info* einfo_b = hash_entry(b, struct exit_info, elem);
    return hash_int(einfo_a->tid) < hash_int(einfo_b->tid);
}