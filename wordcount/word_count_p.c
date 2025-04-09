/*
 * Implementation of the word_count interface using Pintos lists and pthreads.
 *
 * You may modify this file, and are expected to modify it.
 */

/*
 * Copyright (C) 2019 University of California, Berkeley
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PINTOS_LIST
#error "PINTOS_LIST must be #define'd when compiling word_count_lp.c"
#endif

#ifndef PTHREADS
#error "PTHREADS must be #define'd when compiling word_count_lp.c"
#endif

#include "word_count.h"

void init_words(word_count_list_t *wclist) {
    /* TODO */
    // pass in the address of the list struct
    list_init(&wclist->lst);
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    wclist->lock = mutex;
}

size_t len_words(word_count_list_t *wclist) {
    /* TODO */

    struct list_elem *e;
    size_t cnt = 0;
    pthread_mutex_lock(&wclist->lock);
    for (e = list_begin(&wclist->lst); e != list_end(&wclist->lst); e = list_next(e))
        cnt++;
    pthread_mutex_unlock(&wclist->lock);
    return cnt;
}

word_count_t *find_word(word_count_list_t *wclist, char *word) {
    /* TODO */
    struct list_elem *e;
    //pthread_mutex_lock(&wclist->lock);
    e = list_begin(&wclist->lst);
    word_count_t *result = NULL;
    // while not at the end of the list, and the word is not found in current node/struct
    while ((e != list_end(&wclist->lst))) {
        /* list entry retrieves the struct that contains e, by subtracting the offset of the next element 
            to the address of the next element
            elem is attribute of word_count struct that contains prev/next pointers */
        if (strcmp(list_entry(e, word_count_t, elem)->word, word) == 0) {
            result =  list_entry(e, word_count_t, elem);
            break;
        }
        e = list_next(e);

    }
    //pthread_mutex_unlock(&wclist->lock);
    return result;
}

word_count_t *add_word_with_count(word_count_list_t *wclist, char *word, int count) {
    /* TODO */
    pthread_mutex_lock(&wclist->lock);
    word_count_t *wc = find_word(wclist, word);
    if (wc != NULL) {
        wc->count += count;
    // if not in the list add to the head of the list
    } else if ((wc = malloc(sizeof(word_count_t))) != NULL) {
        wc->word = word;
        wc->count = count;
        #ifdef PTHREADS
        list_push_front(&wclist->lst, &wc->elem);
        #else
        list_push_front(wclist, &wc->elem);
        #endif
    }
    else {
        perror("malloc");
    }
    pthread_mutex_unlock(&wclist->lock);
    return wc;
}

word_count_t *add_word(word_count_list_t *wclist, char *word) {
    return add_word_with_count(wclist, word, 1);
}

void fprint_words(word_count_list_t *wclist, FILE *outfile) {
    /* TODO */
    struct list_elem *e;
    pthread_mutex_lock(&wclist->lock);
    e = list_begin(&wclist->lst);
    while (e != list_end(&wclist->lst)) {
        fprintf(outfile, "%8d\t%s\n", list_entry(e, word_count_t, elem)->count,
                list_entry(e, word_count_t, elem)->word);
        e = list_next(e);
    }
    pthread_mutex_unlock(&wclist->lock);
}

static bool less_list(const struct list_elem *ewc1,
    const struct list_elem *ewc2, void *aux) {
    /* TODO */
    word_count_t *wc1 = list_entry(ewc1, word_count_t, elem);
    word_count_t *wc2 = list_entry(ewc2, word_count_t, elem);
    // cast syntax (int) x, so cast aux as a pointer to a function that returns a bool
    bool(*comparator_func)(const word_count_t *, const word_count_t *) =
    (bool (*)(const word_count_t *, const word_count_t *)) aux;
    return comparator_func(wc1, wc2);
}

void wordcount_sort(word_count_list_t *wclist,
                    bool less(const word_count_t *, const word_count_t *)) {
    /* TODO */
    pthread_mutex_lock(&wclist->lock);
    list_sort(&wclist->lst, less_list, less);
    pthread_mutex_unlock(&wclist->lock);
}
