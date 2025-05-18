/*
 * Word count application with one thread per input file.
 *
 * You may modify this file in any way you like, and are expected to modify it.
 * Your solution must read each input file from a separate thread. We encourage
 * you to make as few changes as necessary.
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

#include <ctype.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "word_count.h"
#include "word_helpers.h"

typedef struct {
    word_count_list_t *word_counts_ptr;
    char *filename;
} thread_args_t;

void *count_words_file(void *args) {
    thread_args_t *cast_args = args;
    FILE *infile = fopen(cast_args->filename, "r");
    if (infile == NULL) {
        perror("fopen");
        return (void *) (intptr_t) 1;
    }
    count_words(cast_args->word_counts_ptr, infile);
    fclose(infile);
    free(args);
    return 0;
}

typedef struct {
    word_count_list_t *wclist;
    char *filename;
} thread_args_t;

void *count_words_helper(void *args) {
    thread_args_t *targs = (thread_args_t *)args;
    FILE *infile = fopen(targs->filename, "r");
    //printf("helper called\n");
    count_words(targs->wclist, infile);
    fclose(infile);
    
    pthread_exit(NULL);
    //printf("thread done \n");
}
/*
 * main - handle command line, spawning one thread per file.
 */
int main(int argc, char *argv[]) {
    /* Create the empty data structure. */
    word_count_list_t word_counts;
    init_words(&word_counts);
    void *thread_ret;

    int rc;
    if (argc <= 1) {
        /* Process stdin in a single thread. */
        count_words(&word_counts, stdin);
    } else {
        pthread_t threads[argc - 1];
        for (int i = 1; i < argc; i++){
            thread_args_t *args = malloc(sizeof(*args));
            args->word_counts_ptr = &word_counts;
            args->filename = argv[i];
            pthread_create(&threads[i-1], NULL, count_words_file, args);
        }
        for (int i = 1; i < argc; i++){
            pthread_join(threads[i-1], &thread_ret);
            if ((int) (intptr_t) thread_ret != 0) {
                printf("Word counting failed for the file %s", argv[i]); 
            }
        }
        /* TODO */
        int nthreads = argc - 1;
        pthread_t threads[nthreads];
        int i;
        for (i = 1; i < argc; i++) {
            // FILE *infile = fopen(argv[i], "r");
            // if (infile == NULL) {
            //     perror("fopen");
            //     return 1;
            // }

            thread_args_t *args = malloc(sizeof(thread_args_t));
            args->wclist = &word_counts;
            args->filename = argv[i];
            rc = pthread_create(&threads[i - 1], NULL, count_words_helper, args);
            if (rc) {
                printf("ERROR; return code from pthread_create() is %d\n", rc);
                exit(-1);
            }
            //count_words(&word_counts, infile);
        }
        for (i = 0; i < nthreads; i++) {
            pthread_join(threads[i], NULL);
        }
        
    }

    /* Output final result of all threads' work. */
    wordcount_sort(&word_counts, less_count);
    fprint_words(&word_counts, stdout);
    return 0;
}
