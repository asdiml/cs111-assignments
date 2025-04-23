#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "tokenizer.h"

/* Convenience macro to silence compiler warnings about unused function
 * parameters. */
#define unused __attribute__((unused))

/* Whether the shell is connected to an actual terminal or not. */
bool shell_is_interactive;

/* File descriptor for the shell input */
int shell_terminal;

/* Terminal mode settings for the shell */
struct termios shell_tmodes;

/* Process group id for the shell */
pid_t shell_pgid;

int cmd_exit(struct tokens *tokens);
int cmd_help(struct tokens *tokens);
int cmd_pwd(struct tokens *tokens);
int cmd_cd(struct tokens *tokens);

/* Built-in command functions take token array (see parse.h) and return int */
typedef int cmd_fun_t(struct tokens *tokens);

/* Built-in command struct and lookup table */
typedef struct fun_desc {
    cmd_fun_t *fun;
    char *cmd;
    char *doc;
} fun_desc_t;

fun_desc_t cmd_table[] = {
    {cmd_help, "?", "show this help menu"},
    {cmd_exit, "exit", "exit the command shell"},
    {cmd_pwd, "pwd", "print the current working directory"},
    {cmd_cd, "cd", "change the current working directory"}
};

/* Prints a helpful description for the given command */
int cmd_help(unused struct tokens *tokens) {
    for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++) {
        printf("%s - %s\n", cmd_table[i].cmd, cmd_table[i].doc);
    }
    return 1;
}

/* Exits this shell */
int cmd_exit(unused struct tokens *tokens) {
    exit(0);
}

/* Prints the current working directory */
int cmd_pwd(unused struct tokens *tokens) {
    char *cwd = getcwd(NULL, 0);
    puts(cwd);
    free(cwd);
    return 1;
}

/* Changes the current working directory */
int cmd_cd(struct tokens *tokens) {
    int num_args = tokens_get_length(tokens) - 1;
    if (num_args == 0) {
        if (chdir("~") < 0) {
            fprintf(stderr, "cd: ~: %s\n", strerror(errno));
            return -1;
        }
    } else if (num_args > 1) {
        puts("cd: too many arguments");
        return -1;
    } else if (chdir(tokens_get_token(tokens, 1)) < 0) {
        fprintf(stderr, "cd: %s: %s\n", tokens_get_token(tokens, 1), strerror(errno));
        return -1;
    }
    return 1;
}

/* Looks up the built-in command, if it exists. */
int lookup(char *cmd) {
    if (cmd != NULL) {
        for (int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++) {
            if (strcmp(cmd_table[i].cmd, cmd) == 0) {
                return i;
            }
        }
    }
    return -1;
}

/* Resolve path to binary using PATH env */
int resolve_path(char *path, char *resolved_path) {

    /* If path is already resolved i.e. a path to an executable file, use that */
    if (access(path, X_OK) == 0) {
        strncpy(resolved_path, path, PATH_MAX);
        return 1;
    } 

    /* Get PATH env */
    char *ori_env_path = getenv("PATH");
    if (ori_env_path == NULL) {
        perror("getenv PATH");
        return -1;
    }
    
    /* We are not supposed to modify the original PATH env, which strtok does. Allocate a local buffer and strcpy over */
    char env_path[strlen(ori_env_path) + 1];
    strncpy(env_path, ori_env_path, strlen(ori_env_path));

    /* Iterate through the colon-separated directories */
    char *dir = strtok(env_path, ":");
    while (dir != NULL) {

        DIR *dp;
        struct dirent *dir_entry;

        if ((dp = opendir(dir)) == NULL) {
            fprintf(stderr,"cannot open directory: %s\n", dir);
            goto continue_to_next_dir;
        }

        /* Iterate through the entries of the particular directory in PATH */
        errno = 0;
        while ((dir_entry = readdir(dp)) != NULL) {

            /* Handle readdir errors */
            if (errno != 0) {
                fprintf(stderr, "readdir: %s: %s\n", dir, strerror(errno));
                goto continue_to_next_dir_entry;
            }

            /* Get full path name */
            char full_path[PATH_MAX];
            int len = snprintf(full_path, sizeof(full_path), "%s/%s", dir, dir_entry->d_name);
            if (len < 0 || len >= (int)sizeof(full_path)) {
                if (len >= (int)sizeof(full_path))
                    fprintf(stderr, "resolve_path: max path length exceeded\n");
                else perror("snprintf");
                goto continue_to_next_dir_entry;
            }

            /* If the dir_entry is executable by this process and matches the name, return it */
            if (strcmp(path, dir_entry->d_name) == 0 && access(full_path, X_OK) == 0) {
                strncpy(resolved_path, full_path, PATH_MAX);
                return 1;
            }

    continue_to_next_dir_entry:
            errno = 0;
        }

    continue_to_next_dir:
        closedir(dp);
        dir = strtok(NULL, ":");
    }

    return 2; // Return 2 if the file is not found
}

/* Process the non-path args to be passed to the called binary */
int process_args(struct tokens *tokens, char **argv) {
    
    /* Iterate over the tokens */
    int cur_arg_i = 1, num_tokens = tokens_get_length(tokens);
    for (int i = 1; i < num_tokens; i++) {

        char *cur_token = tokens_get_token(tokens, i);

        /* Handle redirection */
        if (strcmp(cur_token, ">") == 0 || strcmp(cur_token, "<") == 0) {

            /* Check for syntax errors */
            if (i == num_tokens - 1) {
                fprintf(stderr, "shell: syntax error near unexpected token `newline'\n");
                return -1;
            }
            
            /* Redirect stdout */
            if (strcmp(cur_token, ">") == 0) {

                /* Open file and create it if required */
                int out_fd;
                if ((out_fd = creat(tokens_get_token(tokens, i + 1), 0644)) < 0) {
                    perror("open");
                    return -1;
                }

                /* Redirect stdout to the fd */
                if (dup2(out_fd, STDOUT_FILENO) < 0) {
                    perror("dup2");
                    return -1;
                }
                close(out_fd);
            
            /* Redirect stdin */
            } else {

                /* Open file for reading */
                int in_fd;
                if ((in_fd = open(tokens_get_token(tokens, i + 1), O_RDONLY, 0)) < 0) {
                    perror("open");
                    return -1;
                }

                /* Redirect stdin to the fd */
                if (dup2(in_fd, STDIN_FILENO) < 0) {
                    perror("dup2");
                    return -1;
                }
                close(in_fd);
            }

            /* Move the token pointer forward by 1 more to account for the file token*/
            i++;

        /* Handle normal args */
        } else {
            argv[cur_arg_i++] = cur_token;
        }
    }

    argv[cur_arg_i] = NULL;
    return 1;
}

/* Intialization procedures for this shell */
void init_shell() {
    /* Our shell is connected to standard input. */
    shell_terminal = STDIN_FILENO;

    /* Check if we are running interactively */
    shell_is_interactive = isatty(shell_terminal);

    if (shell_is_interactive) {
        /* If the shell is not currently in the foreground, we must pause the
         * shell until it becomes a foreground process. We use SIGTTIN to pause
         * the shell. When the shell gets moved to the foreground, we'll receive
         * a SIGCONT. */
        while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp())) {
            kill(-shell_pgid, SIGTTIN);
        }

        /* Saves the shell's process id */
        shell_pgid = getpid();

        /* Take control of the terminal */
        tcsetpgrp(shell_terminal, shell_pgid);

        /* Save the current termios to a variable, so it can be restored later.
         */
        tcgetattr(shell_terminal, &shell_tmodes);

        /* Set signal handlers */
        signal(SIGTTOU, SIG_IGN);
    }
}

int main(unused int argc, unused char *argv[]) {
    init_shell();

    static char line[4096];
    int line_num = 0;

    /* Only print shell prompts when standard input is not a tty */
    if (shell_is_interactive) {
        fprintf(stdout, "%d: ", line_num);
    }

    while (fgets(line, 4096, stdin)) {
        /* Split our line into words. */
        struct tokens *tokens = tokenize(line);

        /* Find which built-in function to run. */
        int fundex = lookup(tokens_get_token(tokens, 0));

        if (fundex >= 0) {
            cmd_table[fundex].fun(tokens);
        } else {

            /* Resolve command path */
            int resolve_path_result;
            char path[PATH_MAX];
            if ((resolve_path_result = resolve_path(tokens_get_token(tokens, 0), path)) != 1) {
                if (resolve_path_result == 2) 
                    fprintf(stderr, "%s: command not found\n", tokens_get_token(tokens, 0));
                else perror("path resolution");
                goto back_to_shell;
            }

            /* Flush all std fds */
            fflush(stdin);
            fflush(stdout);
            fflush(stderr);

            /* Fork a child to execute the binary */
            pid_t cpid = fork(), wpid;
            if (cpid == -1) {
                perror("fork");
                goto back_to_shell;
            }

            if (cpid > 0) { // Shell

                /* Foreground the child process */
                if (setpgid(cpid, cpid) == -1) {
                    perror("setpgid child");
                    exit(1);
                }
                tcsetpgrp(shell_terminal, cpid);

                /* Indicate that the shell is backgrounded */
                shell_is_interactive = 0;

                /* Wait for the binary to finish executing */
                int status;
                while ((wpid = waitpid(cpid, &status, 0)) > 0) {

                    /* Signal an error if waitpid returns -1 */
                    if (wpid == -1) perror("waitpid");

                    /* Foreground the shell again once the child stops */
                    if (WIFEXITED(status) || WIFSIGNALED(status)) {
                        tcsetpgrp(shell_terminal, shell_pgid);
                        tcsetattr(shell_terminal, TCSADRAIN, &shell_tmodes);
                        shell_is_interactive = 1;
                        break;
                    }
                }
            } 
            else { // Child

                /* Pack args into argv */
                int num_args = tokens_get_length(tokens);
                char *argv[num_args + 1];
                argv[0] = path;
                if (process_args(tokens, argv) == -1) {
                    perror("process_args: error");
                    exit(1);
                };

                /* Restore default signal handlers in the child */
                signal(SIGTTOU, SIG_DFL);

                /* Execute the binary */
                execv(path, argv);
                fprintf(stderr, "%s: %s\n", path, strerror(errno));
                exit(1);
            }
        }

    back_to_shell: 
        if (shell_is_interactive) {
            /* Only print shell prompts when standard input is not a tty. */
            fprintf(stdout, "%d: ", ++line_num);
        }

        /* Clean up memory. */
        tokens_destroy(tokens);
    }

    return 0;
}
