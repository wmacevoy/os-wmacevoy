#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define MAX_CMD_LEN 1024
#define MAX_ARG_LEN 100

void execute_command(char **args);

int main() {
    char command[MAX_CMD_LEN];
    char *args[MAX_ARG_LEN];
    char *token;
    int status;

    while (1) {
        // Print the shell prompt
        printf("tiny-shell> ");
        fflush(stdout);

        // Read the command from the user
        if (fgets(command, sizeof(command), stdin) == NULL) {
            perror("fgets failed");
            continue;
        }

        // Remove the newline character at the end of the command
        command[strcspn(command, "\n")] = '\0';

        // Tokenize the command into arguments
        int i = 0;
        token = strtok(command, " ");
        while (token != NULL && i < MAX_ARG_LEN - 1) {
            args[i++] = token;
            token = strtok(NULL, " ");
        }
        args[i] = NULL;

        // Check if the command is "cd"
        if (args[0] == NULL) {
            continue;  // empty command, do nothing
        } else if (strcmp(args[0], "cd") == 0) {
            if (args[1] == NULL) {
                fprintf(stderr, "cd: missing argument\n");
            } else if (chdir(args[1]) != 0) {
                perror("cd");
            }
        }
        // Check if the command is "echo"
        else if (strcmp(args[0], "echo") == 0) {
            for (int j = 1; args[j] != NULL; j++) {
                printf("%s ", args[j]);
            }
            printf("\n");
        }
        // Check if the command is "exit"
        else if (strcmp(args[0], "exit") == 0) {
            break;
        }
        // For any other command, fork and exec
        else {
            pid_t pid = fork();
            if (pid < 0) {
                perror("fork failed");
            } else if (pid == 0) {
                execute_command(args);
                exit(EXIT_FAILURE);
            } else {
                do {
                    waitpid(pid, &status, WUNTRACED);
                } while (!WIFEXITED(status) && !WIFSIGNALED(status));
            }
        }
    }

    return 0;
}

void execute_command(char **args) {
    if (execvp(args[0], args) == -1) {
        perror("tiny-shell");
    }
}
