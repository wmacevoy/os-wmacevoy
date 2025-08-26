#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>


int main() {
    int parent = getpid();
    int result = fork();
    if (result < 0) { 
        fprintf(stderr, "fork failed.\n");
        exit(1);
    }
    if (result == 0) { /* I am the child */
        usleep(1000);
        printf("I am the child with pid %d\n", getpid());
        exit(0);
    } else { /* I am the parent */
        printf("I am the parent with pid %d\n", getpid());
        usleep(2000);
        printf("I created child pid %d\n", result);
        exit(0);
    }
    return 0;
}