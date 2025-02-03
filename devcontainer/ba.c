#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

int sum(int n) {
    return n > 0 ? n + sum(n-1) : 0;
}

// argc=3, argv={"ls","-l",NULL}
int main(int argc, const char *argv[]) {
    pid_t parent_pid = getpid();
    pid_t child_pid = -1;

    printf("main lives at %p\n", &main);
    printf("sum lives at %p\n",&sum);
    printf("parent_pid lives at %p\n",&parent_pid);
    printf("child_pid lives at %p\n",&child_pid);

    pid_t status = fork();
    if (status == -1) {
        fprintf(stderr,"fork failed\n");
        exit(1);
    }
    if (status == 0) { 
        // child
        child_pid = getpid();
        fprintf(stdout,"child %d of %d\n",child_pid,parent_pid);
        sleep(4);
        execl("/bin/ls","ls","-l",NULL);
        fprintf(stdout,"child %d exec failed\n",child_pid);
    } else {
        // parent
        child_pid = status;
        fprintf(stdout,"parent %d forked child %d\n",
            parent_pid,child_pid);
        waitpid(child_pid,&status,0);
        fprintf(stdout,"parent %d done\n",parent_pid);
    }
    return 0;
}