#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

double p = 1.0;
int pathlen = 0;
char *path[4] = {0};
int win = 0;

int main() {
    // left or right
    if (fork()==0) { // right
        p *= 0.5;
        path[pathlen++]="right";
        p *= 1.0;
        path[pathlen++]="forward";
    } else {
        p *= 0.5;
        path[pathlen++]="left";
        if (fork()==0) {
            p *= 0.7;
            path[pathlen++]="pet dog";
            win = 1;
        } else {
            p *= 0.3;
            path[pathlen++]="pick up key";
        }
    }
    char msg[1024];
    snprintf(msg,sizeof(msg),"%0.4f %s:", p, (win ? "win" : "lose"));
    for (int i=0; i<pathlen; ++i) {
        strcat(msg," ");
        strcat(msg,path[i]);
    }
    printf("%s (pid %d)\n",msg,getpid());
    return 0;
}