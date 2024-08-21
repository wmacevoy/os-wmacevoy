#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <sleep_seconds>\n", argv[0]);
        return 1;
    }

    int sleep_seconds = atoi(argv[1]);

    if (sleep_seconds < 0) {
        fprintf(stderr, "Please provide a non-negative number of seconds.\n");
        return 1;
    }

    pid_t process_id = getpid();
    printf("Current process ID: %d\n", process_id);

    sleep(sleep_seconds);

    printf("Exit from process %d\n", process_id);

    return 0;
}
