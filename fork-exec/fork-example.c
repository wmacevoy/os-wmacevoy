#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>   // for uintptr_t

int main();
int child(int child_pid, int parent_pid);
int parent(int child_pid, int parent_pid);

static void print_function_addrs(void) {
    /* Converting function pointers to integers (uintptr_t) and then to void*
       is implementation-defined but works on common UNIX/POSIX targets. */
    printf("addr(main)  = %p\n",  (void*)(uintptr_t)(void*)&main);
    printf("addr(child) = %p\n",  (void*)(uintptr_t)(void*)&child);
    printf("addr(parent)= %p\n",  (void*)(uintptr_t)(void*)&parent);
}

int main(void) {
    int parent_pid = getpid();
    int child_pid = -1;

    /* Heap object from main (before fork) */
    double *main_heap = (double*)malloc(sizeof *main_heap);
    if (!main_heap) { perror("malloc"); exit(1); }
    *main_heap = 3.14159;

    printf("=== In main (pre-fork), pid=%d ===\n", parent_pid);
    print_function_addrs();
    printf("&child_pid (main stack)  = %p\n", (void*)&child_pid);
    printf("&parent_pid (main stack) = %p\n", (void*)&parent_pid);
    printf("main_heap (heap)         = %p (value=%f)\n", (void*)main_heap, *main_heap);
    printf("----------------------------------------\n");

    int result = fork();
    if (result < 0) {
        fprintf(stderr, "fork failed.\n");
        exit(1);
    }
    if (result == 0) { /* child */
        child_pid = getpid();
        /* Each process now has its own address space. This child will also
           allocate its own heap double so you can compare addresses. */
        return child(child_pid, parent_pid);
    } else {           /* parent */
        child_pid = result;
        return parent(child_pid, parent_pid);
    }
}

int child(int child_pid, int parent_pid) {
    double *child_heap = (double*)malloc(sizeof *child_heap);
    if (!child_heap) { perror("malloc"); _exit(1); }
    *child_heap = 2.71828;

    printf("=== In child, pid=%d (parent pid as seen by main=%d) ===\n",
           getpid(), parent_pid);
    print_function_addrs();
    printf("child_pid value          = %d\n", child_pid);
    printf("parent_pid value         = %d\n", parent_pid);
    printf("&child_pid (child stack) = %p\n", (void*)&child_pid);
    printf("&parent_pid (child stack)= %p\n", (void*)&parent_pid);
    printf("child_heap (heap)        = %p (value=%f)\n", (void*)child_heap, *child_heap);
    printf("----------------------------------------\n");

    /* Not strictly needed before process exit, but good hygiene: */
    free(child_heap);
    return 0;
}

int parent(int child_pid, int parent_pid) {
    double *parent_heap = (double*)malloc(sizeof *parent_heap);
    if (!parent_heap) { perror("malloc"); _exit(1); }
    *parent_heap = 1.41421;

    printf("=== In parent, pid=%d (child pid=%d) ===\n",
           getpid(), child_pid);
    print_function_addrs();
    printf("child_pid value           = %d\n", child_pid);
    printf("parent_pid value          = %d\n", parent_pid);
    printf("&child_pid (parent stack) = %p\n", (void*)&child_pid);
    printf("&parent_pid (parent stack)= %p\n", (void*)&parent_pid);
    printf("parent_heap (heap)        = %p (value=%f)\n", (void*)parent_heap, *parent_heap);
    printf("----------------------------------------\n");

    free(parent_heap);
    return 0;
}
