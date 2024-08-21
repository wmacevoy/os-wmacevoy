#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#if defined(__x86_64__) || defined(_M_X64)
    #define ARCH_X86_64
#elif defined(__i386) || defined(_M_IX86)
    #define ARCH_X86_32
#elif defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
    #define ARCH_ARM64
#else
    #error "Unsupported architecture"
#endif

void print_program_counter_and_stack_pointer(const char *message) {
    void *stack_pointer;
    void *program_counter;

#ifdef ARCH_X86_64
    asm volatile("movq %%rsp, %0" : "=r"(stack_pointer));
    asm volatile("leaq (%%rip), %0" : "=r"(program_counter));
#elif defined(ARCH_X86_32)
    asm volatile("movl %%esp, %0" : "=r"(stack_pointer));
    asm volatile("leal (%%eip), %0" : "=r"(program_counter));
#elif defined(ARCH_ARM64)
    asm volatile("mov %0, sp" : "=r"(stack_pointer));
    asm volatile("adr %0, ." : "=r"(program_counter));
#else
    printf("Unsupported architecture\n");
    return;
#endif

    printf("%s\n", message);
    printf("Program Counter: %p\n", program_counter);
    printf("Stack Pointer: %p\n", stack_pointer);
}

int fibonacci(int n) {
    print_program_counter_and_stack_pointer("Entering fibonacci");
    if (n <= 1) {
        return n;
    }
    int result = fibonacci(n - 1) + fibonacci(n - 2);
    print_program_counter_and_stack_pointer("Exiting fibonacci");
    return result;
}

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

    int n = 5; // Example value for Fibonacci calculation
    printf("Calculating fibonacci(%d):\n", n);
    int fib = fibonacci(n);
    printf("Fibonacci(%d) = %d\n", n, fib);

    printf("Exit from process %d\n", process_id);

    return 0;
}
