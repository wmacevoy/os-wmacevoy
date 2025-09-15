// dining_philosophers.c
// Compile:  gcc -O2 -pthread -o dining dining_philosophers.c
// Run:      ./dining 5 10

#define _XOPEN_SOURCE 700
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <stdatomic.h>

typedef struct {
    int id;
    int n;
    pthread_mutex_t *forks;
    atomic_bool *stop;
    unsigned int rng;
} Philosopher;

static void ms_sleep(unsigned ms) {
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static inline unsigned rand_ms(unsigned int *seed) {
    return (unsigned)(rand_r(seed) % 1000U);
}

static void think(Philosopher *p) {
    unsigned t = rand_ms(&p->rng);
    printf("Philosopher %d is thinking (%u ms)\n", p->id, t);
    fflush(stdout);
    ms_sleep(t);
}

static void eat(Philosopher *p) {
    unsigned t = rand_ms(&p->rng);
    printf("Philosopher %d is eating   (%u ms)\n", p->id, t);
    fflush(stdout);
    ms_sleep(t);
}

static void *philosopher_thread(void *arg) {
    Philosopher *p = (Philosopher *)arg;
    int left  = p->id;
    int right = (p->id + 1) % p->n;

    int first  = left;
    int second = right;
    if (p->id == p->n - 1) {
        first  = right;
        second = left;
    }

    while (!atomic_load_explicit(p->stop, memory_order_relaxed)) {
        think(p);

        pthread_mutex_lock(&p->forks[first]);
        pthread_mutex_lock(&p->forks[second]);

        eat(p);

        pthread_mutex_unlock(&p->forks[second]);
        pthread_mutex_unlock(&p->forks[first]);
    }
    return NULL;
}

static atomic_bool stop_flag = ATOMIC_VAR_INIT(0);

static void handle_sigint(int signo) {
    (void)signo;
    atomic_store(&stop_flag, 1);
}

int main(int argc, char **argv) {
    int N = 5;
    int seconds = 10;

    if (argc >= 2) N = atoi(argv[1]);
    if (argc >= 3) seconds = atoi(argv[2]);
    if (N < 2) {
        fprintf(stderr, "N must be >= 2 (got %d)\n", N);
        return 1;
    }
    if (seconds <= 0) seconds = 10;

    struct sigaction sa = {0};
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);

    pthread_t *threads = calloc((size_t)N, sizeof(pthread_t));
    pthread_mutex_t *forks = calloc((size_t)N, sizeof(pthread_mutex_t));
    Philosopher *phils = calloc((size_t)N, sizeof(Philosopher));
    if (!threads || !forks || !phils) {
        perror("calloc");
        return 1;
    }

    // Initialize stop flag before creating any threads
    atomic_store(&stop_flag, 0);

    // Initialize forks
    for (int i = 0; i < N; ++i) {
        pthread_mutex_init(&forks[i], NULL);
    }

    // Initialize philosophers
    unsigned int base_seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
    for (int i = 0; i < N; ++i) {
        phils[i].id = i;
        phils[i].n = N;
        phils[i].forks = forks;
        phils[i].stop = &stop_flag;
        phils[i].rng = base_seed + (unsigned)i * 2654435761u;
    }

    // Launch philosopher threads
    for (int i = 0; i < N; ++i) {
        if (pthread_create(&threads[i], NULL, philosopher_thread, &phils[i]) != 0) {
            perror("pthread_create");
            atomic_store(&stop_flag, 1);
            N = i;
            break;
        }
    }

    // Run for given time or until interrupted
    for (int s = 0; s < seconds && !atomic_load(&stop_flag); ++s) {
        sleep(1);
    }
    atomic_store(&stop_flag, 1);

    // Join threads and clean up
    for (int i = 0; i < N; ++i) {
        pthread_join(threads[i], NULL);
        pthread_mutex_destroy(&forks[i]);
    }
    free(phils);
    free(forks);
    free(threads);

    printf("Simulation finished.\n");
    return 0;
}