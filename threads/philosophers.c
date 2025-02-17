#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

// Global variables for number of philosophers and maximum sleep time in ms.
int num_philosophers;
int max_sleep_time;

// Array of mutexes representing forks.
pthread_mutex_t *forks;

// Sleep for a specified number of milliseconds.
void msleep(int ms) {
    usleep(ms * 1000); // usleep takes microseconds
}

void* philosopher(void* arg) {
    int id = *((int*)arg);
    int left = id;
    int right = (id + 1) % num_philosophers;

    while (1) {
        // Philosopher is thinking.
        printf("Philosopher %d is thinking.\n", id);
        msleep(rand() % max_sleep_time);

        // Philosopher becomes hungry.
        printf("Philosopher %d is hungry.\n", id);

        // Pick up left fork.
        pthread_mutex_lock(&forks[left]);
        printf("Philosopher %d picked up left fork %d.\n", id, left);
        msleep(rand() % max_sleep_time);

        // Pick up right fork.
        pthread_mutex_lock(&forks[right]);
        printf("Philosopher %d picked up right fork %d and is eating.\n", id, right);
        msleep(rand() % max_sleep_time);

        // Philosopher finishes eating and puts down forks.
        pthread_mutex_unlock(&forks[right]);
        pthread_mutex_unlock(&forks[left]);
        printf("Philosopher %d finished eating and put down forks.\n", id);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <num_philosophers> <max_sleep_time_ms>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    num_philosophers = atoi(argv[1]);
    max_sleep_time = atoi(argv[2]);

    if (num_philosophers < 2) {
        fprintf(stderr, "There must be at least 2 philosophers.\n");
        exit(EXIT_FAILURE);
    }

    // Allocate and initialize mutexes for forks.
    forks = malloc(num_philosophers * sizeof(pthread_mutex_t));
    if (forks == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < num_philosophers; i++) {
        pthread_mutex_init(&forks[i], NULL);
    }

    // Create threads for philosophers.
    pthread_t *threads = malloc(num_philosophers * sizeof(pthread_t));
    int *ids = malloc(num_philosophers * sizeof(int));
    if (threads == NULL || ids == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    srand(time(NULL));
    for (int i = 0; i < num_philosophers; i++) {
        ids[i] = i;
        pthread_create(&threads[i], NULL, philosopher, &ids[i]);
    }

    // Wait for philosopher threads (this program runs indefinitely).
    for (int i = 0; i < num_philosophers; i++) {
        pthread_join(threads[i], NULL);
    }

    // Clean up (unreachable in this infinite loop, but good practice).
    free(threads);
    free(ids);
    free(forks);
    return 0;
}