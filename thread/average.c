#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

// Number of threads
#define NUM_THREADS 8

// Range of values (0 to N-1)
int N;

// Mutex for protecting the shared sum
pthread_mutex_t mutex_sum;

// Shared variable to store the total sum
double total_sum = 0.0;

// Sample function to compute f(x)
double f(int x) {
    return x * x; // Example: f(x) = x^2
}

// Thread function to compute partial sum
void* compute_partial_sum(void* arg) {
    int thread_id = *(int*)arg;
    int range_size = N / NUM_THREADS;
    int start = thread_id * range_size;
    int end = (thread_id == NUM_THREADS - 1) ? N : start + range_size; // Handle last range

    double partial_sum = 0.0;
    for (int i = start; i < end; i++) {
        partial_sum += f(i);
    }

    // Lock the mutex before updating the total sum
    pthread_mutex_lock(&mutex_sum);
    total_sum += partial_sum;
    pthread_mutex_unlock(&mutex_sum);

    pthread_exit(NULL);
}

int main() {
    printf("Enter the value of N (the upper range limit): ");
    scanf("%d", &N);

    // Array to hold thread IDs
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];

    // Initialize mutex
    pthread_mutex_init(&mutex_sum, NULL);

    // Create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        if (pthread_create(&threads[i], NULL, compute_partial_sum, (void*)&thread_ids[i]) != 0) {
            fprintf(stderr, "Error creating thread %d\n", i);
            return 1;
        }
    }

    // Wait for all threads to finish
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // Compute the average
    double average = total_sum / N;

    printf("Average value of f(x) over range 0 to %d: %f\n", N - 1, average);

    // Destroy the mutex
    pthread_mutex_destroy(&mutex_sum);

    return 0;
}
