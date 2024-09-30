#include <iostream>
#include <vector>
#include <chrono>
#include <cstdlib>
#include <algorithm>

// Cache size in bytes (adjust as needed for your system)
constexpr size_t CACHE_SIZE = 8 * 1024 * 1024; // 8 MB

// Cache flush function
void flushCache() {
    std::vector<char> cache(CACHE_SIZE);
    std::fill(cache.begin(), cache.end(), 1);
    volatile char sum = 0;
    for (size_t i = 0; i < cache.size(); ++i) {
        sum += cache[i];
    }
    std::cout << "Cache flushed: " << static_cast<int>(sum) << std::endl; // Prevent compiler optimization
}

int main() {
    constexpr size_t SIZE = 2048; // Size of the 2D matrix
    std::vector<std::vector<int>> matrix(SIZE, std::vector<int>(SIZE, 1));

    // Measure row-major access
    flushCache();
    auto row_start = std::chrono::high_resolution_clock::now();
    volatile int row_sum = 0;
    for (size_t i = 0; i < SIZE; ++i) {
        for (size_t j = 0; j < SIZE; ++j) {
            row_sum += matrix[i][j];
        }
    }
    auto row_end = std::chrono::high_resolution_clock::now();
    auto row_duration = std::chrono::duration_cast<std::chrono::microseconds>(row_end - row_start).count();
    std::cout << "Row-major access sum: " << row_sum << ", Time: " << row_duration << " microseconds\n";

    // Measure column-major access
    flushCache();
    auto col_start = std::chrono::high_resolution_clock::now();
    volatile int col_sum = 0;
    for (size_t j = 0; j < SIZE; ++j) {
        for (size_t i = 0; i < SIZE; ++i) {
            col_sum += matrix[i][j];
        }
    }
    auto col_end = std::chrono::high_resolution_clock::now();
    auto col_duration = std::chrono::duration_cast<std::chrono::microseconds>(col_end - col_start).count();
    std::cout << "Column-major access sum: " << col_sum << ", Time: " << col_duration << " microseconds\n";

    return 0;
}
