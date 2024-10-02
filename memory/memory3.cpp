#include <iostream>
#include <vector>
#include <chrono>
#include <cstdlib>
#include <algorithm>
#include <array>
#include <string.h>
#include <memory>
#include <stdint.h>
#include <functional>

// Cache size in bytes (adjust as needed for your system)
constexpr size_t CACHE_SIZE = 8 * 1024 * 1024; // 8 MB
constexpr size_t SIZE = 4096;                  // Size of the 2D matrix

int flushCache()
{
    std::vector<char> cache(CACHE_SIZE);
    std::fill(cache.begin(), cache.end(), 1);
    volatile char sum = 0;
    for (size_t i = 0; i < cache.size(); ++i)
    {
        sum += cache[i];
    }
    return sum;
}

template <typename Matrix>
void randomize(Matrix &matrix)
{
    for (size_t i = 0; i < SIZE; ++i)
    {
        for (size_t j = 0; j < SIZE; ++j)
        {
            matrix[i][j] = rand();
        }
    }
}

int vector_row_major_benchmark()
{
    auto matrix_ptr = new std::vector<std::vector<int>>(SIZE, std::vector<int>(SIZE, 1));
    auto &matrix = *matrix_ptr;
    randomize(matrix);
    flushCache();

    auto start = std::chrono::high_resolution_clock::now();
    int sum = 0;
    for (size_t i = 0; i < SIZE; ++i)
    {
        int inner_sum = 0;
        for (size_t j = 0; j < SIZE; ++j)
        {
            inner_sum += matrix[i][j];
        }
        sum += inner_sum;
    }

    delete matrix_ptr;
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
    return duration;
}

int vector_column_major_benchmark()
{
    auto matrix_ptr = new std::vector<std::vector<int>>(SIZE, std::vector<int>(SIZE, 1));
    auto &matrix = *matrix_ptr;
    randomize(matrix);
    flushCache();

    auto start = std::chrono::high_resolution_clock::now();
    int sum = 0;
    for (size_t j = 0; j < SIZE; ++j)
    {
        int inner_sum = 0;
        for (size_t i = 0; i < SIZE; ++i)
        {
            inner_sum += matrix[i][j];
        }
        sum += inner_sum;
    }

    delete matrix_ptr;
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
    return duration;
}

int array_row_major_benchmark()
{
    auto matrix_ptr = new std::array<std::array<int, SIZE>, SIZE>();
    auto &matrix = *matrix_ptr;
    randomize(matrix);
    flushCache();

    auto start = std::chrono::high_resolution_clock::now();
    int sum = 0;
    for (size_t i = 0; i < SIZE; ++i)
    {
        int inner_sum = 0;
        for (size_t j = 0; j < SIZE; ++j)
        {
            inner_sum += matrix[i][j];
        }
        sum += inner_sum;
    }

    delete matrix_ptr;
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
    return duration;
}

int array_column_major_benchmark()
{
    auto matrix_ptr = new std::array<std::array<int, SIZE>, SIZE>();
    auto &matrix = *matrix_ptr;
    randomize(matrix);
    flushCache();

    auto start = std::chrono::high_resolution_clock::now();
    int sum = 0;
    for (size_t j = 0; j < SIZE; ++j)
    {
        int inner_sum = 0;
        for (size_t i = 0; i < SIZE; ++i)
        {
            inner_sum += matrix[i][j];
        }
        sum += inner_sum;
    }

    delete matrix_ptr;
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
    return duration;
}

int main(int argc, const char *argv[])
{
    bool use_array = (strcmp(argv[1], "array") == 0);
    bool use_vector = (strcmp(argv[1], "vector") == 0);
    bool row_major = (strcmp(argv[2], "row-major") == 0);
    bool column_major = (strcmp(argv[2], "column-major") == 0);

    if (!((use_array || use_vector)) && (row_major || column_major))
    {
        printf("usage: memory [array|vector] [row-major|column-major]\n");
        exit(1);
    }

    uint32_t milliseconds = 0;
    if (use_vector)
    {
        if (row_major)
        {
            milliseconds = vector_row_major_benchmark();
        }
        else
        {
            milliseconds = vector_column_major_benchmark();
        }
    }
    else
    {
        if (row_major)
        {
            milliseconds = array_row_major_benchmark();
        }
        else
        {
            milliseconds = array_column_major_benchmark();
        }
    }

    std::cout << "time " << argv[1] << " " << argv[2] << " = " << milliseconds << " ms" << std::endl;

    return 0;
}