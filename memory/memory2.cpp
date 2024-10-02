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

template <typename Store>
struct Benchmark
{
    Store matrix;
    bool row_major;

    int cacheFlushSum;
    void flushCache()
    {
        std::vector<char> cache(CACHE_SIZE);
        std::fill(cache.begin(), cache.end(), 1);
        volatile char sum = 0;
        for (size_t i = 0; i < cache.size(); ++i)
        {
            sum += cache[i];
        }
        cacheFlushSum = sum;
    }

    void randomize()
    {
        for (size_t i = 0; i < SIZE; ++i)
        {
            for (size_t j = 0; j < SIZE; ++j)
            {
                matrix[i][j] = rand();
            }
        }
    }

    uint32_t time(std::function<int()> benchmark)
    {
        randomize();
        flushCache();
        auto start = std::chrono::high_resolution_clock::now();
        int result = benchmark();
        auto stop = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
        return duration;
    }

    int row_major_benchmark()
    {
        int sum = 0;
        for (size_t i = 0; i < SIZE; ++i)
        {
            for (size_t j = 0; j < SIZE; ++j)
            {
                sum += matrix[i][j];
            }
        }
        return sum;
    }

    int column_major_benchmark()
    {
        int sum = 0;
        for (size_t j = 0; j < SIZE; ++j)
        {
            for (size_t i = 0; i < SIZE; ++i)
            {
                sum += matrix[i][j];
            }
        }
        return sum;
    }

    uint32_t profile()
    {
        uint32_t result;
        if (row_major)
        {
            result = time([&]() { return row_major_benchmark(); });
        }
        else
        {
            result = time([&]() { return column_major_benchmark(); });
        }
        return result;
    }
    Benchmark(bool _row_major) : row_major(_row_major) {}
};

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
        using Store = std::vector<std::vector<int>>;
        auto benchmark = std::make_shared<Benchmark<Store>>(row_major);
        benchmark->matrix = std::vector<std::vector<int>>(SIZE, std::vector<int>(SIZE, 1));

        milliseconds = benchmark->profile();
    }
    else
    {
        using Store = std::array<std::array<int, SIZE>, SIZE>;
        auto benchmark = std::make_shared<Benchmark<Store>>(row_major);

        milliseconds = benchmark->profile();
    }

    std::cout << "time " << argv[1] << " " << argv[2] << " = " << milliseconds << " ms" << std::endl;

    return 0;
}