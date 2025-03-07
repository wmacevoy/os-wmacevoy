#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <utility>
#include <stdlib.h>
#include <string>
#include <iostream>

// Define a Pixel with red, green, and blue channels.
struct Pixel
{
    uint8_t r, g, b;
};

// Bitmap image represented as a 2D std::array.
// Here, ROWS represents the image height and COLS the image width.
template <std::size_t ROWS, std::size_t COLS>
struct Bitmap
{
    std::array<std::array<Pixel, COLS>, ROWS> data;

    // Row-first traversal: iterates rows then columns.
    // The lambda function 'f' is applied to each pixel.
    template <typename Func>
    void traverseRowFirst(Func f) const
    {
        for (std::size_t row = 0; row < ROWS; ++row)
            for (std::size_t col = 0; col < COLS; ++col)
                f(data[row][col]);
    }

    // Column-first traversal: iterates columns then rows.
    template <typename Func>
    void traverseColumnFirst(Func f) const
    {
        for (std::size_t col = 0; col < COLS; ++col)
            for (std::size_t row = 0; row < ROWS; ++row)
                f(data[row][col]);
    }
};

// Chronograph function: times a lambda function and returns both the result and the elapsed duration.
template <typename F>
auto chronograph(F &&func)
{
    auto start = std::chrono::high_resolution_clock::now();
    auto result = func();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = end - start;
    return std::make_pair(result, duration);
}

    // Define the image dimensions.
    constexpr std::size_t height = 2160; // rows
    constexpr std::size_t width = 4096;  // columns
    Bitmap<height, width> image;

int main(int argc, const char *argv[])
{
    std::string orient = argv[1];
    int loops = atoi(argv[2]);

    // Create a 1920x1080 bitmap image.

    // Initialize the image with some dummy data.
    // Each pixel's red and green channels are based on the row and column indices.
    for (std::size_t row = 0; row < height; ++row)
    {
        for (std::size_t col = 0; col < width; ++col)
        {
            image.data[row][col] = Pixel{
                static_cast<uint8_t>(row % 256),
                static_cast<uint8_t>(col % 256),
                0 // Blue channel set to 0.
            };
        }
    }

    // Time a row-first traversal lambda.
    std::cout << "orientation: " << orient << std::endl;
    std::cout << "loops: " << loops << std::endl;
    if (orient == "row")
    {
        auto [sumRow, rowDuration] = chronograph([&]()
                                                 {
        int sum = 0;  // 'volatile' prevents optimization of the loop.
        for (int i=0; i<loops; ++i) {
        image.traverseRowFirst([&](const Pixel& p) {
            sum += p.r + p.g + p.b;
        });
    }
        return sum; });
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(rowDuration).count();
        std::cout << "row sum=" << sumRow << " in " << ms << " ms" << std::endl;
    }
    if (orient == "column")
    {
        // Time a column-first traversal lambda.
        auto [sumCol, colDuration] = chronograph([&]()
                                                 {
        int sum = 0;
        for (int i=0; i<loops; ++i) {
        image.traverseColumnFirst([&](const Pixel& p) {
            sum += p.r + p.g + p.b;
        });
    }
        return sum; });

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(colDuration).count();
        std::cout << "row sum=" << sumCol << " in " << ms << " ms" << std::endl;

    }

    // The variables 'rowDuration' and 'colDuration' now hold the execution times.
    // No IO is performed as per the requirement.
    return 0;
}