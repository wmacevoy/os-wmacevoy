// bench_mem.cpp
// High-resolution memory access benchmarks with cache randomization.
// Build: g++ -std=c++20 -O3 -march=native -DNDEBUG bench_mem.cpp -o bench_mem

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <random>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using Clock = std::chrono::steady_clock;
using us    = std::chrono::microseconds;

// -------- Global sink to defeat over-optimization --------
static volatile std::uint64_t g_sink = 0;

// -------- RNG (deterministic unless you pass a different seed) --------
struct RNG {
    std::mt19937_64 eng;
    explicit RNG(std::uint64_t seed = 0xC0FFEE123456789ULL) : eng(seed) {}
    std::uint64_t u64() { return eng(); }
    template <typename T>
    T uniform(T lo, T hi) { // inclusive lo, inclusive hi
        std::uniform_int_distribution<long long> dist((long long)lo, (long long)hi);
        return (T)dist(eng);
    }
};

// -------- Dataset (built once, not in the timed regions) --------
struct Dataset {
    std::vector<int> big_vec;                // data for sequential/random access & cache busting
    std::vector<int> rand_indices;           // precomputed random indices for vector random access
    std::map<int,int> m;                     // requested: 1,000,000 entries
    std::unordered_map<int,int> um;          // same keys as map for comparison

    explicit Dataset(std::size_t vec_size = 10'000'000,  // ~40 MB of ints
                     std::size_t bust_size = 32'000'000, // ~128 MB of ints for cache busting
                     std::size_t map_size = 1'000'000,
                     std::uint64_t seed = 0xBADC0FFEEULL) 
    {
        RNG rng(seed);

        // big_vec: contiguous data (we make it max(vec_size, bust_size) so it serves both roles)
        std::size_t N = std::max(vec_size, bust_size);
        big_vec.resize(N);
        std::iota(big_vec.begin(), big_vec.end(), 1);

        // random indices for vector random access (length = vec_size)
        rand_indices.resize(vec_size);
        for (std::size_t i = 0; i < vec_size; ++i) {
            rand_indices[i] = (int)rng.uniform<std::size_t>(0, vec_size - 1);
        }

        // map & unordered_map with one million entries
        // keys are shuffled to avoid trivial in-order artifacts for lookups
        std::vector<int> keys(map_size);
        std::iota(keys.begin(), keys.end(), 0);
        std::shuffle(keys.begin(), keys.end(), rng.eng);

        m.clear();
        m.insert(m.begin(), {0,0}); // ensure tree exists before bulk (minor)
        for (std::size_t i = 0; i < map_size; ++i) {
            m.emplace(keys[i], (int)(keys[i] ^ 0x5a5a5a5a));
        }

        um.reserve(map_size * 2);
        for (std::size_t i = 0; i < map_size; ++i) {
            um.emplace(keys[i], (int)(keys[i] ^ 0x5a5a5a5a));
        }
    }
};

// -------- Cache buster: random touches on a large portion of big_vec --------
static void cache_buster(Dataset& ds, RNG& rng, std::size_t touches = 5'000'000) {
    // Randomly touch many elements spread across big_vec to invalidate caches/TLBs somewhat.
    // Not perfect, but effective enough and platform-agnostic.
    std::size_t N = ds.big_vec.size();
    volatile std::uint64_t s = 0; // local volatile to ensure the loop isn't optimized away
    for (std::size_t i = 0; i < touches; ++i) {
        std::size_t idx = rng.uniform<std::size_t>(0, N - 1);
        s += (unsigned)ds.big_vec[idx];
    }
    g_sink += s;
}

// -------- Benchmark harness plumbing --------
struct ResultRow {
    std::string test_name;
    int repeats;         // 1, 5, or 100
    double usec;         // total microseconds for the repeats
};

struct Test {
    std::string name;
    std::string desc;
    // The body returns a 64-bit checksum to prevent optimization and sanity-check results
    std::function<std::uint64_t(Dataset& ds, RNG& rng)> body;
};

static std::vector<Test> make_tests() {
    std::vector<Test> tests;

    // 1) Sequential vector sum (contiguous access)
    tests.push_back({
        "vec_seq",
        "Sum over vector sequentially (contiguous access).",
        [](Dataset& ds, RNG&) -> std::uint64_t {
            std::uint64_t sum = 0;
            // Use only the "logical" vector portion used for vec tests (ds.rand_indices size)
            std::size_t N = ds.rand_indices.size();
            // We sum the first N elements of big_vec (contiguous)
            for (std::size_t i = 0; i < N; ++i) sum += (unsigned)ds.big_vec[i];
            g_sink += sum;
            return sum;
        }
    });

    // 2) Random vector sum using precomputed random indices
    tests.push_back({
        "vec_rand",
        "Sum vector elements at random indices (random access).",
        [](Dataset& ds, RNG&) -> std::uint64_t {
            std::uint64_t sum = 0;
            std::size_t N = ds.rand_indices.size();
            for (std::size_t i = 0; i < N; ++i) {
                int idx = ds.rand_indices[i];
                sum += (unsigned)ds.big_vec[(std::size_t)idx];
            }
            g_sink += sum;
            return sum;
        }
    });

    // 3) std::map iteration (in-order traversal, pointer-chasing)
    tests.push_back({
        "map_iter",
        "Iterate over std::map and sum values (tree in-order traversal).",
        [](Dataset& ds, RNG&) -> std::uint64_t {
            std::uint64_t sum = 0;
            for (const auto& kv : ds.m) sum += (unsigned)kv.second;
            g_sink += sum;
            return sum;
        }
    });

    // 4) std::map random lookups (pointer-chasing lookups)
    tests.push_back({
        "map_rand",
        "Random std::map lookups by key and sum found values.",
        [](Dataset& ds, RNG& rng) -> std::uint64_t {
            std::uint64_t sum = 0;
            // Do a fixed number of random lookups to keep time reasonable
            const std::size_t lookups = 1'000'000;
            for (std::size_t i = 0; i < lookups; ++i) {
                int k = (int)rng.uniform<std::size_t>(0, ds.m.size() - 1);
                auto it = ds.m.find(k);
                if (it != ds.m.end()) sum += (unsigned)it->second;
            }
            g_sink += sum;
            return sum;
        }
    });

    // 5) std::unordered_map random lookups (hash table)
    tests.push_back({
        "umap_rand",
        "Random std::unordered_map lookups by key and sum values.",
        [](Dataset& ds, RNG& rng) -> std::uint64_t {
            std::uint64_t sum = 0;
            const std::size_t lookups = 1'000'000;
            for (std::size_t i = 0; i < lookups; ++i) {
                int k = (int)rng.uniform<std::size_t>(0, ds.um.size() - 1);
                auto it = ds.um.find(k);
                if (it != ds.um.end()) sum += (unsigned)it->second;
            }
            g_sink += sum;
            return sum;
        }
    });

    return tests;
}

// -------- Timing helper --------
template <class F>
static double time_us(F&& f) {
    auto t0 = Clock::now();
    f();
    auto t1 = Clock::now();
    return (double)std::chrono::duration_cast<us>(t1 - t0).count();
}

// -------- CLI & main --------
static void print_usage(const std::vector<Test>& tests) {
    std::cerr << "Usage: bench_mem [--all|--list|TEST ...] [--seed=N]\n\n";
    std::cerr << "Tests:\n";
    for (auto& t : tests) {
        std::cerr << "  " << std::left << std::setw(12) << t.name << " - " << t.desc << "\n";
    }
    std::cerr << "\nExamples:\n";
    std::cerr << "  ./bench_mem --all\n";
    std::cerr << "  ./bench_mem vec_seq map_rand --seed=12345\n";
}

int main(int argc, char** argv) {
    std::vector<Test> tests = make_tests();

    // Defaults
    bool run_all = false;
    std::uint64_t seed = 0xDEADBEEF42ULL;
    std::vector<std::string> selected;

    // Parse args
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--list") {
            print_usage(tests);
            return 0;
        } else if (a == "--all") {
            run_all = true;
        } else if (a.rfind("--seed=",0) == 0) {
            seed = std::stoull(a.substr(7));
        } else {
            selected.push_back(a);
        }
    }
    if (!run_all && selected.empty()) {
        print_usage(tests);
        return 1;
    }

    // Filter selected tests
    std::vector<Test> to_run;
    if (run_all) {
        to_run = tests;
    } else {
        for (auto& name : selected) {
            auto it = std::find_if(tests.begin(), tests.end(),
                [&](const Test& t){ return t.name == name; });
            if (it != tests.end()) to_run.push_back(*it);
            else {
                std::cerr << "Unknown test: " << name << "\n";
                print_usage(tests);
                return 2;
            }
        }
    }

    // Build dataset (includes: std::map with 1,000,000 entries)
    std::cout << "Building dataset (this is not timed)...\n";
    Dataset ds; // uses defaults described in struct
    RNG rng(seed);

    // Repeats to reveal caching effects
    const int repeats_set[3] = {1, 5, 100};

    // Collect results
    std::vector<ResultRow> results;
    results.reserve(to_run.size() * 3);

    // Run
    for (const auto& test : to_run) {
        for (int repeats : repeats_set) {
            // Scramble cache before each measurement
            cache_buster(ds, rng);

            // Time the block run 'repeats' times
            std::uint64_t checksum = 0;
            double elapsed_us = time_us([&](){
                for (int r = 0; r < repeats; ++r) {
                    checksum += test.body(ds, rng);
                }
            });

            // Prevent over-optimization
            g_sink += checksum;

            results.push_back({test.name, repeats, elapsed_us});
            std::cout << std::left << std::setw(12) << test.name
                      << " x" << std::setw(3) << repeats
                      << " -> " << std::setw(10) << (std::uint64_t)elapsed_us << " us"
                      << "  (checksum=" << checksum << ")\n";
        }
    }

    // Summary
    std::cout << "\n=== Summary (microseconds) ===\n";
    // Pretty table header
    std::cout << std::left << std::setw(16) << "test"
              << std::right << std::setw(12) << "x1"
              << std::setw(12) << "x5"
              << std::setw(12) << "x100"
              << std::setw(12) << "x5/x1"
              << std::setw(12) << "x100/x1"
              << "\n";

    // Group by test name
    struct Row { double x1=-1, x5=-1, x100=-1; };
    std::map<std::string, Row> table;
    for (const auto& r : results) {
        auto& row = table[r.test_name];
        if (r.repeats == 1)   row.x1   = r.usec;
        if (r.repeats == 5)   row.x5   = r.usec;
        if (r.repeats == 100) row.x100 = r.usec;
    }

    for (const auto& [name, row] : table) {
        double r51   = (row.x1   > 0) ? row.x5   / row.x1   : -1;
        double r1001 = (row.x1   > 0) ? row.x100 / row.x1   : -1;
        std::cout << std::left  << std::setw(16) << name
                  << std::right << std::setw(12) << (std::uint64_t)row.x1
                  << std::setw(12) << (std::uint64_t)row.x5
                  << std::setw(12) << (std::uint64_t)row.x100
                  << std::setw(12) << std::fixed << std::setprecision(2) << r51
                  << std::setw(12) << std::fixed << std::setprecision(2) << r1001
                  << "\n";
    }

    // Use g_sink so the compiler can't remove anything
    std::cout << "\n[anti-opt sink] " << g_sink << "\n";
    return 0;
}