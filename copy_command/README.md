# Copy Command

## Status
 * ![Test Status (Windows|MacOS|Ubuntu)](https://github.com/wmacevoy/os-wmacevoy/actions/workflows/copy_command.yml/badge.svg) [action](https://github.com/wmacevoy/os-wmacevoy/blob/main/.github/workflows/copy_command.yml)

 * ![Test Status (Debian|Alpine x ARM|AMD)](https://github.com/wmacevoy/os-wmacevoy/actions/workflows/copy_command_cloud.yml/badge.svg) [action](https://github.com/wmacevoy/os-wmacevoy/blob/main/.github/workflows/copy_command_cloud.yml)

This project contains a cross-platform command-line utility for copying files.

## Features

- Works on Windows, macOS, and Linux
- Uses native APIs for file operations
- Simple and easy to use

## Prerequisites

### Install CMake

Before building the project, ensure that CMake is installed on your system.

- **Windows:**
  - Download and install CMake from the [official website](https://cmake.org/download/).
  - Alternatively, install CMake using [Chocolatey](https://chocolatey.org/):
    ```sh
    choco install cmake --installargs 'ADD_CMAKE_TO_PATH=System' --yes
    ```

- **macOS:**
  - Install CMake using [Homebrew](https://brew.sh/):
    ```sh
    brew install cmake
    ```

- **Linux (Ubuntu):**
  - Install CMake using `apt`:
    ```sh
    sudo apt-get update
    sudo apt-get install -y cmake build-essential
    ```

### Install a C Compiler

Ensure that you have a C compiler installed on your system:

- **Windows:** Visual Studio provides the necessary compiler. Make sure to install the "Desktop development with C++" workload.
- **macOS:** Xcode or the Xcode command-line tools include `clang`.
  ```sh
  xcode-select --install
  ```
- **linux:** Install GCC:
  ```sh
  sudo apt-get install -y gcc
  ```

### Build

- **Windows:**
  ```sh
  cmake -S . -B build
  cmake --build build --config Release
  ```
- **macOS:**
  ```sh
  cmake -S . -B build
  cmake --build build
  ```
- **linux:**
  ```sh
  cmake -S . -B build
  cmake --build build
  ```

## Test

- **Windows:**
  ```sh
  ctest --test-dir build --output-on-failure -C Release
  ```
- **macOS:**
  ```sh
  ctest --test-dir build --output-on-failure
  ```
- **linux:**
  ```sh
  ctest --test-dir build --output-on-failure
  ```
