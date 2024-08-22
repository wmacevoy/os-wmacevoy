cmake_minimum_required(VERSION 3.10)
project(CopyLibrary C)

# Set the C standard
set(CMAKE_C_STANDARD 99)

# Version of the shared library
set(VERSION 1.0.0)

# Add the source files for the library
add_library(copy_file SHARED src/copy_file.c)

# Set the library version
set_target_properties(copy_file PROPERTIES VERSION ${VERSION} SOVERSION 1)

# Specify the library output name for Unix-like systems
if(UNIX)
    set_target_properties(copy_file PROPERTIES OUTPUT_NAME "copy_file")
endif()

# Include directory for headers
target_include_directories(copy_file PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Add the executable that uses the shared library
add_executable(copy_command src/main_copy_command.c)
target_link_libraries(copy_command copy_file)

# Add the test executable
add_executable(test_copy_file src/test_copy_file.c)
target_link_libraries(test_copy_file copy_file)

# Enable testing
enable_testing()
add_test(NAME CopyFileTest COMMAND test_copy_file)
