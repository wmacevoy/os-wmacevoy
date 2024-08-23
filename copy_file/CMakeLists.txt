cmake_minimum_required(VERSION 3.10)
project(CopyCommand C)

# Set the C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Source files (use copy_command.c instead of main.c)
set(SOURCE_FILES copy_command.c)

# Create an executable
add_executable(copy_command ${SOURCE_FILES})

# Enable testing
enable_testing()

# Add a custom command to generate a test input file
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/test_input.txt
    COMMAND ${CMAKE_COMMAND} -E echo "This is a test file." > ${CMAKE_BINARY_DIR}/test_input.txt
    COMMENT "Generating test input file"
)

# Add a custom target that depends on the test input file
add_custom_target(GenerateTestFile ALL DEPENDS ${CMAKE_BINARY_DIR}/test_input.txt)

# Add a test that runs the copy command
add_test(
    NAME CopyTest
    COMMAND $<TARGET_FILE:copy_command> ${CMAKE_BINARY_DIR}/test_input.txt ${CMAKE_BINARY_DIR}/test_output.txt
)

# Ensure the test input file is generated before running the test
add_custom_command(
    TARGET copy_command
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target GenerateTestFile
)

# Clean up after the test
add_test(
    NAME CleanupTestOutput
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/test_input.txt ${CMAKE_BINARY_DIR}/test_output.txt
)
