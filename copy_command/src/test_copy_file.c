#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define TEMP_FILE_TEMPLATE "temp_XXXXXX"
#else
#include <unistd.h>
#endif

#include "copy_file.h"

int main() {
    char source_template[] = "temp_source_XXXXXX";
    char destination_template[] = "temp_destination_XXXXXX";

    FILE *source_file = NULL;
    FILE *dest_file = NULL;

#ifdef _WIN32
    // Windows: Use tmpfile_s
    char source_filename[L_tmpnam_s];
    char destination_filename[L_tmpnam_s];

    if (tmpnam_s(source_filename, L_tmpnam_s) != 0 || tmpnam_s(destination_filename, L_tmpnam_s) != 0) {
        fprintf(stderr, "Failed to create temporary file names.\n");
        return 1;
    }

    fopen_s(&source_file, source_filename, "w");
    fopen_s(&dest_file, destination_filename, "w");

#else
    // Unix-like systems: Use mkstemp
    int src_fd = mkstemp(source_template);
    int dest_fd = mkstemp(destination_template);

    if (src_fd == -1 || dest_fd == -1) {
        perror("Failed to create temporary files");
        return 1;
    }

    source_file = fdopen(src_fd, "w");
    dest_file = fdopen(dest_fd, "w");
#endif

    if (!source_file || !dest_file) {
        perror("Failed to open temporary files");
        return 1;
    }

    const char *content = "This is a test file.";
    fwrite(content, sizeof(char), strlen(content), source_file);
    fclose(source_file);

    // Copy the file using copy_file function
    if (copy_file(source_template, destination_template) != 0) {
        fprintf(stderr, "File copy failed.\n");
        return 1;
    }

    // Verify that the files are identical
    FILE *src = fopen(source_template, "rb");
    FILE *dest = fopen(destination_template, "rb");

    if (!src || !dest) {
        perror("Failed to open files for comparison");
        return 1;
    }

    int result = 0;
    int ch1, ch2;
    while (((ch1 = fgetc(src)) != EOF) && ((ch2 = fgetc(dest)) != EOF)) {
        if (ch1 != ch2) {
            result = 1;
            break;
        }
    }

    fclose(src);
    fclose(dest);

    // Clean up temporary files
    remove(source_template);
    remove(destination_template);

    
    if (result == 0) {
        printf("Test passed: Files are identical.\n");
        return 0;
    } else {
        printf("Test failed: Files are different.\n");
        return 1;
    }
}
