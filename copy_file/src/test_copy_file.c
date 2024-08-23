#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <fcntl.h>
    #include <unistd.h>
#endif

#include "copy_file.h"

int main() {
    char source_template[] = "temp_source_XXXXXX";
    char destination_template[] = "temp_destination_XXXXXX";

#ifdef _WIN32
    char source_filename[L_tmpnam_s];
    char destination_filename[L_tmpnam_s];

    if (tmpnam_s(source_filename, L_tmpnam_s) != 0 || tmpnam_s(destination_filename, L_tmpnam_s) != 0) {
        fprintf(stderr, "Failed to create temporary file names.\n");
        return 1;
    }

    FILE *source_file = fopen(source_filename, "w");
#else
    int src_fd = mkstemp(source_template);
    int dest_fd = mkstemp(destination_template);

    FILE *source_file = fdopen(src_fd, "w");
    char *source_filename = source_template;
    char *destination_filename = destination_template;
#endif

    if (!source_file) {
        perror("Failed to open source file");
        return 1;
    }

    const char *content = "This is a test file.";
    fwrite(content, sizeof(char), strlen(content), source_file);
    fclose(source_file);

    printf("Source file: %s\n", source_filename);
    printf("Destination file: %s\n", destination_filename);

    // Copy the file using copy_file function
    if (copy_file(source_filename, destination_filename) != 0) {
        perror("Error during file copy");
        return 1;
    }

    // Verify that the files are identical
    FILE *src = fopen(source_filename, "rb");
    FILE *dest = fopen(destination_filename, "rb");

    if (!src || !dest) {
        perror("Failed to open files for comparison");
        return 1;
    }

    int result = 0;
    int ch1, ch2;
    int offset = 0;
    for (;;) {
      if (ch1 != EOF) ch1 = fgetc(src);
      if (ch2 != EOF) ch2 = fgetc(dest);
      if (ch1 != ch2) {
	result = 1;
	break;
      }
      if (ch1 == EOF && ch2 == EOF) {
	break;
      }
      ++offset;
    }

    fclose(src);
    fclose(dest);

    // Clean up temporary files
    //    remove(source_filename);
    //    remove(destination_filename);

    if (result == 0) {
        printf("Test passed: Files are identical.\n");
        return 0;
    } else {
        printf("Test failed: Files are different (ch1 = %d, ch2=%d at offset %d.\n",ch1,ch2,offset);
        return 1;
    }
}
