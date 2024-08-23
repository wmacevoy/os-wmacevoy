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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <source_file> <destination_file>\n", argv[0]);
        return 1;
    }

    const char *source = argv[1];
    const char *destination = argv[2];

    if (copy_file(source, destination) != 0) {
        fprintf(stderr, "File copy failed.\n");
        return 1;
    }

    printf("File copied successfully.\n");
    return 0;
}
