#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <fcntl.h>
    #include <unistd.h>
#endif

int copy_file(const char *source, const char *destination) {
#if defined(_WIN32) || defined(_WIN64)
    if (!CopyFile(source, destination, FALSE)) {
        fprintf(stderr, "Error: Unable to copy file. Error code: %lu\n", GetLastError());
        return 1;
    }
#else
    int src_fd = open(source, O_RDONLY);
    if (src_fd < 0) {
        perror("Error opening source file");
        return 1;
    }

    int dst_fd = open(destination, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
        perror("Error opening/creating destination file");
        close(src_fd);
        return 1;
    }

    char buffer[4096];
    ssize_t bytes;
    while ((bytes = read(src_fd, buffer, sizeof(buffer))) > 0) {
        if (write(dst_fd, buffer, bytes) != bytes) {
            perror("Error writing to destination file");
            close(src_fd);
            close(dst_fd);
            return 1;
        }
    }

    if (bytes < 0) {
        perror("Error reading source file");
    }

    close(src_fd);
    close(dst_fd);
#endif

    return 0;
}

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
