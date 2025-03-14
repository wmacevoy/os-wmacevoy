// server.c
#ifdef _WIN32
  #define _WIN32_WINNT 0x0601
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef SOCKET socket_t;
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <errno.h>
  #include <pthread.h>
  typedef int socket_t;
  #define INVALID_SOCKET -1
  #define SOCKET_ERROR -1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PORT 12345

// Stock structure with a fixed 4-character symbol and a 32-bit price (in pennies)
typedef struct {
    char symbol[5];  // 4 characters + null terminator
    uint32_t price;  // Price in pennies
} Stock;

#ifdef _WIN32
void cleanup_winsock() {
    WSACleanup();
}
#endif

// Thread function to handle each client connection
#ifdef _WIN32
DWORD WINAPI client_handler(LPVOID arg) {
    socket_t client_fd = *(socket_t*)arg;
    free(arg);
#else
void* client_handler(void* arg) {
    socket_t client_fd = *(socket_t*)arg;
    free(arg);
#endif

    // Create a sample stock data record
    Stock stock;
    strncpy(stock.symbol, "AAPL", sizeof(stock.symbol));
    stock.symbol[4] = '\0'; // Ensure null termination
    // For example, a price of $123.45 is 12345 pennies
    uint32_t price = 12345;
    // Convert price to network byte order
    stock.price = htonl(price);

    if (send(client_fd, (char*)&stock, sizeof(stock), 0) == SOCKET_ERROR) {
        perror("send failed");
    } else {
        printf("Sent stock data: %s at %u pennies\n", stock.symbol, price);
    }

#ifdef _WIN32
    closesocket(client_fd);
    return 0;
#else
    close(client_fd);
    return NULL;
#endif
}

int main(void) {
#ifdef _WIN32
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif

    socket_t server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;  // Listen on any interface
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) == SOCKET_ERROR) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) == SOCKET_ERROR) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Main loop to accept and handle incoming connections
    while (1) {
        struct sockaddr_in client_address;
#ifdef _WIN32
        int addrlen = sizeof(client_address);
#else
        socklen_t addrlen = sizeof(client_address);
#endif
        // Allocate memory for client socket descriptor pointer
        socket_t* client_fd = malloc(sizeof(socket_t));
        if (!client_fd) {
            fprintf(stderr, "Memory allocation error\n");
            continue;
        }
        *client_fd = accept(server_fd, (struct sockaddr*)&client_address, &addrlen);
        if (*client_fd == INVALID_SOCKET) {
            perror("accept failed");
            free(client_fd);
            continue;
        }
        printf("Client connected.\n");

#ifdef _WIN32
        // Create a new thread using Windows API
        HANDLE thread_handle = CreateThread(NULL, 0, client_handler, client_fd, 0, NULL);
        if (thread_handle == NULL) {
            perror("Failed to create thread");
            closesocket(*client_fd);
            free(client_fd);
            continue;
        }
        CloseHandle(thread_handle); // No need to keep the handle
#else
        // Create a new thread using pthreads
        pthread_t tid;
        if (pthread_create(&tid, NULL, client_handler, client_fd) != 0) {
            perror("pthread_create failed");
            close(*client_fd);
            free(client_fd);
            continue;
        }
        pthread_detach(tid);
#endif
    }

#ifdef _WIN32
    closesocket(server_fd);
    cleanup_winsock();
#else
    close(server_fd);
#endif

    return 0;
}