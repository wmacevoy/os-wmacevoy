// client.c
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
  #include <netdb.h>
  #include <errno.h>
  typedef int socket_t;
  #define INVALID_SOCKET -1
  #define SOCKET_ERROR -1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PORT 12345
#define ITERATIONS 60

// Stock structure must match the server's definition
typedef struct {
    char symbol[5];
    uint32_t price;
} Stock;

#ifdef _WIN32
void cleanup_winsock() {
    WSACleanup();
}
#endif

int main(int argc, char *argv[]) {
#ifdef _WIN32
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif

    // Default server hostname; in Docker Compose, the service name "server" is used
    const char *server_host = (argc >= 2) ? argv[1] : "server";

    printf("Client started. Will connect to server every second for %d seconds...\n", ITERATIONS);

    for (int i = 0; i < ITERATIONS; i++) {
        // Create a new socket for each connection attempt
        socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            perror("socket creation failed");
#ifdef _WIN32
            Sleep(1000);
#else
            sleep(1);
#endif
            continue;
        }

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);
        if (inet_pton(AF_INET, server_host, &serv_addr.sin_addr) <= 0) {
            // If server_host isn't an IP, try resolving hostname
            struct hostent *he = gethostbyname(server_host);
            if (he == NULL) {
                fprintf(stderr, "Invalid address/hostname: %s\n", server_host);
#ifdef _WIN32
                closesocket(sock);
#else
                close(sock);
#endif
#ifdef _WIN32
                Sleep(1000);
#else
                sleep(1);
#endif
                continue;
            }
            memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
        }

        printf("[Attempt %d] Connecting to server %s on port %d...\n", i + 1, server_host, PORT);
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
            perror("connect failed");
#ifdef _WIN32
            closesocket(sock);
            Sleep(1000);
#else
            close(sock);
            sleep(1);
#endif
            continue;
        }
        printf("[Attempt %d] Connected to server.\n", i + 1);

        // Receive the binary stock data
        Stock stock;
        int bytes_received = recv(sock, (char*)&stock, sizeof(stock), 0);
        if (bytes_received <= 0) {
            perror("recv failed or connection closed");
        } else {
            // Convert the price from network byte order to host order
            uint32_t price = ntohl(stock.price);
            printf("[Attempt %d] Received stock data:\n", i + 1);
            printf("  Symbol: %s\n", stock.symbol);
            printf("  Price : %u pennies (i.e., $%.2f)\n", price, price / 100.0);
        }

#ifdef _WIN32
        closesocket(sock);
        Sleep(1000);  // Sleep for 1 second (milliseconds)
#else
        close(sock);
        sleep(1);     // Sleep for 1 second
#endif
    }

#ifdef _WIN32
    cleanup_winsock();
#endif

    printf("Client finished 60 connection attempts.\n");
    return 0;
}