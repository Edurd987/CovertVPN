#include <stdint.h>
#include <time.h>
#include "network.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Если вдруг в common.h нет, страхуемся */
#ifndef MAX_PACKET_SIZE
#define MAX_PACKET_SIZE 8192
#endif

int main(void) {
    printf("[SERVER] Starting CovertVPN Server v1.0...\n");

    if (init_winsock() != 0) {
        printf("[ERROR] Winsock init failed\n");
        return -1;
    }

    net_socket_t server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET) {
        printf("[ERROR] socket() failed: %d\n", WSAGetLastError());
        cleanup_winsock();
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; 
    addr.sin_port = htons(8888);

    if (bind(server, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("[ERROR] bind() failed: %d\n", WSAGetLastError());
        closesocket(server);
        cleanup_winsock();
        return -1;
    }

    if (listen(server, 5) == SOCKET_ERROR) {
        printf("[ERROR] listen() failed\n");
        closesocket(server);
        cleanup_winsock();
        return -1;
    }

    printf("[SERVER] Listening on 0.0.0.0:8888\n");
    printf("[SERVER] Server ready! Press Ctrl+C to stop.\n");

    while (1) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        net_socket_t client = accept(server, (struct sockaddr*)&client_addr, &client_len);
        
        if (client != INVALID_SOCKET) {
            printf("[SERVER] Client connected from %s\n", inet_ntoa(client_addr.sin_addr));

            char buffer[MAX_PACKET_SIZE];
            int n;
            while ((n = recv(client, buffer, sizeof(buffer) - 1, 0)) > 0) {
                buffer[n] = '\0'; // Гарантируем конец строки для вывода
                printf("[SERVER] Received data: %s\n", buffer);

                char response[256];
                snprintf(response, sizeof(response), "{\"status\":\"ok\",\"len\":%d}", n);
                send(client, response, (int)strlen(response), 0);
            }
            printf("[SERVER] Client disconnected.\n");
            closesocket(client);
        }
    }

    closesocket(server);
    cleanup_winsock();
    return 0;
}
