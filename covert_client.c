#include <stdint.h>
#include <time.h>
#include "network.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void) {
    printf("[CLIENT] Starting CovertClient v1.0...\n");
    
    init_winsock();
    
    net_socket_t s = create_client_socket(8888);
    if (s == INVALID_SOCKET) {
        perror("create_client_socket()");
        cleanup_winsock();
        return -1;
    }

    printf("[CLIENT] Connected to server at 127.0.0.1:8888\n");
    
    char input[256];
    while (fgets(input, sizeof(input), stdin)) {
        /* Убрали JSON для MVP — отправляем как есть */
        printf("[CLIENT] Sending covert packet...\n");
        
        size_t len = strlen(input);
        send(s, input, len, 0);
        printf("[CLIENT] Sent data (len=%zu)\n", len);
    }

    closesocket(s);
    cleanup_winsock();
    return 0;
}
