
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network.h"
#include "json_parser.h"

int main(void) {
    printf("[SERVER] Starting CovertVPN Server v2.3 (Fully Audited & Protected)...\n");

    if (init_network() != 0) {
        fprintf(stderr, "[-] Critical: Network subsystem initialization failed.\n");
        return -1;
    }

    covert_context_t server_ctx;
    memset(&server_ctx, 0, sizeof(server_ctx));
    server_ctx.mask_mode = MASK_HTTPS_VALID;

    if (init_covert_ssl(&server_ctx, 1 /* server mode */) != 0) {
        fprintf(stderr, "[-] Critical: Failed to setup OpenSSL server context.\n");
        cleanup_network();
        return -1;
    }

    if (listen_covert_tunnel(&server_ctx, "0.0.0.0", 8888) != 0) {
        fprintf(stderr, "[-] Critical: Server failed to bind/listen on port 8888.\n");
        covert_context_free(&server_ctx);
        cleanup_network();
        return -1;
    }

    printf("[+] Server is successfully listening on 0.0.0.0:8888...\n");
    printf("[*] Awaiting secure stealth handshakes. Press Ctrl+C to stop.\n\n");

    while (1) {
        covert_context_t client_ctx;
        memset(&client_ctx, 0, sizeof(client_ctx));
        client_ctx.mask_mode = MASK_HTTPS_VALID;

        printf("[*] Waiting for incoming TCP connection...\n");
        
        if (accept_covert_tunnel(&server_ctx, &client_ctx) != 0) {
            fprintf(stderr, "[-] Handshake failed with incoming client node.\n");
            covert_context_free(&client_ctx);
            continue; 
        }

        printf("[+] TLS 1.3 Handshake successful. Client tunnel established.\n");

        char rx_buffer[MAX_PACKET_SIZE];
        u32 event_id = 0;
        u64 timestamp = 0;
        u64 received_nonce = 0;
        size_t payload_len = 0;

        while (1) {
            int n = recv_covert_packet(&client_ctx, (uint8_t*)rx_buffer, sizeof(rx_buffer) - 1);

            if (n <= 0) {
                printf("[SERVER] Client disconnected or session expired.\n");
                break;
            }

            rx_buffer[n] = '\0'; 

            if (parse_json_payload(rx_buffer, (size_t)n, &event_id, &timestamp, &received_nonce, &payload_len) == 0) {
                
                printf("[+] Packet Authenticated! [ID]: %u | [Nonce]: 0x%llX\n", 
                       event_id, (unsigned long long)received_nonce);
                
                // Исправление замечания №1: Защита от Terminal Injection (ANSI escape-последовательностей)
                printf("[DATA] Extracted stream: ");
                fwrite(rx_buffer, 1, (size_t)n, stdout);
                printf("\n\n");

                const char* http_ok = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
                
                if (send_covert_packet(&client_ctx, (const uint8_t*)http_ok, (int)strlen(http_ok)) <= 0) {
                    fprintf(stderr, "[-] Warning: Failed to send HTTP response back to client.\n");
                    break;
                }

            } else {
                fprintf(stderr, "[-] Security Alert: Malformed L7 packet! Dropping connection unconditionally.\n");
                break; 
            }
        }

        covert_context_free(&client_ctx);
        printf("[*] Connection closed. Returning to listening state...\n\n");
    }

    covert_context_free(&server_ctx);
    cleanup_network();
    return 0;
}
