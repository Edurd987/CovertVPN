
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network.h"
#include "json_parser.h"

/**
 * @brief Безопасное экранирование спецсимволов для JSON (кавычки и бэкслеши)
 * Устраняет уязвимость №1 (JSON Injection) с жестким контролем границ буфера.
 */
void escape_json_string(const char* src, char* dest, size_t dest_max) {
    if (!src || !dest || dest_max == 0) return;
    
    size_t d_idx = 0;
    while (*src && d_idx < dest_max - 1) {
        if (*src == '"' || *src == '\\') {
            if (d_idx + 2 >= dest_max) break; 
            dest[d_idx++] = '\\';
            dest[d_idx++] = *src;
        } else {
            dest[d_idx++] = *src;
        }
        src++;
    }
    dest[d_idx] = '\0';
}

int main(void) {
    printf("[CLIENT] Starting CovertClient v2.2 (Fully Audited & Protected)...\n");

    // 1. Инициализация глобальной сетевой подсистемы (Winsock + OpenSSL)
    if (init_network() != 0) {
        fprintf(stderr, "[-] Critical: Network subsystem initialization failed.\n");
        return -1;
    }

    // 2. Выделение и обнуление контекста безопасности
    covert_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.mask_mode = MASK_HTTPS_VALID; 

    // Безопасное заполнение фейкового SNI для обхода DPI
    strncpy(ctx.fake_sni, "google.com", sizeof(ctx.fake_sni) - 1);
    ctx.fake_sni[sizeof(ctx.fake_sni) - 1] = '\0';

    // 3. Создание SSL_CTX, импорт Windows CertStore и настройка MITM-защиты
    if (init_covert_ssl(&ctx, 0 /* client mode */) != 0) {
        fprintf(stderr, "[-] Critical: Failed to setup OpenSSL context.\n");
        covert_context_free(&ctx); 
        cleanup_network();
        return -1;
    }

    // 4. Поднятие неблокирующего TLS-туннеля через наше ядро
    const char* target_ip = "127.0.0.1";
    int target_port = 8888;

    printf("[*] Connecting to %s:%d (Spoofing SNI: %s)...\n", target_ip, target_port, ctx.fake_sni);
    if (connect_covert_tunnel(&ctx, target_ip, target_port) != 0) {
        fprintf(stderr, "[-] Connection failed. Tunnel blocked or server offline.\n");
        covert_context_free(&ctx);
        cleanup_network();
        return -1;
    }
    printf("[+] Secure TLS 1.3 tunnel successfully raised!\n\n");

    // Выделяем буферы под обработку маскировки
    char user_input[128];
    char escaped_input[256]; 
    char json_payload[512];
    char http_masked_packet[MAX_PACKET_SIZE];

    printf("[*] Enter message to send covertly (or Ctrl+C to exit):\n> ");
    
    // 5. Основной цикл передачи данных
    while (fgets(user_input, sizeof(user_input), stdin)) {
        user_input[strcspn(user_input, "\r\n")] = 0;
        
        size_t src_len = strlen(user_input);
        if (src_len == 0) {
            printf("> ");
            continue;
        }

        // Исправление замечания v2.2: Математически точная пре-валидация усечения строки
        size_t max_safe_src = (sizeof(escaped_input) - 1) / 2;
        if (src_len > max_safe_src) {
            fprintf(stderr, "[-] Error: Input message too long (%zu bytes). Risk of truncation. Drop frame.\n", src_len);
            printf("> ");
            continue;
        }

        // Теперь вызов гарантированно безопасен и никогда не приведет к потере данных
        escape_json_string(user_input, escaped_input, sizeof(escaped_input));

        // Упаковываем безопасную строку в JSON-структуру
        int json_len = snprintf(json_payload, sizeof(json_payload), 
                                "{\"type\":\"data\",\"payload\":\"%s\",\"status\":\"active\"}", 
                                escaped_input);
        
        if (json_len < 0 || (size_t)json_len >= sizeof(json_payload)) {
            fprintf(stderr, "[-] Error: Input too long for JSON buffer.\n");
            printf("> ");
            continue;
        }

        // Маскируем JSON под легитимный веб-трафик (HTTP POST запрос)
        int ready_packet_len = build_masked_http_request(ctx.fake_sni, json_payload, 
                                                         http_masked_packet, MAX_PACKET_SIZE);
        if (ready_packet_len < 0) {
            fprintf(stderr, "[-] Error: Serialization failed. Injection attempt detected.\n");
            printf("> ");
            continue;
        }

        // Проверка жесткого лимита MTU до отправки на транспорт
        if (ready_packet_len > HTTPS_STANDARD_MTU) {
            fprintf(stderr, "[-] Error: Packet size (%d) exceeds HTTPS_STANDARD_MTU (%d). Drop frame.\n", 
                    ready_packet_len, HTTPS_STANDARD_MTU);
            printf("> ");
            continue;
        }

        printf("[CLIENT] Shipping obfuscated frame (L7 Len: %d)...\n", ready_packet_len);

        // Отправка через наше бронированное ядро network.c
        int bytes_sent = send_covert_packet(&ctx, (const u8*)http_masked_packet, ready_packet_len);
        
        if (bytes_sent <= 0) {
            fprintf(stderr, "[-] Critical: Tunnel broken. Connection lost.\n");
            break;
        }

        printf("[+] Frame transmitted successfully.\n\n> ");
    }

    // 6. Очистка ресурсов и корректное закрытие сессии
    printf("\n[*] Closing client. Cleaning secure contexts...\n");
    covert_context_free(&ctx);
    cleanup_network();

    printf("[+] Covert VPN client terminated cleanly.\n");
    return 0;
}
