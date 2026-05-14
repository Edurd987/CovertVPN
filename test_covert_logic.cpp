#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <windows.h>
#include "CovertPacket.h"

int main() {
    std::cout << "[TEST] Запуск функционального теста 'Завода'...\n";
    
    const char* payload_text = "Secret VPN Tunnel Data: Hello World!";
    CovertMetadata meta;
    memset(&meta, 0, sizeof(meta));
    meta.sequence_id = 1001;
    meta.timestamp_ms = GetTickCount64();
    meta.payload = (uint8_t*)payload_text;
    meta.payload_len = strlen(payload_text);

    uint8_t session_secret[32];
    RAND_bytes(session_secret, 32);

    std::cout << "[INFO] Calling covert_craft_json_packet...\n";
    
    // Передаем 3 аргумента (0 - джиттер для теста)
    char* json_packet = covert_craft_json_packet(&meta, session_secret, 0);
    
    if (json_packet) {
        std::cout << "[RESULT] JSON Packet:\n" << json_packet << "\n\n";
        free(json_packet);
    } else {
        std::cout << "[ERROR] Failed to craft JSON packet.\n";
        ERR_print_errors_fp(stdout);
        return 1;
    }
    return 0;
}
