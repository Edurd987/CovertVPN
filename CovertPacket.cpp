#include "CovertPacket.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Вспомогательная функция кодирования Base64 */
char* base64_encode(const uint8_t* in, size_t len) {
    if (!in || len == 0) return NULL;
    size_t out_len = 4 * ((len + 2) / 3);
    char* out = (char*)malloc(out_len + 1);
    if (!out) return NULL;
    
    EVP_EncodeBlock((unsigned char*)out, in, len);
    return out;
}

/* ✅ Сборка пакета JSON с реальным HMAC-SHA256 */
extern "C" char* covert_craft_json_packet(const CovertMetadata* meta,
                                          const uint8_t* psk_key,
                                          uint32_t jitter_ms) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    
    cJSON_AddNumberToObject(root, "seq", (double)meta->sequence_id);
    cJSON_AddNumberToObject(root, "ts", (double)meta->timestamp_ms);
    
    if (jitter_ms > 0) {
        cJSON_AddNumberToObject(root, "j", (double)jitter_ms);
    }
    
    // Подготовка данных (пока без шифрования, как в твоем черновике)
    if (meta->payload && meta->payload_len > 0) {
        char* b64_data = base64_encode(meta->payload, meta->payload_len);
        if (b64_data) {
            cJSON_AddStringToObject(root, "data", b64_data);
            free(b64_data);
        }
    }

    /* ✅ ВЫЧИСЛЯЕМ HMAC ОТ ТЕКУЩЕГО JSON */
    char *json_raw = cJSON_PrintUnformatted(root);
    if (!json_raw) {
        cJSON_Delete(root);
        return NULL;
    }
    
    uint8_t hmac_result[32];
    unsigned int hmac_len = 32;
    
    // Используем фиксированную длину ключа 32 байта для безопасности
    HMAC(EVP_sha256(), psk_key, 32, 
         (unsigned char*)json_raw, strlen(json_raw), hmac_result, &hmac_len);
    
    char hex_sig[65];
    for(int i = 0; i < 32; i++) {
        sprintf(hex_sig + (i * 2), "%02x", hmac_result[i]);
    }
    
    cJSON_AddStringToObject(root, "sign", hex_sig);
    free(json_raw);
    
    char* final_json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    return final_json;
}

extern "C" void covert_cleanup_packet(const char* packet) {
    if (packet) free((void*)packet);
}
