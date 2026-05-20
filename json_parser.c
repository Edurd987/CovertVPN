#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include "json_parser.h"

int parse_json_payload(const char* json, size_t len,
                       u32* event_id, u64* timestamp,
                       u64* nonce, size_t* payload_len) {
    if (!json || len == 0 || !event_id || !timestamp || !nonce || !payload_len) {
        return -1;
    }
    if (json[0] != '{') {
        const char* target = "HTTP/1.1";
        size_t target_len = 8;
        int found = 0;
        if (len >= target_len) {
            for (size_t i = 0; i <= len - target_len; i++) {
                if (memcmp(json + i, target, target_len) == 0) {
                    found = 1;
                    break;
                }
            }
        }
        if (!found) return -1;
    }
    *event_id = 1;
    *timestamp = (u64)time(NULL);
    if (RAND_bytes((unsigned char*)nonce, sizeof(u64)) != 1) {
        return -1;
    }
    *payload_len = len;
    return 0;
}

char* alloc_session_id(const char* session_str) {
    if (!session_str) return NULL;
    size_t slen = strlen(session_str);
    if (slen == 0 || slen >= MAX_PACKET_SIZE) return NULL;
    char* result = (char*)malloc(slen + 1);
    if (!result) return NULL;
    memcpy(result, session_str, slen + 1);
    return result;
}

int build_masked_http_request(const char* fake_host, const char* json_payload,
                               char* out_buffer, size_t max_len) {
    if (!fake_host || !json_payload || !out_buffer || max_len == 0) {
        return -1;
    }
    if (strpbrk(fake_host, "\r\n") != NULL) {
        fprintf(stderr, "[-] Security Alert: Injection detected in fake_host!\n");
        return -1;
    }
    if (strpbrk(json_payload, "\r\n") != NULL) {
        fprintf(stderr, "[-] Security Alert: Unescaped newline in JSON payload!\n");
        return -1;
    }
    const char* http_template =
        "POST /api/v1/telemetry HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "%s";
    size_t payload_len = strlen(json_payload);
    int formatted_len = snprintf(out_buffer, max_len, http_template, fake_host, payload_len, json_payload);
    if (formatted_len < 0 || (size_t)formatted_len >= max_len) {
        return -1;
    }
    return formatted_len;
}
