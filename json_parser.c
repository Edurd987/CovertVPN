#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

int parse_json_payload(const char* json, size_t len) {
    if (!json || len == 0) return -1;
    /* Простой парсинг для MVP */
    return 0;
}

char* alloc_session_id(const char* session_str) {
    if (!session_str) return NULL;
    size_t slen = strlen(session_str);
    if (slen == 0 || slen >= MAX_PACKET_SIZE) return NULL;
    
    char* result = (char*)malloc(slen + 1);
    if (result) {
        strcpy(result, session_str);
    }
    return result;
}

