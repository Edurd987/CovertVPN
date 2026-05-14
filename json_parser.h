#pragma once
#include "common.h"

int parse_json_payload(const char* json, size_t len, 
                       u32* event_id, u64* timestamp, 
                       u64* nonce, size_t* payload_len);

char* alloc_session_id(const char* session_str);
