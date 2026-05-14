#pragma once
#include <stdint.h>
#include <stddef.h>

uint8_t* encode_string(const char* str, size_t len, uint8_t* buf, size_t* buf_len);
uint8_t* decode_string(const uint8_t* data, size_t len, uint8_t* buf, size_t* buf_len);
void zero_mem(void* ptr, size_t len);
