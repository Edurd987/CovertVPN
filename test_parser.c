#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "json_parser.h"

int tests_passed = 0;
int tests_failed = 0;

#define TEST(name, condition) \
    if (condition) { \
        printf("[PASS] %s\n", name); \
        tests_passed++; \
    } else { \
        printf("[FAIL] %s\n", name); \
        tests_failed++; \
    }

void test_null_inputs(void) {
    printf("\n--- NULL Input Tests ---\n");
    u32 event_id; u64 timestamp, nonce; size_t payload_len;

    TEST("NULL json pointer",
        parse_json_payload(NULL, 10, &event_id, &timestamp, &nonce, &payload_len) == -1);

    TEST("Zero length",
        parse_json_payload("{}", 0, &event_id, &timestamp, &nonce, &payload_len) == -1);

    TEST("NULL event_id",
        parse_json_payload("{}", 2, NULL, &timestamp, &nonce, &payload_len) == -1);

    TEST("NULL timestamp",
        parse_json_payload("{}", 2, &event_id, NULL, &nonce, &payload_len) == -1);

    TEST("NULL nonce",
        parse_json_payload("{}", 2, &event_id, &timestamp, NULL, &payload_len) == -1);

    TEST("NULL payload_len",
        parse_json_payload("{}", 2, &event_id, &timestamp, &nonce, NULL) == -1);
}

void test_valid_json(void) {
    printf("\n--- Valid JSON Tests ---\n");
    u32 event_id; u64 timestamp, nonce; size_t payload_len;

    const char* json = "{\"type\":\"data\"}";
    TEST("Valid JSON starting with {",
        parse_json_payload(json, strlen(json), &event_id, &timestamp, &nonce, &payload_len) == 0);

    TEST("event_id set to 1",
        event_id == 1);

    TEST("payload_len matches input length",
        payload_len == strlen(json));

    TEST("nonce is non-zero",
        nonce != 0);

    TEST("timestamp is non-zero",
        timestamp != 0);
}

void test_http_format(void) {
    printf("\n--- HTTP Format Tests ---\n");
    u32 event_id; u64 timestamp, nonce; size_t payload_len;

    const char* http = "POST /api HTTP/1.1\r\nHost: test.com\r\n";
    TEST("Valid HTTP/1.1 packet",
        parse_json_payload(http, strlen(http), &event_id, &timestamp, &nonce, &payload_len) == 0);

    const char* invalid = "INVALID DATA 12345";
    TEST("Invalid format returns -1",
        parse_json_payload(invalid, strlen(invalid), &event_id, &timestamp, &nonce, &payload_len) == -1);
}

void test_edge_cases(void) {
    printf("\n--- Edge Case Tests ---\n");
    u32 event_id; u64 timestamp, nonce; size_t payload_len;

    // Одиночный символ {
    TEST("Single { character",
        parse_json_payload("{", 1, &event_id, &timestamp, &nonce, &payload_len) == 0);

    // HTTP строка короче чем "HTTP/1.1"
    const char* short_http = "HTTP/1.";
    TEST("HTTP string too short",
        parse_json_payload(short_http, strlen(short_http), &event_id, &timestamp, &nonce, &payload_len) == -1);

    // Пустая строка но len > 0
    const char* spaces = "       ";
    TEST("Spaces only returns -1",
        parse_json_payload(spaces, strlen(spaces), &event_id, &timestamp, &nonce, &payload_len) == -1);
}

int main(void) {
    printf("=============================\n");
    printf("  parse_json_payload Tests   \n");
    printf("=============================\n");

    test_null_inputs();
    test_valid_json();
    test_http_format();
    test_edge_cases();

    printf("\n=============================\n");
    printf("  PASSED: %d\n", tests_passed);
    printf("  FAILED: %d\n", tests_failed);
    printf("  TOTAL:  %d\n", tests_passed + tests_failed);
    printf("=============================\n");

    return tests_failed > 0 ? 1 : 0;
}
