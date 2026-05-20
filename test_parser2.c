#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* ─── alloc_session_id Tests ─────────────────────── */
void test_alloc_session_id(void) {
    printf("\n--- alloc_session_id Tests ---\n");

    // NULL вход
    TEST("NULL input returns NULL",
        alloc_session_id(NULL) == NULL);

    // Пустая строка
    TEST("Empty string returns NULL",
        alloc_session_id("") == NULL);

    // Нормальная строка
    char* s = alloc_session_id("user123");
    TEST("Valid input returns non-NULL",
        s != NULL);
    TEST("Content matches input",
        s != NULL && strcmp(s, "user123") == 0);
    if (s) free(s);

    // Строка ровно MAX_PACKET_SIZE-1 символов (граница)
    char big[MAX_PACKET_SIZE - 1];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    char* r = alloc_session_id(big);
    TEST("String at MAX_PACKET_SIZE-1 succeeds",
        r != NULL);
    if (r) free(r);

    // Строка ровно MAX_PACKET_SIZE символов (за границей)
    char toolong[MAX_PACKET_SIZE + 1];
    memset(toolong, 'A', MAX_PACKET_SIZE);
    toolong[MAX_PACKET_SIZE] = '\0';
    TEST("String at MAX_PACKET_SIZE returns NULL",
        alloc_session_id(toolong) == NULL);

    // Память корректно освобождается
    char* mem = alloc_session_id("test");
    free(mem);
    TEST("free() after alloc does not crash",
        1); // если дошли сюда — краша нет
}

/* ─── build_masked_http_request Tests ───────────── */
void test_build_masked_http_request(void) {
    printf("\n--- build_masked_http_request Tests ---\n");

    char buf[4096];

    // NULL аргументы
    TEST("NULL fake_host returns -1",
        build_masked_http_request(NULL, "{}", buf, sizeof(buf)) == -1);

    TEST("NULL json_payload returns -1",
        build_masked_http_request("host.com", NULL, buf, sizeof(buf)) == -1);

    TEST("NULL out_buffer returns -1",
        build_masked_http_request("host.com", "{}", NULL, sizeof(buf)) == -1);

    TEST("Zero max_len returns -1",
        build_masked_http_request("host.com", "{}", buf, 0) == -1);

    // Header Injection защита
    TEST("\\r\\n in fake_host blocked",
        build_masked_http_request("evil.com\r\nX-Inject: pwned", "{}", buf, sizeof(buf)) == -1);

    TEST("\\r\\n in json_payload blocked",
        build_masked_http_request("host.com", "{\"a\":\"b\r\nc\"}", buf, sizeof(buf)) == -1);

    TEST("\\n only in fake_host blocked",
        build_masked_http_request("evil.com\nInject: x", "{}", buf, sizeof(buf)) == -1);

    // Нормальный запрос
    int len = build_masked_http_request("google.com", "{\"type\":\"data\"}", buf, sizeof(buf));
    TEST("Valid request returns positive length",
        len > 0);

    TEST("Output contains HTTP/1.1",
        len > 0 && strstr(buf, "HTTP/1.1") != NULL);

    TEST("Output contains Host header",
        len > 0 && strstr(buf, "Host: google.com") != NULL);

    TEST("Output contains Content-Type",
        len > 0 && strstr(buf, "Content-Type: application/json") != NULL);

    TEST("Output contains json payload",
        len > 0 && strstr(buf, "{\"type\":\"data\"}") != NULL);

    // Буфер слишком мал
    char smallbuf[10];
    TEST("Buffer too small returns -1",
        build_masked_http_request("host.com", "{}", smallbuf, sizeof(smallbuf)) == -1);

    // Возвращаемая длина совпадает с реальной
    int ret_len = build_masked_http_request("host.com", "{}", buf, sizeof(buf));
    TEST("Returned length matches strlen",
        ret_len == (int)strlen(buf));
}

int main(void) {
    printf("=====================================\n");
    printf("  alloc_session_id Tests             \n");
    printf("  build_masked_http_request Tests    \n");
    printf("=====================================\n");

    test_alloc_session_id();
    test_build_masked_http_request();

    printf("\n=====================================\n");
    printf("  PASSED: %d\n", tests_passed);
    printf("  FAILED: %d\n", tests_failed);
    printf("  TOTAL:  %d\n", tests_passed + tests_failed);
    printf("=====================================\n");

    return tests_failed > 0 ? 1 : 0;
}
