
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ─── Базовые типы ─────────────────────────────────────── */
#include "types.h" // Устранено дублирование. Все типы (u8, u16, u32, u64) теперь здесь.

/* ─── Константы ────────────────────────────────────────── */
#ifndef MAX_PACKET_SIZE
#define MAX_PACKET_SIZE 4096
#endif

#if MAX_PACKET_SIZE > 65535
#error "MAX_PACKET_SIZE is dangerously large"
#endif

#define HTTPS_STANDARD_MTU 1460

/* ─── Режимы маскировки ────────────────────────────────── */
typedef enum {
    MASK_HTTPS_VALID = 0,
    MASK_WEBSOCKET   = 1,
    MASK_PURE_NOISE  = 2
} covert_mask_mode_t;

/* ─── Контекст безопасности ────────────────────────────── */
typedef struct {
    SSL_CTX            *ssl_ctx;
    SSL                *ssl_handle;
    SOCKET              socket_fd;        // UINT_PTR, безопасен на x64
    covert_mask_mode_t  mask_mode;
    char                fake_sni[256];    // Только через strncpy + null-term
} covert_context_t;

/* ─── Прототипы ────────────────────────────────────────── */
int  init_network(void);
void cleanup_network(void);
void stealth_jitter_us(long long microseconds);
int  init_covert_ssl(covert_context_t *ctx, int is_server);
int  connect_covert_tunnel(covert_context_t *ctx, const char *ip, int port);
int  send_covert_packet(covert_context_t *ctx, const uint8_t *buf, int len);
void covert_context_free(covert_context_t *ctx);
int  listen_covert_tunnel(covert_context_t *ctx, const char *ip, int port);
int  accept_covert_tunnel(covert_context_t *server_ctx, covert_context_t *client_ctx);
int  recv_covert_packet(covert_context_t *ctx, uint8_t *buf, int max_len);

