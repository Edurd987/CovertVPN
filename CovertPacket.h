
#ifndef COVERT_PACKET_H
#define COVERT_PACKET_H

/* ==================== ВЕРСИЯ И КОМПОНЕНТЫ ==================== */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Протокол версии — для совместимости и детекции версий в сети */
#define COVERT_VERSION_MAJOR 2
#define COVERT_VERSION_MINOR 5
#define COVERT_PROTOCOL_ID 0x434F5645  /* ASCII "COVE" in hex */

/* ✅ Обертка для совместимости C и C++ */
#ifdef __cplusplus
extern "C" {
#endif

/* ==================== КОНСТАНТЫ И ЛИМИТЫ ==================== */
#define MAX_PACKET_SIZE            16384
#define MIN_SAFE_CHUNK             1024
#define MAX_SAFE_CHUNK             8192
#define ABSOLUTE_MAX_CHUNK         32768
#define HMAC_SHA256_LEN            32
#define X25519_SECRET_LEN          32
#define SESSION_SECRET_LEN         32
#define REPLAY_CACHE_MAX_ENTRIES   1024
#define REPLAY_TTL_SECONDS         120

/* ==================== СТРУКТУРЫ МЕТАДАННЫХ ==================== */
typedef struct {
    uint64_t sequence_id;
    uint64_t timestamp_ms;
    uint32_t nonce;
    const uint8_t* payload;
    size_t payload_len;
    const char* session_id;
    uint16_t header_crc;
} CovertMetadata;

typedef struct {
    const uint8_t* client_pubkey;
    const uint8_t* server_pubkey;
} CovertKeyExchangeInfo;

typedef struct {
    uint64_t session_id;
    uint32_t nonce;
    uint64_t timestamp_ms;
    uint8_t seen;
} ReplayCacheEntry;

/* ==================== ФУНКЦИИ (ОБЪЯВЛЕНИЯ) ==================== */

extern void covert_init_session(const uint8_t* shared_secret, const char* app_endpoint);
extern void covert_generate_nonce(uint32_t* out_nonce);
extern uint64_t covert_generate_timestamp_ms(void);

/* ✅ Функция сборки пакета ( jitter_ms добавлен в параметры ) */
extern char* covert_craft_json_packet(const CovertMetadata* meta,
                                      const uint8_t* psk_key,
                                      uint32_t jitter_ms);

extern uint8_t* covert_craft_binary_packet(const CovertMetadata* meta,
                                           const uint8_t* psk_key,
                                           size_t* out_len);

extern bool covert_validate_header(const uint8_t* buffer, size_t buffer_len);
extern bool covert_check_replay_protect(const CovertMetadata* meta,
                                        ReplayCacheEntry* cache[],
                                        int cache_size);

extern void covert_compute_hmac(const uint8_t* data, size_t data_len,
                                const uint8_t* key, char* out_hex);

extern bool covert_verify_hmac(const uint8_t* data, size_t data_len,
                               const uint8_t* received_hmac,
                               const uint8_t* key);

extern bool covert_eccdh_generate_keys(const CovertKeyExchangeInfo* exchange_info,
                                       uint8_t* shared_secret);
extern void covert_eccdh_cleanup_keys(void);

extern int covert_encrypt_payload(const uint8_t* plaintext, size_t plaintext_len,
                                  const uint8_t* shared_secret,
                                  const uint8_t* nonce,
                                  uint8_t** out_ciphertext,
                                  size_t* out_ciphertext_len);

extern int covert_decrypt_payload(const uint8_t* ciphertext, size_t ciphertext_len,
                                  const uint8_t* shared_secret,
                                  const uint8_t* nonce,
                                  uint8_t** out_plaintext,
                                  size_t* out_plaintext_len);

extern void covert_init_replay_cache(ReplayCacheEntry* cache[], int cache_size);
extern bool covert_add_to_replay_cache(const char* session_id, uint32_t nonce,
                                       uint64_t timestamp_ms, ReplayCacheEntry* cache[]);
extern void covert_cleanup_session_cache(const char* session_id, ReplayCacheEntry* cache[]);

extern const char* covert_get_fake_useragent(void);
extern void covert_add_noise_headers(char** out_header, size_t* header_len);

extern void covert_cleanup_packet(const char* packet);
extern void covert_cleanup_crypto_keys(void);

#ifdef __cplusplus
}
#endif /* extern "C" end */

#endif /* COVERT_PACKET_H */
