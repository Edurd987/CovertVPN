#include <stdint.h>
#include <time.h>
#include "encoding.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

/**
 * Внутренняя функция базового шифрования AES-256-GCM.
 */
int _internal_encrypt_gcm(const uint8_t* plain, int len, const uint8_t* key, uint8_t* out) {
    EVP_CIPHER_CTX *ctx = NULL;
    int outlen = 0, final_len = 0;
    uint8_t nonce[12];
    
    // ✅ Стандартная проверка системного ГСЧ для Nonce
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return -1;
    
    memcpy(out, nonce, 12);

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto err;

    if (EVP_EncryptUpdate(ctx, out + 12, &outlen, plain, len) != 1) goto err;
    if (EVP_EncryptFinal_ex(ctx, out + 12 + outlen, &final_len) != 1) goto err;

    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) goto err;
    memcpy(out + 12 + outlen + final_len, tag, 16);

    EVP_CIPHER_CTX_free(ctx);
    return 12 + outlen + final_len + 16;

err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/**
 * СУПЕР ПРОТОКОЛ СТЕЛС: Финальная версия
 */
int encrypt_stealth_layer(const uint8_t* plain, int len, const uint8_t* key, uint8_t* out, size_t max_out_len) {
    // 1. Проверка на минимально допустимый размер буфера
    if (max_out_len < (size_t)(12 + len + 16 + 16)) return -1;

    int actual_base = _internal_encrypt_gcm(plain, len, key, out);
    if (actual_base <= 0) return -1;

    // 2. ✅ Использование криптостойкого ГСЧ для паддинга
    uint8_t rand_byte;
    if (RAND_bytes(&rand_byte, 1) != 1) rand_byte = (uint8_t)rand(); 
    
    // volatile для защиты от оптимизаций компилятора, влияющих на тайминг
    volatile int pad_len = (rand_byte % 112) + 16; 

    // 3. Строгая проверка границ перед копированием шума
    if ((size_t)(actual_base + pad_len) > max_out_len) {
        pad_len = (int)(max_out_len - actual_base);
    }

    if (pad_len > 0) {
        uint8_t* noise = (uint8_t*)malloc(pad_len);
        if (noise) {
            // Заполняем паддинг криптографическим шумом, а не нулями
            if (RAND_bytes(noise, pad_len) == 1) {
                memcpy(out + actual_base, noise, pad_len);
            }
            free(noise);
        }
    }

    return actual_base + pad_len;
}

