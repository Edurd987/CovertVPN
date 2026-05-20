
#pragma once

#include <stddef.h>
#include "types.h" // Подключаем единые типы

#ifndef MAX_PACKET_SIZE
#define MAX_PACKET_SIZE 4096
#endif

/* ─── Прототипы функций с защитой контрактов ──────────── */

/**
 * @brief Безопасный парсинг входящего JSON-пакета.
 * * @param json        Указатель на строку с JSON-данными (не должен быть NULL)
 * @param len         Длина входящих данных (должна быть > 0)
 * @param event_id    Выходной указатель для ID события (не должен быть NULL)
 * @param timestamp   Выходной указатель для временной метки (не должен быть NULL)
 * @param nonce       Выходной указатель для криптографической соли (не должен быть NULL)
 * @param payload_len Выходной указатель для длины полезной нагрузки (не должен быть NULL)
 * * @return int        0 при успешном парсинге, -1 при невалидных указателях или ошибке структуры.
 */
int parse_json_payload(const char* json, size_t len,
                       u32* event_id, u64* timestamp,
                       u64* nonce, size_t* payload_len);

/**
 * @brief Выделяет память в куче и копирует идентификатор сессии.
 * * @param session_str Исходная строка сессии.
 * @return char* Указатель на выделенную память с подстрокой, либо NULL при ошибке.
 * * @warning Вызывающий код (Caller) обязан самостоятельно освободить 
 * выделенную память через free(), чтобы избежать утечек!
 */
char* alloc_session_id(const char* session_str);

/**
 * @brief Формирует легитимный HTTP POST-запрос, маскирующий JSON.
 * * @param fake_host    Имя хоста для подстановки в заголовок Host (не NULL)
 * @param json_payload Сырые JSON-данные для тела запроса (не NULL)
 * @param out_buffer   Целевой буфер для записи сформированного HTTP-пакета (не NULL)
 * @param max_len      Максимальный размер целевого буфера (должен быть > 0)
 * * @return int         Длина записанной строки или -1 при ошибке/переполнении буфера.
 */
int build_masked_http_request(const char* fake_host, const char* json_payload, 
                               char* out_buffer, size_t max_len);
