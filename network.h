

#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>

#ifdef _WIN32
    #include <winsock2.h>
    typedef SOCKET net_socket_t;
#else
    // Задел для портирования на Linux по твоему совету
    typedef int net_socket_t;
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR   (-1)
#endif

/**
 * Инициализация сетевой подсистемы (Winsock для Windows).
 * Должна быть вызвана один раз при старте main().
 */
int init_network(void);

/**
 * Очистка сетевых ресурсов перед завершением работы.
 */
void cleanup_network(void);

/**
 * Установка TCP-соединения в неблокирующем режиме.
 * Поддерживает Dual-Stack IPv4/IPv6.
 * @return 0 при успехе, -1 при ошибке.
 */
int connect_tcp(net_socket_t *s, const char* ip, int port);

/**
 * Ожидание завершения соединения для неблокирующего сокета.
 */
int wait_for_connect(net_socket_t s, long timeout_ms);

/**
 * Отправка пакета с применением адаптивного микросекундного джиттера (L4).
 * Использует RAND_bytes для генерации интервалов.
 */
int send_stealth_packet(net_socket_t s, const uint8_t* buf, int len);

/**
 * Высокоточная микросекундная задержка.
 */
void stealth_jitter_us(long long microseconds);

#endif // NETWORK_H

