#include <stdint.h>
#include <time.h>

#include "network.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mmsystem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>

#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "Ws2_32.lib")

/**
 * Инициализация сетевого стека Windows (WSA).
 */
int init_network(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[-] Failed to initialize Winsock.\n");
        return -1;
    }
#endif
    return 0;
}

/**
 * Завершение работы с сетью.
 */
void cleanup_network(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

/**
 * Высокоточный джиттер с защитой CPU.
 */
void stealth_jitter_us(long long microseconds) {
    if (microseconds <= 0) return;
    
    LARGE_INTEGER frequency, start, end;
    if (!QueryPerformanceFrequency(&frequency)) return;
    QueryPerformanceCounter(&start);
    
    long long target = (microseconds * frequency.QuadPart) / 1000000;
    
    do {
        QueryPerformanceCounter(&end);
        if (microseconds > 1000) {
            YieldProcessor(); // Оптимизация для Windows 10
        }
    } while (end.QuadPart - start.QuadPart < target);
}

/**
 * Расширенная проверка ошибок сокета с системным описанием.
 */
static void log_socket_error(const char* context) {
    int err = WSAGetLastError();
    char* s = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
                   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&s, 0, NULL);
    fprintf(stderr, "[-] %s | Error %d: %s\n", context, err, s ? s : "Unknown");
    LocalFree(s);
}

/**
 * Ожидание соединения для неблокирующего сокета.
 */
int wait_for_connect(net_socket_t s, long timeout_ms) {
    fd_set write_fds, err_fds;
    FD_ZERO(&write_fds);
    FD_ZERO(&err_fds);
    FD_SET(s, &write_fds);
    FD_SET(s, &err_fds);

    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    int sel_res = select(0, NULL, &write_fds, &err_fds, &tv);
    
    if (sel_res > 0) {
        if (FD_ISSET(s, &err_fds)) {
            log_socket_error("select() reported error");
            return -1;
        }
        if (FD_ISSET(s, &write_fds)) {
            int error = 0;
            int len = sizeof(error);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&error, &len) == 0 && error == 0) {
                return 0;
            }
        }
    }
    return -1;
}

/**
 * Установка TCP-соединения (IPv4/IPv6 Dual-Stack).
 */
int connect_tcp(net_socket_t *s, const char* ip, int port) {
    struct addrinfo hints, *res = NULL, *p = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(ip, NULL, &hints, &res) != 0) return -1;

    int connected = -1;
    for (p = res; p != NULL; p = p->ai_next) {
        *s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (*s == INVALID_SOCKET) continue;

        if (p->ai_family == AF_INET) ((struct sockaddr_in*)p->ai_addr)->sin_port = htons(port);
        else ((struct sockaddr_in6*)p->ai_addr)->sin6_port = htons(port);

        unsigned long mode = 1;
        ioctlsocket(*s, FIONBIO, &mode);

        if (connect(*s, p->ai_addr, (int)p->ai_addrlen) == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                if (wait_for_connect(*s, 3000) == 0) {
                    connected = 0;
                    break;
                }
            }
            closesocket(*s);
            *s = INVALID_SOCKET;
        } else {
            connected = 0;
            break;
        }
    }

    if (res) freeaddrinfo(res);
    return connected;
}

/**
 * Стелс-отправка с микросекундным джиттером.
 */
int send_stealth_packet(net_socket_t s, const uint8_t* buf, int len) {
    if (s == INVALID_SOCKET || !buf || len <= 0) return -1;

    uint16_t entropy;
    if (RAND_bytes((uint8_t*)&entropy, sizeof(entropy)) != 1) {
        fprintf(stderr, "[-] Critical: No entropy for jitter.\n");
        return -1;
    }
    
    long long interval = 80 + (entropy % 270);
    stealth_jitter_us(interval);

    int sent = send(s, (const char*)buf, len, 0);
    if (sent == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAEWOULDBLOCK) return 0;
        log_socket_error("send() failed");
        return -1;
    }
    return sent;
}
