#ifndef NETWORK_H
#define NETWORK_H

// В MSYS2/Linux эти макросы обычно не нужны, но для совместимости с Windows-заголовками оставим
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdio.h>

// Для MSYS2 линковка будет через -lws2_32 в командной строке, 
// но прагму можно оставить для VS.
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

typedef struct {
    char host[256];
    int port;
    SOCKET main_socket;
} NetworkConfig;

// Сигнатуры для нашего "стелс-ядра"
int init_network_subsystem();
SOCKET create_client_socket(const char* host, int port);
void close_network_connection(SOCKET s);

#endif // NETWORK_H
