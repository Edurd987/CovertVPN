#include <openssl/rand.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network.h"

/**
 * @brief Переводит сокет в режим прослушивания и связывает его с портом.
 */
int listen_covert_tunnel(covert_context_t *ctx, const char *ip, int port) {
    if (!ctx) return -1;

    // Создаем стандартный IPv4 TCP сокет
    ctx->socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ctx->socket_fd == INVALID_SOCKET) {
        fprintf(stderr, "[-] Server socket() failed: %d\n", WSAGetLastError());
        return -1;
    }

    // Разрешаем повторное использование адреса (SO_REUSEADDR), чтобы сервер перезапускался без задержек
    int opt = 1;
    if (setsockopt(ctx->socket_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        fprintf(stderr, "[-] setsockopt(SO_REUSEADDR) failed: %d\n", WSAGetLastError());
        closesocket(ctx->socket_fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    // Безопасное преобразование IP-адреса из строки
    if (ip == NULL || strlen(ip) == 0 || strcmp(ip, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
            fprintf(stderr, "[-] Invalid listen IP address format.\n");
            closesocket(ctx->socket_fd);
            return -1;
        }
    }

    // Привязка сокета
    if (bind(ctx->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[-] bind() failed: %d\n", WSAGetLastError());
        closesocket(ctx->socket_fd);
        return -1;
    }

    // Перевод в режим прослушивания (backlog = 5)
    if (listen(ctx->socket_fd, 5) == SOCKET_ERROR) {
        fprintf(stderr, "[-] listen() failed: %d\n", WSAGetLastError());
        closesocket(ctx->socket_fd);
        return -1;
    }

    return 0;
}

/**
 * @brief Ожидает входящее TCP-соединение и выполняет SSL_accept.
 */
int accept_covert_tunnel(covert_context_t *server_ctx, covert_context_t *client_ctx) {
    if (!server_ctx || !client_ctx) return -1;

    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);

    // Блокирующий accept входящего TCP-подключения
    SOCKET client_fd = accept(server_ctx->socket_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd == INVALID_SOCKET) {
        fprintf(stderr, "[-] accept() failed: %d\n", WSAGetLastError());
        return -1;
    }

    // Исправление уязвимости №2 из прошлого аудита: Потокобезопасное логирование IP через inet_ntop
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str)) != NULL) {
        printf("[*] Remote TCP connection accepted from %s:%d\n", ip_str, ntohs(client_addr.sin_port));
    }

    // Привязываем новый сокет к контексту клиента
    client_ctx->socket_fd = client_fd;
    client_ctx->ssl_ctx = server_ctx->ssl_ctx; // Наследуем конфигурацию OpenSSL

    // Создаем объект SSL для новой сессии
    client_ctx->ssl_handle = SSL_new(server_ctx->ssl_ctx);
    if (!client_ctx->ssl_handle) {
        fprintf(stderr, "[-] SSL_new() failed.\n");
        closesocket(client_fd);
        return -1;
    }

    // Связываем SSL с дескриптором сокета
    SSL_set_fd(client_ctx->ssl_handle, (int)client_ctx->socket_fd);

    // Выполняем серверное TLS-рукопожатие
    printf("[*] Performing TLS 1.3 cryptographic handshake...\n");
    int ssl_res = SSL_accept(client_ctx->ssl_handle);
    if (ssl_res <= 0) {
        int err = SSL_get_error(client_ctx->ssl_handle, ssl_res);
        fprintf(stderr, "[-] TLS Handshake failed. OpenSSL Error Code: %d\n", err);
        
        // Очищаем локальные ресурсы сессии при сбое
        SSL_free(client_ctx->ssl_handle);
        client_ctx->ssl_handle = NULL;
        closesocket(client_fd);
        return -1;
    }

    return 0;
}

/**
 * @brief Безопасный прием маскированных данных через SSL_read.
 */
int recv_covert_packet(covert_context_t *ctx, uint8_t *buf, int max_len) {
    if (!ctx || !ctx->ssl_handle || !buf || max_len <= 0) return -1;

    // Чтение данных из защищенного TLS-потока
    int bytes_read = SSL_read(ctx->ssl_handle, buf, max_len);
    
    if (bytes_read <= 0) {
        int err = SSL_get_error(ctx->ssl_handle, bytes_read);
        if (err == SSL_ERROR_ZERO_RETURN) {
            // Чистое закрытие соединения со стороны клиента
            return 0;
        }
        // Ошибка ввода-вывода или разрыв сокета
        return -1;
    }

    return bytes_read;
}
int init_network(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[-] Failed to initialize Winsock.\n");
        return -1;
    }
#endif
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    return 0;
}

void cleanup_network(void) {
#ifdef _WIN32
    WSACleanup();
#endif
    EVP_cleanup();
    ERR_free_strings();
}

void covert_context_free(covert_context_t *ctx) {
    if (!ctx) return;
    if (ctx->ssl_handle) {
        int r = SSL_shutdown(ctx->ssl_handle);
        if (r == 0) SSL_shutdown(ctx->ssl_handle);
        SSL_free(ctx->ssl_handle);
        ctx->ssl_handle = NULL;
    }
    if (ctx->ssl_ctx) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
    }
    if (ctx->socket_fd != INVALID_SOCKET) {
        closesocket(ctx->socket_fd);
        ctx->socket_fd = INVALID_SOCKET;
    }
}

void stealth_jitter_us(long long microseconds) {
    if (microseconds <= 0) return;
    if (microseconds >= 1000) {
        Sleep((DWORD)(microseconds / 1000));
        microseconds %= 1000;
    }
    if (microseconds <= 0) return;
    LARGE_INTEGER frequency, start, end;
    if (!QueryPerformanceFrequency(&frequency)) return;
    QueryPerformanceCounter(&start);
    long long target = (microseconds * frequency.QuadPart) / 1000000;
    do {
        QueryPerformanceCounter(&end);
        YieldProcessor();
    } while (end.QuadPart - start.QuadPart < target);
}

int init_covert_ssl(covert_context_t *ctx, int is_server) {
    if (!ctx) return -1;
    const SSL_METHOD *method = is_server ? TLS_server_method() : TLS_client_method();
    ctx->ssl_ctx = SSL_CTX_new(method);
    if (!ctx->ssl_ctx) return -1;
    if (SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_3_VERSION) != 1) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
        return -1;
    }
    if (!is_server) {
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_set_default_verify_paths(ctx->ssl_ctx) != 1) {
            SSL_CTX_free(ctx->ssl_ctx);
            ctx->ssl_ctx = NULL;
            return -1;
        }
    }
    SSL_CTX_set_ecdh_auto(ctx->ssl_ctx, 1);
    if (is_server) {
        if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
            fprintf(stderr, "[-] Failed to load certificate.\n");
            SSL_CTX_free(ctx->ssl_ctx);
            ctx->ssl_ctx = NULL;
            return -1;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
            fprintf(stderr, "[-] Failed to load private key.\n");
            SSL_CTX_free(ctx->ssl_ctx);
            ctx->ssl_ctx = NULL;
            return -1;
        }
    }
    return 0;
}

static int handle_ssl_blocking_state(SOCKET socket_fd, int ssl_err, long timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(socket_fd, &fds);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    if (ssl_err == SSL_ERROR_WANT_READ) return select(0, &fds, NULL, NULL, &tv);
    if (ssl_err == SSL_ERROR_WANT_WRITE) return select(0, NULL, &fds, NULL, &tv);
    return -1;
}

int connect_covert_tunnel(covert_context_t *ctx, const char* ip, int port) {
    struct addrinfo hints, *res = NULL, *p = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(ip, NULL, &hints, &res) != 0) return -1;
    int connected = -1;
    for (p = res; p != NULL; p = p->ai_next) {
        ctx->socket_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (ctx->socket_fd == INVALID_SOCKET) continue;
        if (p->ai_family == AF_INET) ((struct sockaddr_in*)p->ai_addr)->sin_port = htons(port);
        else ((struct sockaddr_in6*)p->ai_addr)->sin6_port = htons(port);
        unsigned long mode = 1;
        ioctlsocket(ctx->socket_fd, FIONBIO, &mode);
        if (connect(ctx->socket_fd, p->ai_addr, (int)p->ai_addrlen) == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                fd_set write_fds;
                FD_ZERO(&write_fds);
                FD_SET(ctx->socket_fd, &write_fds);
                struct timeval tv = { 3, 0 };
                if (select(0, NULL, &write_fds, NULL, &tv) > 0) {
                    connected = 0;
                    break;
                }
            }
            closesocket(ctx->socket_fd);
            ctx->socket_fd = INVALID_SOCKET;
        } else {
            connected = 0;
            break;
        }
    }
    if (res) freeaddrinfo(res);
    if (connected != 0) return -1;
    ctx->ssl_handle = SSL_new(ctx->ssl_ctx);
    if (!ctx->ssl_handle) {
        closesocket(ctx->socket_fd);
        ctx->socket_fd = INVALID_SOCKET;
        return -1;
    }
    if (ctx->socket_fd > (SOCKET)INT_MAX) {
        SSL_free(ctx->ssl_handle);
        ctx->ssl_handle = NULL;
        closesocket(ctx->socket_fd);
        ctx->socket_fd = INVALID_SOCKET;
        return -1;
    }
    SSL_set_fd(ctx->ssl_handle, (int)ctx->socket_fd);
    if (ctx->mask_mode == MASK_HTTPS_VALID && ctx->fake_sni[0] != '\0') {
        SSL_set_tlsext_host_name(ctx->ssl_handle, ctx->fake_sni);
    }
    int handshake_res;
    while ((handshake_res = SSL_connect(ctx->ssl_handle)) <= 0) {
        int ssl_err = SSL_get_error(ctx->ssl_handle, handshake_res);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            if (handle_ssl_blocking_state(ctx->socket_fd, ssl_err, 5000) <= 0) goto fail_cleanup;
        } else {
            goto fail_cleanup;
        }
    }
    return 0;
fail_cleanup:
    SSL_free(ctx->ssl_handle);
    ctx->ssl_handle = NULL;
    closesocket(ctx->socket_fd);
    ctx->socket_fd = INVALID_SOCKET;
    return -1;
}

int send_covert_packet(covert_context_t *ctx, const uint8_t* buf, int len) {
    if (!ctx || !ctx->ssl_handle || !buf || len <= 0) return -1;
    if (ctx->mask_mode == MASK_HTTPS_VALID && len > HTTPS_STANDARD_MTU) return -1;
    uint16_t entropy;
    if (RAND_bytes((uint8_t*)&entropy, sizeof(entropy)) != 1) return -1;
    stealth_jitter_us(80 + (entropy % 270));
    const uint8_t* data_to_send = buf;
    int data_len = len;
    uint8_t final_buffer[HTTPS_STANDARD_MTU];
    if (ctx->mask_mode == MASK_HTTPS_VALID) {
        memcpy(final_buffer, buf, len);
        if (len < HTTPS_STANDARD_MTU) {
            RAND_bytes(final_buffer + len, HTTPS_STANDARD_MTU - len);
            data_len = HTTPS_STANDARD_MTU;
        }
        data_to_send = final_buffer;
    }
    int sent;
    while ((sent = SSL_write(ctx->ssl_handle, data_to_send, data_len)) <= 0) {
        int ssl_err = SSL_get_error(ctx->ssl_handle, sent);
        if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
            if (handle_ssl_blocking_state(ctx->socket_fd, ssl_err, 3000) <= 0) return -1;
        } else {
            return -1;
        }
    }
    return sent;
}
