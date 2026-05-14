#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>

// Только наши заголовки оборачиваем в extern "C"
extern "C" {
    #include "encoding.h"
    #include "common.h"
    #include "network.h"
}

u8 xor_key = 0x37;

void server_init() {
    std::cout << "[SERVER] Initializing network..." << std::endl;
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        std::cerr << "[ERROR] WSAStartup failed!" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    std::cout << "[SERVER] WSAStartup OK\n";
}

void server_cleanup() {
    WSACleanup();
    std::cout << "[SERVER] Network cleanup complete\n";
}

// ========================================================
// ФУНКЦИЯ PARSE_MULTIPART
// ========================================================
int parse_multipart(SOCKET sock, char* body, size_t body_len,
                    std::string& boundary, std::string& content) {
    std::string full_boundary = "--" + boundary;
    char* data_part = strstr(body, full_boundary.c_str());
    if (!data_part) {
        std::cerr << "[SERVER] Boundary not found\n";
        return -1;
    }
    char* search_start = data_part + full_boundary.length();
    char* content_start = strstr(search_start, "\r\n\r\n");
    if (!content_start) {
        std::cerr << "[SERVER] Malformed multipart: no headers end found\n";
        return -1;
    }
    content_start += 4;
    std::string end_boundary = "\r\n--" + boundary;
    char* content_end = strstr(content_start, end_boundary.c_str());
    if (content_end) {
        content.assign(content_start, content_end - content_start);
        return 0;
    }
    content.assign(content_start);
    return 0;
}

// ========================================================
// ОСНОВНАЯ ФУНКЦИЯ MAIN
// ========================================================
int main() {
    server_init();
    SOCKET s_server = socket(AF_INET, SOCK_STREAM, 0);
    if (s_server == INVALID_SOCKET) {
        std::cerr << "[ERROR] Socket creation failed!" << std::endl;
        server_cleanup();
        return 1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
    if (::bind(s_server, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "[ERROR] Bind failed!" << std::endl;
        net_close(s_server);
        server_cleanup();
        return 1;
    }
    std::cout << "[SERVER] Bound to 127.0.0.1:8080\n";

    if (::listen(s_server, 5) < 0) {
        std::cerr << "[ERROR] Listen failed!" << std::endl;
        net_close(s_server);
        server_cleanup();
        return 1;
    }
    std::cout << "[SERVER] Listening...\n";
    std::cout << "[SERVER] Waiting for client...\n";

    SOCKET client_socket = ::accept(s_server, NULL, NULL);
    if (client_socket == INVALID_SOCKET) {
        std::cerr << "[ERROR] Accept failed!" << std::endl;
        net_close(s_server);
        server_cleanup();
        return 1;
    }
    std::cout << "[SERVER] Client connected\n";

    // ========================================================
    // ЧТЕНИЕ ЗАПРОСА: читаем заголовки + тело полностью
    // ========================================================
    char request[65536] = {0};
    int total_received = 0;
    int content_length = 0;

    while (total_received < (int)sizeof(request) - 1) {
        int bytes = ::recv(client_socket,
                           request + total_received,
                           sizeof(request) - 1 - total_received, 0);
        if (bytes <= 0) {
            std::cerr << "[SERVER] Connection closed or recv error\n";
            break;
        }
        total_received += bytes;
        request[total_received] = '\0';

        // Ищем конец заголовков
        char* header_end = strstr(request, "\r\n\r\n");
        if (!header_end) continue; // заголовки ещё не пришли полностью

        // Парсим Content-Length один раз
        if (content_length == 0) {
            char* cl = strstr(request, "Content-Length:");
            if (cl) {
                content_length = atoi(cl + 15);
                std::cout << "[SERVER] Content-Length: " << content_length << "\n";
            }
        }

        // Проверяем получили ли тело целиком
        int header_size  = (int)((header_end + 4) - request);
        int body_received = total_received - header_size;
        if (content_length > 0 && body_received >= content_length) {
            std::cout << "[SERVER] Full request received ("
                      << total_received << " bytes)\n";
            break;
        }
    }

    std::cout << "[SERVER] Received request:\n" << request << std::endl;

    // Проверяем что это POST
    if (strstr(request, "POST") == NULL) {
        std::cerr << "[SERVER] Not a POST request\n";
        net_close(client_socket);
        net_close(s_server);
        server_cleanup();
        return 1;
    }

    // Ищем тело после "\r\n\r\n"
    char* body_start = strstr(request, "\r\n\r\n");
    if (!body_start) {
        std::cerr << "[SERVER] No body found\n";
        net_close(client_socket);
        net_close(s_server);
        server_cleanup();
        return 1;
    }
    char* body = body_start + 4;

    // Парсим multipart
    std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    std::string content;
    if (parse_multipart(client_socket, body, strlen(body), boundary, content) != 0) {
        std::cerr << "[SERVER] Failed to parse multipart\n";
        net_close(client_socket);
        net_close(s_server);
        server_cleanup();
        return 1;
    }
    std::cout << "[SERVER] Content length: " << content.length() << " bytes\n";

    // ========================================================
    // КРИТИЧЕСКИ ВАЖНЫЙ ШАГ: Санитизация PEM-данных
    // ========================================================
    std::cout << "[SERVER] Starting PEM payload sanitization...\n";

    char* cleaned_ptr = clean_base64_payload(content.c_str());

    if (!cleaned_ptr) {
        std::cerr << "[ERROR] Sanitation failed (OOM or Null)\n";
        net_close(client_socket);
        net_close(s_server);
        server_cleanup();
        return 1;
    }

    std::cout << "[SERVER] Cleaned payload length: " << strlen(cleaned_ptr) << " bytes\n";

    // ========================================================
    // Декодируем Base64
    // ========================================================
    sz decoded_len = 0;
    u8* decoded_bytes = base64_decode(cleaned_ptr, &decoded_len);

    // ВНИМАНИЕ: Очищаем память cleaned_ptr после использования!
    free(cleaned_ptr);

    if (!decoded_bytes) {
        std::cerr << "[SERVER] Base64 decode failed even after sanitation!\n";
        net_close(client_socket);
        net_close(s_server);
        server_cleanup();
        return 1;
    }

    std::cout << "[SERVER] Decoded: " << decoded_len << " bytes\n";

    // ========================================================
    // Снимаем XOR
    // ========================================================
    u8* clean_data = xor_buf(decoded_bytes, decoded_len, xor_key);
    free(decoded_bytes);

    if (!clean_data) {
        std::cerr << "[SERVER] XOR failed\n";
        net_close(client_socket);
        net_close(s_server);
        server_cleanup();
        return 1;
    }
    std::cout << "[SERVER] XOR removed\n";

    // ========================================================
    // Сохраняем в файл
    // ========================================================
    std::ofstream f("received_key.bin", std::ios::binary);
    if (!f.is_open()) {
        std::cerr << "[SERVER] Cannot open file\n";
        free(clean_data);
        net_close(client_socket);
        net_close(s_server);
        server_cleanup();
        return 1;
    }
    f.write((char*)clean_data, decoded_len);
    f.close();
    free(clean_data);

    std::cout << "[SERVER] Key saved to received_key.bin\n";

    // ========================================================
    // Отправляем HTTP ответ
    // ========================================================
    const char* http_response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 29\r\n"
        "Connection: close\r\n\r\n"
        "PQC_KEY_STASHED_SUCCESSFULLY";

    ::send(client_socket, http_response, (int)strlen(http_response), 0);
    std::cout << "[SERVER] Response sent\n";

    // Завершение
    net_close(client_socket);
    net_close(s_server);
    server_cleanup();
    std::cout << "[SERVER] Shutdown complete\n";

    return 0;
}

