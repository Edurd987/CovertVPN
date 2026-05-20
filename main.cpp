#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <cstring>

extern "C" {
    #include "network.h"
    #include "encoding.h"
   
}

// Используем твой XOR ключ
u8 xor_key = 0x37;

int main() {
    // 1. Инициализация сети
    net_init();

    // 2 & 3. Подключение (используем функции из твоего network.h для чистоты)
    SOCKET s_client = net_connect("127.0.0.1", 8080); 
    if (s_client == INVALID_SOCKET) {
        std::cerr << "[ERROR] Connection failed! Is server running on 8080?" << std::endl;
        net_cleanup();
        return 1;
    }

    std::cout << "[CONNECTED] Preparing obfuscated PQC transfer..." << std::endl;

    // 5. Данные
    const char* raw_pqc = "REAL_BINARY_PQC_DATA_1234567890_ABCDEF";
    sz raw_len = strlen(raw_pqc);

    // 6. Обфускация: ТВОЙ XOR
    u8* xored = xor_buf((const u8*)raw_pqc, raw_len, xor_key);
    
    // 7. Кодирование: ТВОЙ Base64
    char* encoded_key = base64_encode(xored, raw_len);
    
    // Освобождаем промежуточный XOR буфер сразу
    free(xored);

    // 8. Сборка тела запроса
    std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    std::stringstream body;
    body << "--" << boundary << "\r\n"
         << "Content-Disposition: form-data; name=\"pqc_key\"\r\n"
         << "Content-Type: text/plain\r\n\r\n"
         << encoded_key << "\r\n"
         << "--" << boundary << "--\r\n";
    std::string body_str = body.str();
    free(encoded_key); // Очищаем после копирования в stringstream

    // 9. Заголовки
    std::stringstream headers;
    headers << "POST /upload/pqc HTTP/1.1\r\n"
            << "Host: 127.0.0.1\r\n"
            << "Content-Type: multipart/form-data; boundary=" << boundary << "\r\n"
            << "Content-Length: " << body_str.length() << "\r\n"
            << "Connection: close\r\n\r\n";

    std::string full_request = headers.str() + body_str;

    // 10. Отправка (используем твою логику фрагментации)
    std::cout << "[SEND] Delivering PQC payload..." << std::endl;
    const char* p = full_request.c_str();
    size_t total_sent = 0;
    while (total_sent < full_request.length()) {
        size_t chunk = (rand() % 128) + 32; 
        if (total_sent + chunk > full_request.length()) chunk = full_request.length() - total_sent;
        
        send(s_client, p + total_sent, (int)chunk, 0);
        total_sent += chunk;
        Sleep(10); // Небольшая пауза для имитации живого трафика
    }

    std::cout << "[SUCCESS] Payload sent. Waiting for ACK..." << std::endl;

    // 11. Ответ сервера
    char response[1024] = {0};
    recv(s_client, response, sizeof(response) - 1, 0);
    std::cout << "[RESPONSE] " << response << std::endl;

    // 12. Очистка
    net_close(s_client);
    net_cleanup();
    return 0;
}
