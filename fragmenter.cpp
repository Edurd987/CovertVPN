#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <climits>

// Подключаем наши общие стандарты (C-интерфейсы оборачиваем в extern "C")
extern "C" {
    #include "types.h"
    #include "network.h"
}

// Задаем лимиты для защиты от переполнения и DoS-атак
#define FRAGMENT_MAX_DATA_SIZE 512
#define MAX_ASSEMBLY_SIZE (10 * 1024 * 1024) // 10 Мегабайт — жесткий лимит на один поток сборки

struct Fragment {
    uint32_t sequence_id;
    uint8_t is_last;
    std::vector<uint8_t> data;
};

class StreamFragmenter {
public:
    /**
     * @brief Нарезает большой массив данных на безопасные фрагменты
     */
    static std::vector<Fragment> split_stream(const uint8_t* raw_data, size_t total_size) {
        std::vector<Fragment> fragments;
        if (!raw_data || total_size == 0) return fragments;

        uint32_t seq = 0;
        size_t offset = 0;

        while (offset < total_size) {
            // Замечание №1: Защита от переполнения sequence_id
            if (seq == UINT32_MAX) {
                std::cerr << "[-] Fragmenter Error: Stream is too large, sequence_id overflow danger.\n";
                return {}; // Возвращаем пустой вектор, прекращая обработку
            }

            Fragment frag;
            frag.sequence_id = seq++;
            
            size_t remaining = total_size - offset;
            size_t chunk_size = (remaining > FRAGMENT_MAX_DATA_SIZE) ? FRAGMENT_MAX_DATA_SIZE : remaining;
            
            frag.is_last = (offset + chunk_size >= total_size) ? 1 : 0;
            
            frag.data.assign(raw_data + offset, raw_data + offset + chunk_size);
            fragments.push_back(frag);

            offset += chunk_size;
        }

        return fragments;
    }
};

class StreamAssembler {
private:
    std::vector<uint8_t> assembly_buffer;
    uint32_t expected_seq = 0;
    bool is_complete = false;

public:
    void reset() {
        assembly_buffer.clear();
        expected_seq = 0;
        is_complete = false;
    }

    /**
     * @brief Собирает фрагменты обратно в единый поток с контролем последовательности и лимитов памяти
     * @return true - поток полностью собран, false - ожидает куски или произошел сбой
     */
    bool add_fragment(const Fragment& frag) {
        if (is_complete) return true;

        // Контроль нарушения порядка пакетов (Out-of-Order)
        if (frag.sequence_id != expected_seq) {
            std::cerr << "[-] Assembler Error: Packet drop detected. Expected " 
                      << expected_seq << ", got " << frag.sequence_id << "\n";
            reset(); 
            return false;
        }

        // Замечание №2: Защита от неограниченного роста буфера (OOM DoS Attack Prevention)
        if (assembly_buffer.size() + frag.data.size() > MAX_ASSEMBLY_SIZE) {
            std::cerr << "[-] Security Alert: Assembly buffer exceeded MAX_ASSEMBLY_SIZE! Dropping stream.\n";
            reset();
            return false;
        }

        // Безопасное дописывание данных
        assembly_buffer.insert(assembly_buffer.end(), frag.data.begin(), frag.data.end());
        expected_seq++;

        if (frag.is_last == 1) {
            is_complete = true;
            return true;
        }

        return false;
    }

    const std::vector<uint8_t>& get_result() const {
        return assembly_buffer;
    }

    bool is_stream_ready() const {
        return is_complete;
    }
};
