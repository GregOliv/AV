#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace av {

struct PE_Info {
    bool is_valid_pe = false;
    uint16_t machine = 0;
    uint16_t sections_count = 0;
    bool is_executable = false;
    bool is_dll = false;
    std::vector<std::string> suspicious_indicators;
};

class PEAnalyzer {
public:
    // Analisis header PE (Portable Executable) secara aman
    PE_Info analyze(const std::string& filepath);
};

} // namespace av
