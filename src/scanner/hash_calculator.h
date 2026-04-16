#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace av {

class HashCalculator {
public:
    HashCalculator();
    ~HashCalculator();

    // Calculate SHA-256 hash of a file
    // Returns lowercase hex string, or empty string on error
    std::string sha256_file(const std::string& file_path) const;

    // Calculate SHA-256 hash of raw bytes (for testing)
    std::string sha256_bytes(const uint8_t* data, size_t length) const;

private:
    // Convert raw hash bytes to hex string
    static std::string bytes_to_hex(const uint8_t* data, size_t length);

    // Buffer size for file reading (64 KB)
    static constexpr size_t READ_BUFFER_SIZE = 65536;
};

} // namespace av
