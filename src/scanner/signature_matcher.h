#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace av {

struct Signature {
    std::string name;
    std::vector<uint8_t> pattern;
};

class SignatureMatcher {
public:
    SignatureMatcher();
    ~SignatureMatcher();

    // Menambah pola byte untuk dideteksi
    void add_signature(const std::string& name, const std::vector<uint8_t>& pattern);
    
    // Cek file terhadap semua signature. Mengembalikan true jika terdeteksi.
    bool scan(const std::string& filepath, std::string& out_threat_name);

private:
    std::vector<Signature> m_signatures;
    
    // Buffer terbatas agar mencegah memory exhaustion (DoS) saat membaca file raksasa
    static constexpr size_t MAX_SCAN_SIZE = 10 * 1024 * 1024; // Limit 10MB pertama
};

} // namespace av
