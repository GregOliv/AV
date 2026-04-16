#include "scanner/signature_matcher.h"
#include <fstream>
#include <algorithm>

namespace av {

SignatureMatcher::SignatureMatcher() = default;
SignatureMatcher::~SignatureMatcher() = default;

void SignatureMatcher::add_signature(const std::string& name, const std::vector<uint8_t>& pattern) {
    if (!pattern.empty()) {
        m_signatures.push_back({name, pattern});
    }
}

bool SignatureMatcher::scan(const std::string& filepath, std::string& out_threat_name) {
    if (m_signatures.empty()) return false;

    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) return false;

    // Batasi maksimum file scan untuk efisiensi dan mitigasi DoS
    file.seekg(0, std::ios::end);
    std::streamsize filesize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::streamsize read_size = std::min(filesize, static_cast<std::streamsize>(MAX_SCAN_SIZE));
    if (read_size <= 0) return false;

    std::vector<uint8_t> buffer(read_size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), read_size)) {
        return false;
    }

    // Pencarian pola byte paling sederhana (Bisa dioptimasi menjadi Aho-Corasick/Boyer-Moore nanti)
    for (const auto& sig : m_signatures) {
        if (sig.pattern.size() > buffer.size()) continue;

        auto it = std::search(buffer.begin(), buffer.end(), sig.pattern.begin(), sig.pattern.end());
        if (it != buffer.end()) {
            out_threat_name = sig.name;
            return true; // Ditemukan hit signature
        }
    }

    return false;
}

} // namespace av
