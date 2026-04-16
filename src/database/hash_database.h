#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>

namespace av {

struct ThreatInfo {
    std::string hash;
    std::string name;       // e.g. "Trojan.Win32.Agent"
    std::string category;   // e.g. "Trojan", "Worm", "Ransomware"
    std::string severity;   // "Low", "Medium", "High", "Critical"
};

class HashDatabase {
public:
    HashDatabase();
    ~HashDatabase();

    // Load hash database from file
    // Format baru: hash|name|category|severity  (pipe-separated)
    // Format lama: hash saja (tetap didukung)
    size_t load(const std::string& db_file_path);

    // Check if a hash exists in the database
    bool contains(const std::string& hash) const;

    // Get threat info for a hash
    ThreatInfo get_threat_info(const std::string& hash) const;

    size_t size() const;
    void clear();
    bool verify_integrity() const;

private:
    std::unordered_set<std::string> m_hashes;
    std::unordered_map<std::string, ThreatInfo> m_threat_map;

    static bool is_valid_sha256(const std::string& hash);
    static std::string normalize(const std::string& hash);
};

} // namespace av
