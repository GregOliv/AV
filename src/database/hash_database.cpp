#include "database/hash_database.h"
#include "utils/logger.h"

#include <fstream>
#include <algorithm>
#include <cctype>
#include <sstream>

namespace av {

HashDatabase::HashDatabase() = default;
HashDatabase::~HashDatabase() = default;

bool HashDatabase::is_valid_sha256(const std::string& hash) {
    if (hash.length() != 64) return false;
    for (char c : hash) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

std::string HashDatabase::normalize(const std::string& hash) {
    std::string result = hash;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

size_t HashDatabase::load(const std::string& db_file_path) {
    std::ifstream file(db_file_path);
    if (!file.is_open()) {
        Logger::instance().error("Cannot open hash database: " + db_file_path);
        return 0;
    }

    m_hashes.clear();
    m_threat_map.clear();
    std::string line;
    size_t loaded = 0;
    size_t skipped = 0;

    while (std::getline(file, line)) {
        // Trim
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty() || line[0] == '#') continue;

        // Format baru: hash|name|category|severity
        // Format lama: hash [spasi filename]
        ThreatInfo info;

        auto pipe1 = line.find('|');
        if (pipe1 != std::string::npos) {
            // Format pipe-separated
            std::string hash_part = normalize(line.substr(0, pipe1));
            if (!is_valid_sha256(hash_part)) { ++skipped; continue; }

            info.hash = hash_part;

            auto pipe2 = line.find('|', pipe1 + 1);
            if (pipe2 != std::string::npos) {
                info.name = line.substr(pipe1 + 1, pipe2 - pipe1 - 1);
                auto pipe3 = line.find('|', pipe2 + 1);
                if (pipe3 != std::string::npos) {
                    info.category = line.substr(pipe2 + 1, pipe3 - pipe2 - 1);
                    info.severity = line.substr(pipe3 + 1);
                } else {
                    info.category = line.substr(pipe2 + 1);
                    info.severity = "Medium";
                }
            } else {
                info.name = line.substr(pipe1 + 1);
                info.category = "Malware";
                info.severity = "Medium";
            }

            m_hashes.insert(hash_part);
            m_threat_map[hash_part] = info;
            ++loaded;
        } else {
            // Format lama: hash saja
            std::string hash_part;
            auto space_pos = line.find_first_of(" \t");
            hash_part = (space_pos != std::string::npos) ? line.substr(0, space_pos) : line;

            std::string normalized = normalize(hash_part);
            if (!is_valid_sha256(normalized)) { ++skipped; continue; }

            info.hash = normalized;
            info.name = "Malware.Generic.SHA256";
            info.category = "Malware";
            info.severity = "Medium";

            m_hashes.insert(normalized);
            m_threat_map[normalized] = info;
            ++loaded;
        }
    }

    Logger::instance().info("Loaded " + std::to_string(loaded) + " hashes from: " + db_file_path);
    if (skipped > 0) {
        Logger::instance().warning("Skipped " + std::to_string(skipped) + " invalid entries");
    }

    return loaded;
}

bool HashDatabase::contains(const std::string& hash) const {
    return m_hashes.count(normalize(hash)) > 0;
}

ThreatInfo HashDatabase::get_threat_info(const std::string& hash) const {
    auto it = m_threat_map.find(normalize(hash));
    if (it != m_threat_map.end()) return it->second;
    ThreatInfo unknown;
    unknown.name = "Unknown";
    unknown.category = "Unknown";
    unknown.severity = "Unknown";
    return unknown;
}

size_t HashDatabase::size() const {
    return m_hashes.size();
}

void HashDatabase::clear() {
    m_hashes.clear();
    m_threat_map.clear();
}

bool HashDatabase::verify_integrity() const {
    for (const auto& hash : m_hashes) {
        if (!is_valid_sha256(hash)) return false;
    }
    return true;
}

} // namespace av
