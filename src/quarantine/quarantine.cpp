#include "quarantine/quarantine.h"
#include "utils/logger.h"

#include <filesystem>
#include <fstream>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace fs = std::filesystem;

namespace av {

QuarantineManager::QuarantineManager() = default;
QuarantineManager::~QuarantineManager() = default;

bool QuarantineManager::init(const std::string& quarantine_path) {
    m_quarantine_path = quarantine_path;

    std::error_code ec;
    if (!fs::exists(quarantine_path, ec)) {
        if (!fs::create_directories(quarantine_path, ec)) {
            Logger::instance().error("Failed to create quarantine directory: " + quarantine_path);
            return false;
        }
    }

    m_initialized = true;
    Logger::instance().info("Quarantine initialized at: " + quarantine_path);
    return true;
}

std::string QuarantineManager::generate_quarantine_name(const std::string& original_path) const {
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();

    // Use timestamp + original filename to create unique name
    fs::path orig(original_path);
    std::ostringstream oss;
    oss << millis << "_" << orig.filename().string() << ".quarantined";
    return oss.str();
}

bool QuarantineManager::write_metadata(const std::string& quarantine_name,
                                        const std::string& original_path,
                                        const std::string& reason) const {
    std::string meta_path = (fs::path(m_quarantine_path) / (quarantine_name + ".meta")).string();
    std::ofstream meta(meta_path);
    if (!meta.is_open()) {
        return false;
    }

    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_now;
#ifdef _WIN32
    localtime_s(&tm_now, &time_t_now);
#else
    localtime_r(&time_t_now, &tm_now);
#endif

    meta << "original_path=" << original_path << "\n";
    meta << "quarantine_name=" << quarantine_name << "\n";
    meta << "reason=" << reason << "\n";

    std::ostringstream time_oss;
    time_oss << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S");
    meta << "timestamp=" << time_oss.str() << "\n";

    return true;
}

bool QuarantineManager::quarantine_file(const std::string& file_path, const std::string& reason) {
    if (!m_initialized) {
        Logger::instance().error("Quarantine not initialized");
        return false;
    }

    // Verify source file exists
    std::error_code ec;
    if (!fs::exists(file_path, ec)) {
        Logger::instance().error("File not found for quarantine: " + file_path);
        return false;
    }

    std::string q_name = generate_quarantine_name(file_path);
    fs::path dest = fs::path(m_quarantine_path) / q_name;

    // Move file to quarantine
    fs::rename(file_path, dest, ec);
    if (ec) {
        // If rename fails (cross-device), try copy + delete
        fs::copy_file(file_path, dest, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            Logger::instance().error("Failed to quarantine file: " + file_path + " (" + ec.message() + ")");
            return false;
        }
        fs::remove(file_path, ec);
        if (ec) {
            Logger::instance().warning("File copied to quarantine but original could not be removed: " + file_path);
        }
    }

    // Write metadata
    if (!write_metadata(q_name, file_path, reason)) {
        Logger::instance().warning("Failed to write quarantine metadata for: " + file_path);
    }

    Logger::instance().info("Quarantined: " + file_path + " -> " + q_name);
    return true;
}

bool QuarantineManager::restore_file(const std::string& quarantined_name) {
    if (!m_initialized) {
        Logger::instance().error("Quarantine not initialized");
        return false;
    }

    // Read metadata to get original path
    std::string meta_path = (fs::path(m_quarantine_path) / (quarantined_name + ".meta")).string();
    std::ifstream meta(meta_path);
    if (!meta.is_open()) {
        Logger::instance().error("Metadata not found for: " + quarantined_name);
        return false;
    }

    std::string original_path;
    std::string line;
    while (std::getline(meta, line)) {
        if (line.rfind("original_path=", 0) == 0) {
            original_path = line.substr(14);
            break;
        }
    }

    if (original_path.empty()) {
        Logger::instance().error("Original path not found in metadata for: " + quarantined_name);
        return false;
    }

    // Move back to original location
    fs::path src = fs::path(m_quarantine_path) / quarantined_name;
    std::error_code ec;

    fs::rename(src, original_path, ec);
    if (ec) {
        fs::copy_file(src, original_path, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            Logger::instance().error("Failed to restore file: " + quarantined_name + " (" + ec.message() + ")");
            return false;
        }
        fs::remove(src, ec);
    }

    // Remove metadata file
    fs::remove(meta_path, ec);

    Logger::instance().info("Restored: " + quarantined_name + " -> " + original_path);
    return true;
}

const std::string& QuarantineManager::get_path() const {
    return m_quarantine_path;
}

size_t QuarantineManager::count() const {
    if (!m_initialized) return 0;

    size_t count = 0;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(m_quarantine_path, ec)) {
        if (entry.path().extension() == ".quarantined") {
            ++count;
        }
    }
    return count;
}

} // namespace av
