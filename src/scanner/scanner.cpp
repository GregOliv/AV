#include "scanner/scanner.h"
#include "utils/logger.h"

#include <chrono>
#include <fstream>
#include <algorithm>

namespace av {

Scanner::Scanner() {
    // Pass cancel flag ke walker agar counting bisa di-cancel
    m_walker.set_cancel_flag(&m_cancel_requested);
}
Scanner::~Scanner() = default;

bool Scanner::load_database(const std::string& db_path) {
    size_t count = m_database.load(db_path);
    if (count == 0) {
        Logger::instance().warning("Hash database is empty or failed to load: " + db_path);
        return false;
    }
    if (!m_database.verify_integrity()) {
        Logger::instance().error("Hash database integrity check failed");
        return false;
    }
    m_db_loaded = true;
    Logger::instance().info("Database loaded: " + std::to_string(count) + " signatures");
    return true;
}

bool Scanner::init_quarantine(const std::string& quarantine_path) {
    m_quarantine_initialized = m_quarantine.init(quarantine_path);
    return m_quarantine_initialized;
}

void Scanner::set_max_file_size(uintmax_t max_bytes) {
    m_walker.set_max_file_size(max_bytes);
}

void Scanner::set_auto_quarantine(bool enabled) {
    m_auto_quarantine = enabled;
}

void Scanner::set_progress_callback(ScanProgressCallback callback) {
    m_progress_callback = callback;
}

void Scanner::add_exclude_path(const std::string& path) {
    m_walker.add_exclude_path(path);
}

bool Scanner::load_whitelist(const std::string& wl_path) {
    std::lock_guard<std::mutex> lk(m_wl_mutex);
    std::ifstream file(wl_path);
    if (!file.is_open()) return false;

    m_whitelist.clear();
    std::string line;
    while (std::getline(file, line)) {
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (line.empty() || line[0] == '#') continue;
        // Normalisasi ke lowercase
        std::transform(line.begin(), line.end(), line.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (line.length() == 64) m_whitelist.insert(line);
    }
    Logger::instance().info("Whitelist loaded: " + std::to_string(m_whitelist.size()) + " entries");
    return true;
}

void Scanner::add_to_whitelist(const std::string& hash) {
    std::lock_guard<std::mutex> lk(m_wl_mutex);
    std::string h = hash;
    std::transform(h.begin(), h.end(), h.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    m_whitelist.insert(h);
}

bool Scanner::save_whitelist(const std::string& wl_path) const {
    std::lock_guard<std::mutex> lk(m_wl_mutex);
    std::ofstream file(wl_path);
    if (!file.is_open()) return false;
    file << "# AV Guard Whitelist — known-safe SHA-256 hashes\n";
    file << "# One hash per line\n";
    for (const auto& h : m_whitelist) {
        file << h << "\n";
    }
    return true;
}

size_t Scanner::whitelist_size() const {
    std::lock_guard<std::mutex> lk(m_wl_mutex);
    return m_whitelist.size();
}

void Scanner::request_cancel() {
    m_cancel_requested = true;
}

bool Scanner::is_cancelled() const {
    return m_cancel_requested.load();
}

ScanStats Scanner::scan(const std::string& target_path) {
    ScanStats stats;
    m_results.clear();
    m_cancel_requested = false;

    if (!m_db_loaded) {
        Logger::instance().error("No hash database loaded.");
        return stats;
    }

    Logger::instance().info("Starting scan: " + target_path);
    auto start_time = std::chrono::high_resolution_clock::now();

    // Phase 1: Count files (with progress reporting)
    size_t total_files = 0;
    auto last_report = start_time;

    try {
        m_walker.walk(target_path, [&](const std::string&, uintmax_t) {
            if (m_cancel_requested) return;
            ++total_files;
            auto now = std::chrono::high_resolution_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_report).count() > 200) {
                if (m_phase_callback)
                    m_phase_callback(Phase::COUNTING, total_files, 0);
                last_report = now;
            }
        });
    } catch (...) {
        Logger::instance().warning("Exception during file counting (continuing with partial count)");
    }

    if (m_cancel_requested) return stats;
    if (total_files == 0) {
        Logger::instance().info("No scannable files found in: " + target_path);
        return stats;
    }

    stats.total_files = total_files;
    Logger::instance().info("Files to scan: " + std::to_string(total_files));

    if (m_phase_callback)
        m_phase_callback(Phase::SCANNING, 0, total_files);

    // Phase 2: Scan each file
    size_t current = 0;

    try {
        m_walker.walk(target_path, [&](const std::string& file_path, uintmax_t file_size) {
            if (m_cancel_requested) return;
            ++current;
            ++stats.scanned_files;

            if (m_phase_callback && current % 100 == 0)
                m_phase_callback(Phase::SCANNING, current, total_files);

            try {
                ScanResult result;
                result.file_path = file_path;
                result.file_size = file_size;

                // Hash file
                result.hash = m_hasher.sha256_file(file_path);
                if (result.hash.empty()) {
                    ++stats.errors;
                    return; // File tidak bisa di-hash, skip
                }

                // Cocokkan dengan database
                if (m_database.contains(result.hash)) {
                    // Cek whitelist dulu — jika sudah di-whitelist, skip
                    {
                        std::lock_guard<std::mutex> wlk(m_wl_mutex);
                        if (m_whitelist.count(result.hash) > 0) {
                            // File ada di whitelist, aman
                            if (m_progress_callback)
                                m_progress_callback(result, current, total_files);
                            return;
                        }
                    }

                    auto threat = m_database.get_threat_info(result.hash);
                    result.is_threat = true;
                    result.threat_name = threat.name + " [" + threat.category + "|" + threat.severity + "]";
                    ++stats.threats_found;

                    Logger::instance().critical("THREAT: " + file_path + " => " + threat.name);

                    if (m_auto_quarantine && m_quarantine_initialized) {
                        if (m_quarantine.quarantine_file(file_path, "Hash: " + result.hash))
                            ++stats.quarantined;
                    }

                    // Simpan hanya threats
                    std::lock_guard<std::mutex> lock(m_results_mutex);
                    m_results.push_back(result);
                }

                // Progress callback
                if (m_progress_callback)
                    m_progress_callback(result, current, total_files);

            } catch (...) {
                ++stats.errors;
                // File bermasalah — skip, lanjut ke file berikutnya
            }
        });
    } catch (...) {
        Logger::instance().warning("Exception during scan walk (partial results returned)");
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    stats.elapsed_seconds = std::chrono::duration<double>(end_time - start_time).count();

    Logger::instance().info("Scan complete: "
        + std::to_string(stats.scanned_files) + " scanned, "
        + std::to_string(stats.threats_found) + " threats, "
        + std::to_string(stats.errors) + " errors, "
        + std::to_string(stats.elapsed_seconds) + "s");

    return stats;
}

const std::vector<ScanResult>& Scanner::get_results() const {
    return m_results;
}

std::vector<ScanResult> Scanner::get_threats() const {
    std::vector<ScanResult> threats;
    for (const auto& r : m_results) {
        if (r.is_threat) threats.push_back(r);
    }
    return threats;
}

} // namespace av
