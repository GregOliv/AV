#pragma once

#include "scanner/file_walker.h"
#include "scanner/hash_calculator.h"
#include "database/hash_database.h"
#include "quarantine/quarantine.h"

#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <functional>
#include <unordered_set>

namespace av {

// Scan result for a single file
struct ScanResult {
    std::string file_path;
    std::string hash;
    bool is_threat = false;
    std::string threat_name; // e.g., "Malware.Generic.SHA256"
    uintmax_t file_size = 0;
};

// Overall scan statistics
struct ScanStats {
    size_t total_files = 0;
    size_t scanned_files = 0;
    size_t threats_found = 0;
    size_t errors = 0;
    size_t quarantined = 0;
    double elapsed_seconds = 0.0;
};

// Callback for scan progress
using ScanProgressCallback = std::function<void(const ScanResult& result, size_t current, size_t total)>;

class Scanner {
public:
    Scanner();
    ~Scanner();

    // Load hash database
    bool load_database(const std::string& db_path);

    // Initialize quarantine
    bool init_quarantine(const std::string& quarantine_path);

    // Configure scanner
    void set_max_file_size(uintmax_t max_bytes);
    void set_auto_quarantine(bool enabled);
    void set_progress_callback(ScanProgressCallback callback);

    // Exclude paths (quarantine folder, etc.)
    void add_exclude_path(const std::string& path);

    // Whitelist: hashes that are known-safe and should not be flagged
    bool load_whitelist(const std::string& wl_path);
    void add_to_whitelist(const std::string& hash);
    bool save_whitelist(const std::string& wl_path) const;
    size_t whitelist_size() const;

    // Cancel support
    void request_cancel();
    bool is_cancelled() const;

    // Optional ETA helpers
    enum class Phase { COUNTING, SCANNING };
    std::function<void(Phase, size_t, size_t)> m_phase_callback;
    void set_phase_callback(std::function<void(Phase, size_t, size_t)> cb) { m_phase_callback = cb; }

    ScanStats scan(const std::string& target_path);
    const std::vector<ScanResult>& get_results() const;
    std::vector<ScanResult> get_threats() const;

private:
    FileWalker m_walker;
    HashCalculator m_hasher;
    HashDatabase m_database;
    QuarantineManager m_quarantine;

    std::vector<ScanResult> m_results;
    std::mutex m_results_mutex;

    bool m_auto_quarantine = false;
    bool m_db_loaded = false;
    bool m_quarantine_initialized = false;
    std::atomic<bool> m_cancel_requested{false};

    ScanProgressCallback m_progress_callback;

    // Whitelist
    std::unordered_set<std::string> m_whitelist;
    mutable std::mutex m_wl_mutex;
};

} // namespace av
