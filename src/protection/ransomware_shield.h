#pragma once

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <mutex>
#include <set>
#include <map>
#include <chrono>
#include <windows.h>

// Forward declaration
namespace av { class QuarantineManager; }

namespace av {

// ===== Threat Event =====
struct RansomwareEvent {
    enum class Type {
        CANARY_TRIGGERED,
        MASS_RENAME_DETECTED,
        HIGH_ENTROPY_WRITE,
        IO_SPIKE_DETECTED,
        VSS_DELETE_ATTEMPT,
        REGISTRY_PERSISTENCE,
        SUSPICIOUS_PROCESS,
        ENTROPY_SPIKE          // BARU: file berubah dari entropi rendah ke tinggi
    };

    Type type;
    DWORD process_id;
    std::string process_name;
    std::string process_path;
    std::string detail;
    std::chrono::system_clock::time_point timestamp;
};

using RansomwareCallback = std::function<void(const RansomwareEvent&)>;

// ===== Canary File System (Enhanced) =====
// v2: Penamaan strategis (! prefix → sort pertama secara alfabetis)
//     Deploy ke folder user (Desktop, Documents, Downloads)
//     Atribut Hidden + System
class CanaryMonitor {
public:
    bool deploy_canaries(const std::string& directory, int count = 5);

    // BARU: Deploy canary ke folder user (Desktop, Documents, Downloads)
    // dengan nama yang sort pertama secara alfabetis
    bool deploy_user_canaries();

    bool check_canaries() const;

    const std::vector<std::string>& get_canary_paths() const { return m_canary_paths; }

    // Dapatkan SEMUA direktori yang dimonitor
    const std::vector<std::string>& get_monitored_dirs() const { return m_monitored_dirs; }

    std::string get_last_triggered_path() const { return m_last_triggered_path; }

    void remove_canaries();

private:
    mutable std::string m_last_triggered_path;

    const std::string& get_directory() const { return m_directory; }

private:
    struct CanaryFile {
        std::string path;
        std::string original_hash;
        FILETIME original_write_time;
        DWORD original_size;
    };

    std::string m_directory;
    std::vector<std::string> m_canary_paths;
    std::vector<std::string> m_monitored_dirs;
    std::vector<CanaryFile> m_canaries;

    // Nama strategis: '!' sort sebelum semua huruf/angka di filesystem
    // Ransomware yang enkripsi secara alfabetis akan menyentuh file ini PERTAMA
    std::string generate_canary_name(int index) const;
    std::string generate_strategic_name(int index) const;
    std::string generate_canary_content() const;

    static std::string get_user_desktop();
    static std::string get_user_documents();
    static std::string get_user_downloads();
};

// ===== Entropy Analyzer =====
class EntropyAnalyzer {
public:
    static double calculate(const uint8_t* data, size_t length);
    static double calculate_file(const std::string& file_path);
    static bool is_encrypted(double entropy) { return entropy > 7.5; }
    static std::string classify(double entropy);
};

// ===== Extension Monitor =====
class ExtensionMonitor {
public:
    void set_threshold(int renames_per_second = 10) { m_threshold = renames_per_second; }
    void report_rename(const std::string& old_name, const std::string& new_name, DWORD pid);
    bool is_anomaly_detected() const;
    DWORD get_suspect_pid() const { return m_suspect_pid; }
    void reset();

private:
    int m_threshold = 10;
    DWORD m_suspect_pid = 0;
    struct RenameEvent {
        std::string old_ext;
        std::string new_ext;
        DWORD pid;
        std::chrono::steady_clock::time_point time;
    };
    mutable std::mutex m_mtx;
    std::vector<RenameEvent> m_events;
    std::set<std::string> m_known_ransomware_exts;
    void init_known_exts();
};

// ===== I/O Activity Monitor =====
class IOActivityMonitor {
public:
    void set_write_threshold(int ops_per_sec = 50) { m_write_threshold = ops_per_sec; }
    void report_write(DWORD pid, const std::string& file_path);
    bool has_spike() const;
    DWORD get_spike_pid() const;
    int get_write_count(DWORD pid) const;
    void cleanup();

private:
    int m_write_threshold = 50;
    struct WriteEvent {
        DWORD pid;
        std::chrono::steady_clock::time_point time;
    };
    mutable std::mutex m_mtx;
    std::vector<WriteEvent> m_events;
};

// ===== VSS Protection (Enhanced) =====
// v2: Auto-kill proses yang mencoba menghapus shadow copies
//     Command line analysis (bukan hanya nama proses)
//     Blokir vssadmin, wmic shadowcopy, bcdedit, wbadmin
class VSSProtector {
public:
    static bool detect_vss_deletion_attempt();
    static std::vector<DWORD> scan_processes_for_vss_commands();

    // BARU: Auto-kill semua proses yang melakukan VSS abuse
    // Return: jumlah proses yang di-kill
    static int kill_vss_abusers();

    // BARU: Analisis command line untuk mendeteksi VSS abuse
    static bool is_vss_abuse_cmdline(const std::wstring& cmdline);

    // BARU: Scan + kill + quarantine (integrated response)
    struct VSSViolation {
        DWORD pid;
        std::string exe_path;
        std::string command_hint;
    };
    static std::vector<VSSViolation> detect_and_respond();
};

// ===== Registry Monitor =====
class RegistryMonitor {
public:
    bool take_snapshot();
    std::vector<std::pair<std::string, std::string>> detect_new_entries();

    struct RollbackResult {
        std::string registry_path;
        std::string name;
        std::string value;
        bool success;
    };
    std::vector<RollbackResult> rollback_new_entries();
    void refresh_snapshot();

private:
    struct RegEntry {
        std::string name;
        std::string value;
    };

    std::vector<RegEntry> m_snapshot_run;
    std::vector<RegEntry> m_snapshot_runonce;
    std::vector<RegEntry> m_snapshot_hkcu_run;
    std::vector<RegEntry> m_snapshot_hkcu_runonce;
    std::vector<RegEntry> m_snapshot_hklm_run;
    std::vector<RegEntry> m_snapshot_hklm_runonce;

    mutable std::mutex m_mtx;

    static std::vector<RegEntry> read_run_key(HKEY root, const char* subkey);
    static bool delete_reg_value(HKEY root, const char* subkey, const std::string& name);
};

// ===== Self-Defense =====
// Proteksi proses AV dari terminasi oleh malware.
// - Mengubah DACL proses: deny PROCESS_TERMINATE untuk semua kecuali SYSTEM
// - Watchdog: proses kedua yang saling memantau
class SelfDefense {
public:
    // Set DACL restrictif pada proses saat ini.
    // Mencegah TerminateProcess dari proses non-SYSTEM.
    // Catatan: bisa di-bypass oleh proses dengan SeDebugPrivilege,
    // tapi cukup efektif melawan malware biasa.
    static bool protect_current_process();

    // Start watchdog process yang akan me-restart AV jika dimatikan
    static HANDLE start_watchdog(const std::string& watchdog_path);

    // Cek apakah watchdog masih hidup, restart jika mati
    static bool check_watchdog(HANDLE hWatchdog, const std::string& watchdog_path);
};

// ===== Main Ransomware Shield (v3) =====
// ARSITEKTUR DETEKSI:
//   Layer 1: ReadDirectoryChangesW     → real-time (instan) + entropy check
//   Layer 2: Polling loop 500ms        → backup + VSS + registry + IO spike
//   Layer 3: User folder canaries      → early warning di Desktop/Documents/Downloads
//
// ARSITEKTUR RESPONS:
//   Step 0: Identifikasi PID (process baseline + IO analysis)
//   Step 1: TerminateProcess (kill langsung)
//   Step 2: Quarantine executable
//   Step 3: Rollback perubahan registry
//   Step 4: Redeploy canary files
//
// PROTEKSI BARU:
//   - Entropy spike detection (file berubah dari low ke high entropy)
//   - VSS auto-kill (blokir vssadmin/wmic/bcdedit)
//   - User folder canaries (strategis, alphabetical-first naming)
//   - Self-defense (DACL + watchdog)
class RansomwareShield {
public:
    RansomwareShield();
    ~RansomwareShield();

    bool init(const std::string& protected_dir);
    void set_quarantine(QuarantineManager* qm) { m_quarantine = qm; }
    void start();
    void stop();
    bool is_running() const { return m_running; }
    void set_callback(RansomwareCallback cb) { m_callback = cb; }
    RansomwareEvent check_now();

    // Respons Ancaman
    static bool kill_process(DWORD pid);
    static bool suspend_process(DWORD pid);
    bool quarantine_threat(DWORD pid, const std::string& reason);
    std::vector<RansomwareEvent> get_recent_events() const;

    // BARU: Deploy canary ke folder user
    void deploy_user_folder_canaries();

private:
    std::atomic<bool> m_running{false};
    std::string m_protected_dir;
    RansomwareCallback m_callback;
    QuarantineManager* m_quarantine = nullptr;

    CanaryMonitor m_canary;
    CanaryMonitor m_user_canary;  // BARU: canary di folder user
    EntropyAnalyzer m_entropy;
    ExtensionMonitor m_ext_monitor;
    IOActivityMonitor m_io_monitor;
    VSSProtector m_vss;
    RegistryMonitor m_reg_monitor;

    mutable std::mutex m_event_mtx;
    std::vector<RansomwareEvent> m_events;

    // Layer 1: Real-time directory monitoring
    HANDLE m_hWatchDir = INVALID_HANDLE_VALUE;
    HANDLE m_hStopEvent = NULL;
    void directory_watch_loop();

    // BARU: Entropy tracking saat file berubah
    // Jika file berubah dari entropi rendah (<5) ke tinggi (>7.5) → ransomware
    void check_entropy_on_change(const BYTE* buffer, DWORD bytes);

    // Process baseline
    struct ProcessIOBaseline {
        std::string exe_path;
        ULONGLONG write_bytes;
    };
    std::set<DWORD> m_baseline_pids;
    std::map<DWORD, ProcessIOBaseline> m_io_baselines;
    std::mutex m_baseline_mtx;
    void take_process_baseline();

    // Suspect finder
    struct SuspectProcess {
        DWORD pid;
        std::string exe_path;
        ULONGLONG write_bytes;
        bool is_new;
    };
    std::vector<SuspectProcess> find_suspect_processes();

    // Debounce & dedup
    std::atomic<uint64_t> m_last_response_ms{0};
    std::set<DWORD> m_responded_pids;
    std::mutex m_responded_mtx;
    static const uint64_t RESPONSE_COOLDOWN_MS = 5000;

    // Core
    void monitor_loop();
    void fire_event(RansomwareEvent event);
    static std::string get_process_path(DWORD pid);
    void respond_to_threat(RansomwareEvent& event);
    void respond_unknown_pid(RansomwareEvent& event);
};

} // namespace av
