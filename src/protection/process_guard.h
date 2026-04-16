#pragma once

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <mutex>
#include <set>
#include <windows.h>

namespace av {

// Event saat malware terdeteksi dijalankan
struct ProcessThreatEvent {
    DWORD pid;
    std::string exe_path;
    std::string threat_name;
    std::string action_taken;  // "Suspended", "Terminated", "Allowed"
};

using ProcessThreatCallback = std::function<void(const ProcessThreatEvent&)>;

// ===== Real-Time Process Guard =====
// Monitor proses baru. Saat user menjalankan file yang hashnya
// ada di database ancaman, proses langsung di-suspend/terminate.
class ProcessGuard {
public:
    ProcessGuard();
    ~ProcessGuard();

    // Set database path untuk lookup hash
    void set_database_path(const std::string& db_path) { m_db_path = db_path; }

    // Set callback untuk notifikasi
    void set_callback(ProcessThreatCallback cb) { m_callback = cb; }

    // Mode: suspend (bisa di-review) atau terminate (langsung kill)
    enum class Action { SUSPEND, TERMINATE };
    void set_action(Action a) { m_action = a; }

    // Start/Stop monitoring
    void start();
    void stop();
    bool is_running() const { return m_running; }

    // Get daftar proses yang diblokir
    std::vector<ProcessThreatEvent> get_blocked() const;

    // Izinkan proses yang di-suspend untuk lanjut
    static bool resume_process(DWORD pid);

    // Terminate proses
    static bool kill_process(DWORD pid);

private:
    std::atomic<bool> m_running{false};
    std::string m_db_path;
    ProcessThreatCallback m_callback;
    Action m_action = Action::SUSPEND;

    std::set<DWORD> m_known_pids;
    std::mutex m_pid_mtx;

    mutable std::mutex m_blocked_mtx;
    std::vector<ProcessThreatEvent> m_blocked;

    void monitor_loop();
    std::string get_process_path(DWORD pid);
};

} // namespace av
