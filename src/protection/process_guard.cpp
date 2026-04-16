#include "protection/process_guard.h"
#include "database/hash_database.h"
#include "scanner/hash_calculator.h"
#include "utils/logger.h"

#include <thread>
#include <map>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

namespace av {

ProcessGuard::ProcessGuard() = default;

ProcessGuard::~ProcessGuard() {
    stop();
}

void ProcessGuard::start() {
    if (m_running) return;
    m_running = true;

    // Enable SeDebugPrivilege di thread ini juga
    // (privilege diwariskan ke thread baru, tapi pastikan sudah aktif)
    std::thread(&ProcessGuard::monitor_loop, this).detach();
    Logger::instance().info("ProcessGuard started");
}

void ProcessGuard::stop() {
    m_running = false;
    Logger::instance().info("ProcessGuard stopped");
}

// Resolve PID → full executable path
// Menggunakan multiple fallback methods untuk menangani proses elevated
std::string ProcessGuard::get_process_path(DWORD pid) {
    if (pid == 0) return "";

    // Method 1: QueryFullProcessImageNameA (paling ringan, lintas session)
    // Membutuhkan PROCESS_QUERY_LIMITED_INFORMATION
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        char path[MAX_PATH] = {};
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameA(hProc, 0, path, &sz)) {
            CloseHandle(hProc);
            return std::string(path);
        }
        CloseHandle(hProc);
    }

    // Method 2: GetModuleFileNameExA (fallback, butuh lebih banyak permission)
    hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProc) {
        char path[MAX_PATH] = {};
        if (GetModuleFileNameExA(hProc, NULL, path, MAX_PATH) > 0) {
            CloseHandle(hProc);
            return std::string(path);
        }
        CloseHandle(hProc);
    }

    // Method 3: GetProcessImageFileNameA (kernel path, perlu konversi)
    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        char path[MAX_PATH] = {};
        if (GetProcessImageFileNameA(hProc, path, MAX_PATH) > 0) {
            CloseHandle(hProc);
            // Path dalam format \Device\HarddiskVolume1\...
            // Konversi tidak sempurna tapi cukup untuk hashing
            std::string nt_path(path);
            // Coba konversi sederhana: \Device\HarddiskVolumeN\ → C:\ dst
            // Untuk hashing, kita bisa gunakan path apa adanya jika konversi gagal
            for (char drive = 'A'; drive <= 'Z'; ++drive) {
                char drive_str[3] = { drive, ':', '\0' };
                char device[MAX_PATH] = {};
                if (QueryDosDeviceA(drive_str, device, MAX_PATH) > 0) {
                    std::string dev(device);
                    if (nt_path.find(dev) == 0) {
                        return std::string(drive_str) + nt_path.substr(dev.length());
                    }
                }
            }
            // Jika konversi gagal, return nt_path (masih bisa di-hash)
            return nt_path;
        }
        CloseHandle(hProc);
    }

    return "";
}

void ProcessGuard::monitor_loop() {
    // Load database sekali
    HashDatabase db;
    if (!db.load(m_db_path) || db.size() == 0) {
        Logger::instance().error("ProcessGuard: cannot load database: " + m_db_path);
        m_running = false;
        return;
    }

    HashCalculator hasher;

    // Set untuk PID yang gagal di-resolve — akan dicoba lagi nanti
    // Tapi dibatasi retry agar tidak polling berlebihan
    std::map<DWORD, int> retry_count; // PID → jumlah retry
    const int MAX_RETRIES = 5;

    while (m_running) {
        Sleep(1500); // Cek setiap 1.5 detik
        if (!m_running) break;

        try {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE) continue;

            PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);

            if (Process32FirstW(snap, &pe)) {
                do {
                    DWORD pid = pe.th32ProcessID;

                    // Skip PID yang sudah BERHASIL dicek dan aman
                    {
                        std::lock_guard<std::mutex> lk(m_pid_mtx);
                        if (m_known_pids.count(pid)) continue;
                    }

                    // Skip system processes
                    if (pid <= 4) {
                        std::lock_guard<std::mutex> lk(m_pid_mtx);
                        m_known_pids.insert(pid);
                        continue;
                    }

                    // Dapatkan path exe
                    std::string exe_path = get_process_path(pid);
                    if (exe_path.empty()) {
                        // PENTING: JANGAN masukkan ke known_pids!
                        // Proses elevated yang gagal di-resolve harus dicoba lagi.
                        // Tapi batasi retry agar tidak polling berlebihan.
                        retry_count[pid]++;
                        if (retry_count[pid] >= MAX_RETRIES) {
                            // Sudah dicoba 5x, skip tapi log warning
                            Logger::instance().warning("ProcessGuard: cannot resolve PID " +
                                std::to_string(pid) + " after " + std::to_string(MAX_RETRIES) +
                                " retries (elevated process without SeDebugPrivilege?)");
                            std::lock_guard<std::mutex> lk(m_pid_mtx);
                            m_known_pids.insert(pid);
                        }
                        continue;
                    }

                    // Berhasil resolve — hapus dari retry counter
                    retry_count.erase(pid);

                    // Hash file exe
                    std::string hash = hasher.sha256_file(exe_path);
                    if (hash.empty()) {
                        // Bisa di-resolve tapi gagal hash — mungkin file locked
                        // Jangan masukkan ke known, coba lagi nanti
                        continue;
                    }

                    // Cek terhadap database
                    if (db.contains(hash)) {
                        auto threat = db.get_threat_info(hash);

                        ProcessThreatEvent evt;
                        evt.pid = pid;
                        evt.exe_path = exe_path;
                        evt.threat_name = threat.name + " [" + threat.category + "]";

                        Logger::instance().critical("PROCESS GUARD: " + threat.name +
                            " detected! PID=" + std::to_string(pid) +
                            " Path=" + exe_path);

                        // Ambil tindakan
                        if (m_action == Action::SUSPEND) {
                            // Suspend via NtSuspendProcess
                            typedef LONG(NTAPI* NtSuspendProcessFn)(HANDLE);
                            HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                            if (ntdll) {
                                auto pSuspend = reinterpret_cast<NtSuspendProcessFn>(
                                    GetProcAddress(ntdll, "NtSuspendProcess"));
                                if (pSuspend) {
                                    HANDLE hP = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
                                    if (hP) {
                                        pSuspend(hP);
                                        CloseHandle(hP);
                                        evt.action_taken = "Suspended";
                                        Logger::instance().critical("SUSPENDED PID " + std::to_string(pid));
                                    } else {
                                        evt.action_taken = "Failed (access denied)";
                                    }
                                }
                            }
                        } else {
                            // Terminate
                            HANDLE hP = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                            if (hP) {
                                TerminateProcess(hP, 1);
                                CloseHandle(hP);
                                evt.action_taken = "Terminated";
                                Logger::instance().critical("TERMINATED PID " + std::to_string(pid));
                            } else {
                                evt.action_taken = "Failed (access denied)";
                            }
                        }

                        // Simpan dan notifikasi
                        {
                            std::lock_guard<std::mutex> lk(m_blocked_mtx);
                            m_blocked.push_back(evt);
                        }

                        if (m_callback) m_callback(evt);
                    }

                    // Proses berhasil dicek dan aman (atau sudah ditangani)
                    // SEKARANG baru masukkan ke known_pids
                    {
                        std::lock_guard<std::mutex> lk(m_pid_mtx);
                        m_known_pids.insert(pid);
                    }

                } while (Process32NextW(snap, &pe));
            }

            CloseHandle(snap);

            // Cleanup old PIDs (setiap 30 iterasi)
            // Hapus PID yang sudah tidak ada
            static int cleanup_counter = 0;
            if (++cleanup_counter >= 30) {
                cleanup_counter = 0;
                std::lock_guard<std::mutex> lk(m_pid_mtx);
                std::set<DWORD> alive;
                HANDLE s2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (s2 != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32W p2 = {}; p2.dwSize = sizeof(p2);
                    if (Process32FirstW(s2, &p2)) {
                        do { alive.insert(p2.th32ProcessID); } while (Process32NextW(s2, &p2));
                    }
                    CloseHandle(s2);
                    m_known_pids = alive;
                }
                // Cleanup retry map — hapus PID yang sudah mati
                for (auto it = retry_count.begin(); it != retry_count.end(); ) {
                    if (!alive.count(it->first)) it = retry_count.erase(it);
                    else ++it;
                }
            }

        } catch (...) {
            Logger::instance().error("ProcessGuard: exception in monitor loop");
        }
    }
}

std::vector<ProcessThreatEvent> ProcessGuard::get_blocked() const {
    std::lock_guard<std::mutex> lk(m_blocked_mtx);
    return m_blocked;
}

bool ProcessGuard::resume_process(DWORD pid) {
    typedef LONG(NTAPI* NtResumeProcessFn)(HANDLE);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    auto pResume = reinterpret_cast<NtResumeProcessFn>(
        GetProcAddress(ntdll, "NtResumeProcess"));
    if (!pResume) return false;
    HANDLE hP = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hP) return false;
    pResume(hP);
    CloseHandle(hP);
    return true;
}

bool ProcessGuard::kill_process(DWORD pid) {
    HANDLE hP = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hP) return false;
    TerminateProcess(hP, 1);
    CloseHandle(hP);
    return true;
}

} // namespace av
