#include "protection/ransomware_shield.h"
#include "scanner/hash_calculator.h"
#include "quarantine/quarantine.h"
#include "utils/logger.h"

#include <fstream>
#include <cmath>
#include <thread>
#include <filesystem>
#include <algorithm>
#include <random>
#include <sstream>
#include <deque>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>
#include <RestartManager.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Rstrtmgr.lib")

namespace fs = std::filesystem;

namespace av {

// ============================================================
// CanaryMonitor — File umpan/honeypot
// ============================================================

std::string CanaryMonitor::generate_canary_name(int index) const {
    // Nama file yang terlihat seperti dokumen penting
    const char* names[] = {
        "Important_Budget_2026.xlsx",
        "Company_Passwords_Backup.docx",
        "Financial_Report_Q4.pdf",
        "Employee_Database.csv",
        "Tax_Returns_2025.xlsx",
        "Confidential_Notes.docx",
        "Project_Proposal_Final.pptx",
        "Invoice_Archive.pdf"
    };
    int count = sizeof(names) / sizeof(names[0]);
    return names[index % count];
}

// BARU: Nama strategis dengan '!' prefix → sort pertama secara alfabetis
// Ransomware biasanya mengenkripsi file secara alfabetis per folder.
// File dengan '!' di depan akan dienkripsi PERTAMA → peringatan dini.
std::string CanaryMonitor::generate_strategic_name(int index) const {
    const char* names[] = {
        "!000_Important_Backup.docx",
        "!001_Financial_Data.xlsx",
        "!002_Company_Records.pdf",
        "!003_Employee_List.csv",
        "!004_Tax_Returns.xlsx",
        "#000_Confidential_Notes.docx",
        "#001_Project_Archive.pptx",
        "$000_Invoice_Backup.pdf"
    };
    int count = sizeof(names) / sizeof(names[0]);
    return names[index % count];
}

// Helper: Get user folder paths
std::string CanaryMonitor::get_user_desktop() {
    char path[MAX_PATH] = {};
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, path) == S_OK)
        return std::string(path);
    return "";
}
std::string CanaryMonitor::get_user_documents() {
    char path[MAX_PATH] = {};
    if (SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, path) == S_OK)
        return std::string(path);
    return "";
}
std::string CanaryMonitor::get_user_downloads() {
    char path[MAX_PATH] = {};
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path) == S_OK)
        return std::string(path) + "\\Downloads";
    return "";
}

std::string CanaryMonitor::generate_canary_content() const {
    // Konten acak yang terlihat seperti dokumen asli
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 255);

    // Header yang terlihat seperti file asli + data acak
    std::string content = "DO NOT DELETE - SYSTEM BACKUP FILE\n";
    content += "Generated: " + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "\n";

    // Tambah data random agar ukuran file realistis (4-16 KB)
    std::uniform_int_distribution<> size_dist(4096, 16384);
    int size = size_dist(gen);
    for (int i = 0; i < size; ++i) {
        content += static_cast<char>(dist(gen));
    }
    return content;
}

bool CanaryMonitor::deploy_canaries(const std::string& directory, int count) {
    std::error_code ec;
    if (!fs::exists(directory, ec)) {
        fs::create_directories(directory, ec);
        if (ec) return false;
    }

    m_directory = directory;
    m_monitored_dirs.push_back(directory);
    std::string canary_dir = directory;

    for (int i = 0; i < count; ++i) {
        std::string name = generate_canary_name(i);
        std::string path = canary_dir + "\\" + name;

        // Tulis konten canary
        std::string content = generate_canary_content();
        std::ofstream out(path, std::ios::binary);
        if (!out.is_open()) continue;
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        out.close();

        // Simpan metadata
        CanaryFile cf;
        cf.path = path;
        cf.original_size = static_cast<DWORD>(content.size());

        // Hitung hash asli
        HashCalculator hasher;
        cf.original_hash = hasher.sha256_file(path);

        // Catat waktu tulis asli
        HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            GetFileTime(hFile, NULL, NULL, &cf.original_write_time);
            CloseHandle(hFile);
        }

        // Set atribut tersembunyi agar user biasa tidak menghapusnya
        SetFileAttributesA(path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

        m_canaries.push_back(cf);
        m_canary_paths.push_back(path);

        Logger::instance().info("Canary deployed: " + path);
    }

    return !m_canaries.empty();
}

// BARU: Deploy canary ke folder user dengan nama strategis
bool CanaryMonitor::deploy_user_canaries() {
    std::string folders[] = { get_user_desktop(), get_user_documents(), get_user_downloads() };
    const char* folder_names[] = { "Desktop", "Documents", "Downloads" };
    int deployed = 0;

    for (int f = 0; f < 3; ++f) {
        if (folders[f].empty()) continue;

        std::error_code ec;
        if (!fs::exists(folders[f], ec)) continue;

        m_monitored_dirs.push_back(folders[f]);

        // Deploy 2 canary per folder user
        for (int i = 0; i < 2; ++i) {
            std::string name = generate_strategic_name(f * 2 + i);
            std::string path = folders[f] + "\\" + name;

            // Jangan overwrite jika sudah ada
            if (fs::exists(path, ec)) {
                // Sudah ada dari session sebelumnya — tetap monitor
                CanaryFile cf;
                cf.path = path;
                cf.original_size = static_cast<DWORD>(fs::file_size(path, ec));
                HashCalculator hasher;
                cf.original_hash = hasher.sha256_file(path);
                HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                           NULL, OPEN_EXISTING, 0, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    GetFileTime(hFile, NULL, NULL, &cf.original_write_time);
                    CloseHandle(hFile);
                }
                m_canaries.push_back(cf);
                m_canary_paths.push_back(path);
                deployed++;
                continue;
            }

            std::string content = generate_canary_content();
            std::ofstream out(path, std::ios::binary);
            if (!out.is_open()) continue;
            out.write(content.data(), static_cast<std::streamsize>(content.size()));
            out.close();

            CanaryFile cf;
            cf.path = path;
            cf.original_size = static_cast<DWORD>(content.size());
            HashCalculator hasher;
            cf.original_hash = hasher.sha256_file(path);
            HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                       NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                GetFileTime(hFile, NULL, NULL, &cf.original_write_time);
                CloseHandle(hFile);
            }

            // Hidden + System — tidak terlihat oleh user biasa
            SetFileAttributesA(path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

            m_canaries.push_back(cf);
            m_canary_paths.push_back(path);
            deployed++;

            Logger::instance().info("Strategic canary deployed: " + path + " (" + folder_names[f] + ")");
        }
    }

    Logger::instance().info("User folder canaries deployed: " + std::to_string(deployed) + " files");
    return deployed > 0;
}

bool CanaryMonitor::check_canaries() const {
    for (const auto& cf : m_canaries) {
        std::error_code ec;
        // Cek 1: File masih ada?
        if (!fs::exists(cf.path, ec)) {
            Logger::instance().critical("CANARY DELETED: " + cf.path);
            m_last_triggered_path = cf.path;
            return false; // RANSOMWARE TERDETEKSI
        }

        // Cek 2: Ukuran berubah?
        auto current_size = fs::file_size(cf.path, ec);
        if (ec || current_size != cf.original_size) {
            Logger::instance().critical("CANARY MODIFIED (size): " + cf.path);
            m_last_triggered_path = cf.path;
            return false;
        }

        // Cek 3: Hash berubah?
        HashCalculator hasher;
        std::string current_hash = hasher.sha256_file(cf.path);
        if (current_hash != cf.original_hash) {
            Logger::instance().critical("CANARY MODIFIED (hash): " + cf.path);
            m_last_triggered_path = cf.path;
            return false;
        }
    }
    return true; // Semua canary aman
}

void CanaryMonitor::remove_canaries() {
    for (const auto& path : m_canary_paths) {
        SetFileAttributesA(path.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileA(path.c_str());
    }
    m_canaries.clear();
    m_canary_paths.clear();
}

// ============================================================
// EntropyAnalyzer — Deteksi data terenkripsi
// ============================================================

double EntropyAnalyzer::calculate(const uint8_t* data, size_t length) {
    if (length == 0) return 0.0;

    // Hitung frekuensi setiap byte (0-255)
    size_t freq[256] = {};
    for (size_t i = 0; i < length; ++i) {
        freq[data[i]]++;
    }

    // Shannon entropy: H = -sum(p * log2(p))
    double entropy = 0.0;
    double len = static_cast<double>(length);
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / len;
        entropy -= p * std::log2(p);
    }

    return entropy; // Range: 0.0 (uniform) - 8.0 (max random)
}

double EntropyAnalyzer::calculate_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) return -1.0;

    // Baca max 1MB untuk perhitungan entropi
    constexpr size_t MAX_READ = 1024 * 1024;
    std::vector<uint8_t> buffer(MAX_READ);
    file.read(reinterpret_cast<char*>(buffer.data()), MAX_READ);
    size_t bytes_read = static_cast<size_t>(file.gcount());

    if (bytes_read == 0) return 0.0;

    return calculate(buffer.data(), bytes_read);
}

std::string EntropyAnalyzer::classify(double entropy) {
    if (entropy < 0) return "ERROR";
    if (entropy < 1.0) return "VERY_LOW (plaintext/empty)";
    if (entropy < 3.0) return "LOW (text/structured)";
    if (entropy < 5.0) return "MEDIUM (mixed data)";
    if (entropy < 7.0) return "HIGH (compressed/binary)";
    if (entropy < 7.5) return "VERY_HIGH (compressed)";
    return "ENCRYPTED (entropy > 7.5)";
}

// ============================================================
// ExtensionMonitor — Deteksi rename massal
// ============================================================

void ExtensionMonitor::init_known_exts() {
    if (!m_known_ransomware_exts.empty()) return;
    // Ekstensi yang sering digunakan ransomware
    m_known_ransomware_exts = {
        ".encrypted", ".locked", ".crypto", ".crypt",
        ".locky", ".cerber", ".zepto", ".odin",
        ".thor", ".aesir", ".zzzzz", ".micro",
        ".enc", ".crypted", ".crinf", ".r5a",
        ".XRNT", ".XTBL", ".crypt1", ".da_vinci_code",
        ".magic", ".SUPERCRYPT", ".CTBL", ".CTB2",
        ".wflx", ".hermes", ".WNCRY", ".wcry",
        ".arena", ".cobra", ".java", ".arrow",
        ".bip", ".cmb", ".combo", ".ETH",
        ".gamma", ".heets", ".money", ".phobos"
    };
}

void ExtensionMonitor::report_rename(const std::string& old_name,
                                      const std::string& new_name, DWORD pid) {
    init_known_exts();

    std::lock_guard<std::mutex> lk(m_mtx);

    std::string old_ext = fs::path(old_name).extension().string();
    std::string new_ext = fs::path(new_name).extension().string();

    // Hanya catat jika ekstensi berubah
    if (old_ext == new_ext) return;

    RenameEvent evt;
    evt.old_ext = old_ext;
    evt.new_ext = new_ext;
    evt.pid = pid;
    evt.time = std::chrono::steady_clock::now();

    m_events.push_back(evt);

    // Bonus: cek apakah ekstensi baru = ekstensi ransomware yang diketahui
    std::string lower_ext = new_ext;
    std::transform(lower_ext.begin(), lower_ext.end(), lower_ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (m_known_ransomware_exts.count(lower_ext)) {
        m_suspect_pid = pid;
        Logger::instance().critical("RANSOMWARE EXT DETECTED: " + new_ext + " by PID " + std::to_string(pid));
    }
}

bool ExtensionMonitor::is_anomaly_detected() const {
    std::lock_guard<std::mutex> lk(m_mtx);

    if (m_events.empty()) return false;

    auto now = std::chrono::steady_clock::now();

    // Hitung rename dalam 1 detik terakhir per PID
    std::map<DWORD, int> pid_counts;
    for (const auto& evt : m_events) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - evt.time);
        if (age.count() <= 1) {
            pid_counts[evt.pid]++;
        }
    }

    // Cek per-PID threshold
    for (const auto& [pid, count] : pid_counts) {
        if (count >= m_threshold) {
            return true;
        }
    }

    return false;
}

void ExtensionMonitor::reset() {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_events.clear();
    m_suspect_pid = 0;
}

// ============================================================
// IOActivityMonitor — Deteksi I/O spike
// ============================================================

void IOActivityMonitor::report_write(DWORD pid, const std::string& file_path) {
    UNREFERENCED_PARAMETER(file_path);
    std::lock_guard<std::mutex> lk(m_mtx);

    WriteEvent evt;
    evt.pid = pid;
    evt.time = std::chrono::steady_clock::now();
    m_events.push_back(evt);
}

bool IOActivityMonitor::has_spike() const {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto now = std::chrono::steady_clock::now();

    std::map<DWORD, int> pid_counts;
    for (const auto& evt : m_events) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - evt.time);
        if (age.count() <= 1) {
            pid_counts[evt.pid]++;
        }
    }

    for (const auto& [pid, count] : pid_counts) {
        if (count >= m_write_threshold) return true;
    }
    return false;
}

DWORD IOActivityMonitor::get_spike_pid() const {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto now = std::chrono::steady_clock::now();

    std::map<DWORD, int> pid_counts;
    for (const auto& evt : m_events) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - evt.time);
        if (age.count() <= 1) {
            pid_counts[evt.pid]++;
        }
    }

    DWORD max_pid = 0;
    int max_count = 0;
    for (const auto& [pid, count] : pid_counts) {
        if (count > max_count) { max_count = count; max_pid = pid; }
    }
    return max_pid;
}

int IOActivityMonitor::get_write_count(DWORD pid) const {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto now = std::chrono::steady_clock::now();
    int count = 0;
    for (const auto& evt : m_events) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - evt.time);
        if (age.count() <= 2 && evt.pid == pid) count++;
    }
    return count;
}

void IOActivityMonitor::cleanup() {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto now = std::chrono::steady_clock::now();
    m_events.erase(
        std::remove_if(m_events.begin(), m_events.end(),
            [&now](const WriteEvent& e) {
                return std::chrono::duration_cast<std::chrono::seconds>(now - e.time).count() > 10;
            }),
        m_events.end()
    );
}

// ============================================================
// VSSProtector — Proteksi Volume Shadow Copy
// ============================================================

bool VSSProtector::detect_vss_deletion_attempt() {
    auto suspects = scan_processes_for_vss_commands();
    return !suspects.empty();
}

// Analisis command line untuk mendeteksi VSS abuse
// Pattern: vssadmin delete shadows, wmic shadowcopy delete,
//          bcdedit /set recoveryenabled No, wbadmin delete catalog
bool VSSProtector::is_vss_abuse_cmdline(const std::wstring& cmdline) {
    std::wstring lower = cmdline;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    // vssadmin delete shadows
    if (lower.find(L"vssadmin") != std::wstring::npos &&
        lower.find(L"delete") != std::wstring::npos &&
        lower.find(L"shadow") != std::wstring::npos) return true;

    // wmic shadowcopy delete
    if (lower.find(L"wmic") != std::wstring::npos &&
        lower.find(L"shadowcopy") != std::wstring::npos &&
        lower.find(L"delete") != std::wstring::npos) return true;

    // bcdedit /set recoveryenabled no
    if (lower.find(L"bcdedit") != std::wstring::npos &&
        lower.find(L"recoveryenabled") != std::wstring::npos &&
        lower.find(L"no") != std::wstring::npos) return true;

    // wbadmin delete catalog
    if (lower.find(L"wbadmin") != std::wstring::npos &&
        lower.find(L"delete") != std::wstring::npos &&
        lower.find(L"catalog") != std::wstring::npos) return true;

    return false;
}

std::vector<DWORD> VSSProtector::scan_processes_for_vss_commands() {
    std::vector<DWORD> suspect_pids;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return suspect_pids;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring name(pe.szExeFile);
            std::wstring lower_name = name;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);

            // Proses yang bisa menjalankan VSS commands
            bool is_suspect_exe = (lower_name == L"cmd.exe" ||
                                   lower_name == L"powershell.exe" ||
                                   lower_name == L"wmic.exe" ||
                                   lower_name == L"vssadmin.exe" ||
                                   lower_name == L"bcdedit.exe" ||
                                   lower_name == L"wbadmin.exe");

            if (!is_suspect_exe) continue;

            // vssadmin.exe dan wbadmin.exe yang berjalan = langsung curigai
            if (lower_name == L"vssadmin.exe" || lower_name == L"wbadmin.exe" ||
                lower_name == L"bcdedit.exe") {
                // Cek parent process: jika parent bukan explorer.exe/services.exe
                // kemungkinan besar dijalankan oleh malware
                suspect_pids.push_back(pe.th32ProcessID);
                continue;
            }

            // Untuk cmd/powershell/wmic: cek command line
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                CloseHandle(hProc);
                // Nama proses shell + parent bukan explorer = curigai
                suspect_pids.push_back(pe.th32ProcessID);
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return suspect_pids;
}

// BARU: Auto-kill semua proses yang melakukan VSS abuse
int VSSProtector::kill_vss_abusers() {
    auto suspects = scan_processes_for_vss_commands();
    int killed = 0;

    for (DWORD pid : suspects) {
        if (pid <= 4) continue;

        HANDLE hP = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hP) {
            TerminateProcess(hP, 1);
            CloseHandle(hP);
            killed++;
            Logger::instance().critical("VSS PROTECTOR: Killed PID " + std::to_string(pid) +
                                        " (VSS abuse attempt)");
        }
    }

    return killed;
}

// BARU: Detect + respond (kill + log details)
std::vector<VSSProtector::VSSViolation> VSSProtector::detect_and_respond() {
    std::vector<VSSViolation> violations;
    auto suspects = scan_processes_for_vss_commands();

    for (DWORD pid : suspects) {
        if (pid <= 4) continue;

        VSSViolation v;
        v.pid = pid;

        // Get exe path
        HANDLE hP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pid);
        if (hP) {
            char path[MAX_PATH] = {};
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameA(hP, 0, path, &sz)) {
                v.exe_path = path;
            }
            v.command_hint = "VSS/shadow copy deletion";

            // KILL!
            TerminateProcess(hP, 1);
            CloseHandle(hP);

            Logger::instance().critical("VSS PROTECTOR: Killed " + v.exe_path +
                                        " (PID " + std::to_string(pid) + ")");
        }

        violations.push_back(v);
    }

    return violations;
}

// ============================================================
// SelfDefense — Proteksi proses AV dari terminasi
// ============================================================

bool SelfDefense::protect_current_process() {
    // Deny PROCESS_TERMINATE untuk Everyone
    // Ini membuat taskkill/TerminateProcess gagal dari proses lain
    // kecuali yang punya SeDebugPrivilege

    HANDLE hProcess = GetCurrentProcess();
    DWORD pid = GetCurrentProcessId();

    // Buat DACL:
    // ALLOW PROCESS_ALL_ACCESS untuk SYSTEM
    // DENY PROCESS_TERMINATE untuk Everyone
    // ALLOW PROCESS_ALL_ACCESS untuk proses kita sendiri

    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:"
            "(D;;0x0001;;;WD)"     // DENY PROCESS_TERMINATE untuk Everyone (World)
            "(A;;0x1FFFFF;;;SY)"   // ALLOW ALL untuk SYSTEM
            "(A;;0x1FFFFF;;;BA)",  // ALLOW ALL untuk Built-in Administrators
            SDDL_REVISION_1, &pSD, NULL)) {
        Logger::instance().warning("SelfDefense: Failed to create security descriptor");
        return false;
    }

    PACL pDacl = NULL;
    BOOL bDaclPresent = FALSE, bDaclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted) || !bDaclPresent) {
        LocalFree(pSD);
        return false;
    }

    // Apply ke proses saat ini
    DWORD result = SetSecurityInfo(
        hProcess,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, pDacl, NULL
    );

    LocalFree(pSD);

    if (result == ERROR_SUCCESS) {
        Logger::instance().info("SelfDefense: Process protected (PID " + std::to_string(pid) + ")");
        return true;
    }

    Logger::instance().warning("SelfDefense: SetSecurityInfo failed: " + std::to_string(result));
    return false;
}

HANDLE SelfDefense::start_watchdog(const std::string& watchdog_path) {
    if (watchdog_path.empty()) return NULL;

    std::error_code ec;
    if (!fs::exists(watchdog_path, ec)) {
        Logger::instance().warning("Watchdog not found: " + watchdog_path);
        return NULL;
    }

    // Jalankan watchdog dengan PID kita sebagai argumen
    DWORD myPid = GetCurrentProcessId();
    std::string cmdline = "\"" + watchdog_path + "\" --watch " + std::to_string(myPid);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    if (CreateProcessA(NULL, const_cast<char*>(cmdline.c_str()),
                       NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        Logger::instance().info("Watchdog started (PID " + std::to_string(pi.dwProcessId) + ")");
        return pi.hProcess;
    }

    Logger::instance().warning("Failed to start watchdog");
    return NULL;
}

bool SelfDefense::check_watchdog(HANDLE hWatchdog, const std::string& watchdog_path) {
    if (!hWatchdog) return false;

    DWORD exitCode = 0;
    if (GetExitCodeProcess(hWatchdog, &exitCode) && exitCode == STILL_ACTIVE) {
        return true; // Masih hidup
    }

    // Watchdog mati — restart!
    Logger::instance().warning("Watchdog died, restarting...");
    CloseHandle(hWatchdog);
    HANDLE hNew = start_watchdog(watchdog_path);
    return (hNew != NULL);
}

// ============================================================
// RegistryMonitor — Deteksi persistence + Rollback otomatis
// ============================================================

std::vector<RegistryMonitor::RegEntry> RegistryMonitor::read_run_key(HKEY root, const char* subkey) {
    std::vector<RegEntry> entries;

    HKEY hKey;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return entries;

    char name[256];
    BYTE data[1024];

    for (DWORD i = 0; ; ++i) {
        DWORD nameLen = sizeof(name);
        DWORD dataLen = sizeof(data);
        DWORD type = 0;

        LONG result = RegEnumValueA(hKey, i, name, &nameLen, NULL, &type, data, &dataLen);
        if (result != ERROR_SUCCESS) break;

        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            RegEntry e;
            e.name = std::string(name, nameLen);
            e.value = std::string(reinterpret_cast<char*>(data), dataLen > 0 ? dataLen - 1 : 0);
            entries.push_back(e);
        }
    }

    RegCloseKey(hKey);
    return entries;
}

bool RegistryMonitor::delete_reg_value(HKEY root, const char* subkey, const std::string& name) {
    HKEY hKey;
    if (RegOpenKeyExA(root, subkey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        Logger::instance().warning("Registry rollback: cannot open key for write: " + std::string(subkey));
        return false;
    }

    LONG result = RegDeleteValueA(hKey, name.c_str());
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS) {
        Logger::instance().info("Registry rollback: deleted value '" + name + "' from " + subkey);
        return true;
    } else {
        Logger::instance().warning("Registry rollback: failed to delete '" + name + "' from " + subkey +
                                   " (error " + std::to_string(result) + ")");
        return false;
    }
}

bool RegistryMonitor::take_snapshot() {
    std::lock_guard<std::mutex> lk(m_mtx);

    // Snapshot terpisah per hive untuk rollback yang presisi
    m_snapshot_hkcu_run = read_run_key(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    m_snapshot_hkcu_runonce = read_run_key(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    m_snapshot_hklm_run = read_run_key(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    m_snapshot_hklm_runonce = read_run_key(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");

    // Gabungkan untuk backward compatibility
    m_snapshot_run.clear();
    m_snapshot_run.insert(m_snapshot_run.end(), m_snapshot_hkcu_run.begin(), m_snapshot_hkcu_run.end());
    m_snapshot_run.insert(m_snapshot_run.end(), m_snapshot_hklm_run.begin(), m_snapshot_hklm_run.end());

    m_snapshot_runonce.clear();
    m_snapshot_runonce.insert(m_snapshot_runonce.end(), m_snapshot_hkcu_runonce.begin(), m_snapshot_hkcu_runonce.end());
    m_snapshot_runonce.insert(m_snapshot_runonce.end(), m_snapshot_hklm_runonce.begin(), m_snapshot_hklm_runonce.end());

    Logger::instance().info("Registry snapshot: " +
        std::to_string(m_snapshot_run.size()) + " Run, " +
        std::to_string(m_snapshot_runonce.size()) + " RunOnce entries");

    return true;
}

std::vector<std::pair<std::string, std::string>> RegistryMonitor::detect_new_entries() {
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<std::pair<std::string, std::string>> new_entries;

    auto current_run = read_run_key(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    auto current_runonce = read_run_key(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");

    auto lm_run = read_run_key(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    auto lm_runonce = read_run_key(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");

    current_run.insert(current_run.end(), lm_run.begin(), lm_run.end());
    current_runonce.insert(current_runonce.end(), lm_runonce.begin(), lm_runonce.end());

    // Bandingkan Run
    for (const auto& cur : current_run) {
        bool found = false;
        for (const auto& snap : m_snapshot_run) {
            if (snap.name == cur.name && snap.value == cur.value) { found = true; break; }
        }
        if (!found) {
            new_entries.push_back({cur.name, cur.value});
            Logger::instance().warning("NEW REGISTRY ENTRY Run: " + cur.name + " = " + cur.value);
        }
    }

    // Bandingkan RunOnce
    for (const auto& cur : current_runonce) {
        bool found = false;
        for (const auto& snap : m_snapshot_runonce) {
            if (snap.name == cur.name && snap.value == cur.value) { found = true; break; }
        }
        if (!found) {
            new_entries.push_back({cur.name, cur.value});
            Logger::instance().warning("NEW REGISTRY ENTRY RunOnce: " + cur.name + " = " + cur.value);
        }
    }

    return new_entries;
}

std::vector<RegistryMonitor::RollbackResult> RegistryMonitor::rollback_new_entries() {
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<RollbackResult> results;

    struct HiveCheck {
        HKEY root;
        const char* subkey;
        const char* display_path;
        const std::vector<RegEntry>* snapshot;
    };

    HiveCheck hives[] = {
        { HKEY_CURRENT_USER,
          "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          "HKCU\\...\\Run",
          &m_snapshot_hkcu_run },
        { HKEY_CURRENT_USER,
          "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
          "HKCU\\...\\RunOnce",
          &m_snapshot_hkcu_runonce },
        { HKEY_LOCAL_MACHINE,
          "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          "HKLM\\...\\Run",
          &m_snapshot_hklm_run },
        { HKEY_LOCAL_MACHINE,
          "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
          "HKLM\\...\\RunOnce",
          &m_snapshot_hklm_runonce },
    };

    for (const auto& hive : hives) {
        auto current = read_run_key(hive.root, hive.subkey);

        for (const auto& cur : current) {
            bool is_new = true;
            for (const auto& snap : *(hive.snapshot)) {
                if (snap.name == cur.name && snap.value == cur.value) {
                    is_new = false;
                    break;
                }
            }

            if (is_new) {
                Logger::instance().critical("REGISTRY ROLLBACK: removing '" + cur.name +
                    "' = '" + cur.value + "' from " + hive.display_path);

                RollbackResult rr;
                rr.registry_path = hive.display_path;
                rr.name = cur.name;
                rr.value = cur.value;
                rr.success = delete_reg_value(hive.root, hive.subkey, cur.name);

                results.push_back(rr);
            }
        }
    }

    return results;
}

void RegistryMonitor::refresh_snapshot() {
    take_snapshot();
}

// ============================================================
// RansomwareShield — Koordinator utama
// ============================================================

RansomwareShield::RansomwareShield() = default;

RansomwareShield::~RansomwareShield() {
    stop();
}

// ============================================================
// Process baseline — snapshot PID + IO counters saat init
// ============================================================
void RansomwareShield::take_process_baseline() {
    std::lock_guard<std::mutex> lk(m_baseline_mtx);
    m_baseline_pids.clear();
    m_io_baselines.clear();

    DWORD my_pid = GetCurrentProcessId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            m_baseline_pids.insert(pid);

            if (pid <= 4 || pid == my_pid) continue;

            // Simpan IO baseline untuk deteksi anomali di kemudian hari
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (hProc) {
                IO_COUNTERS io = {};
                if (GetProcessIoCounters(hProc, &io)) {
                    ProcessIOBaseline bl;
                    bl.exe_path = get_process_path(pid);
                    bl.write_bytes = io.WriteTransferCount;
                    m_io_baselines[pid] = bl;
                }
                CloseHandle(hProc);
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    Logger::instance().info("Process baseline: " + std::to_string(m_baseline_pids.size()) + " PIDs recorded");
}

// ============================================================
// find_suspect_processes — Identifikasi proses ransomware
// ============================================================
// Strategi:
//   1. Proses BARU (tidak di baseline) + BUKAN di folder sistem = suspect pasti
//   2. Proses LAMA (di baseline) tapi IO write naik >50MB sejak baseline = suspect
// Ini menangkap ransomware yang:
//   a. Baru dijalankan setelah shield aktif (case 1)
//   b. Sudah berjalan sebelum shield aktif (case 2)
std::vector<RansomwareShield::SuspectProcess> RansomwareShield::find_suspect_processes() {
    std::vector<SuspectProcess> suspects;
    std::lock_guard<std::mutex> lk(m_baseline_mtx);

    DWORD my_pid = GetCurrentProcessId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return suspects;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;

            // Skip system & self
            if (pid <= 4 || pid == my_pid) continue;

            // Skip PID yang sudah pernah kita respond
            {
                std::lock_guard<std::mutex> rl(m_responded_mtx);
                if (m_responded_pids.count(pid)) continue;
            }

            std::string path = get_process_path(pid);
            if (path.empty()) continue;

            // Skip proses di folder sistem Windows
            std::string lower_path = path;
            std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (lower_path.find("\\windows\\") != std::string::npos) continue;
            if (lower_path.find("\\program files\\") != std::string::npos) continue;
            if (lower_path.find("\\program files (x86)\\") != std::string::npos) continue;

            bool is_new = (m_baseline_pids.count(pid) == 0);

            // Ambil IO counters saat ini
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!hProc) continue;

            IO_COUNTERS io = {};
            bool got_io = (GetProcessIoCounters(hProc, &io) != 0);
            CloseHandle(hProc);

            if (!got_io) continue;

            if (is_new) {
                // Proses baru + bukan sistem → suspect
                // Threshold rendah: bahkan sedikit write sudah mencurigakan saat canary triggered
                if (io.WriteTransferCount > 0) {
                    SuspectProcess sp;
                    sp.pid = pid;
                    sp.exe_path = path;
                    sp.write_bytes = io.WriteTransferCount;
                    sp.is_new = true;
                    suspects.push_back(sp);

                    Logger::instance().warning("SUSPECT (new process): PID=" + std::to_string(pid) +
                        " Path=" + path +
                        " WriteBytes=" + std::to_string(io.WriteTransferCount));
                }
            } else {
                // Proses lama — cek IO delta dari baseline
                auto it = m_io_baselines.find(pid);
                if (it != m_io_baselines.end()) {
                    ULONGLONG delta = io.WriteTransferCount - it->second.write_bytes;
                    // >50MB write delta = sangat mencurigakan
                    if (delta > 50ULL * 1024 * 1024) {
                        SuspectProcess sp;
                        sp.pid = pid;
                        sp.exe_path = path;
                        sp.write_bytes = delta;
                        sp.is_new = false;
                        suspects.push_back(sp);

                        Logger::instance().warning("SUSPECT (IO anomaly): PID=" + std::to_string(pid) +
                            " Path=" + path +
                            " WriteDelta=" + std::to_string(delta / (1024 * 1024)) + "MB");
                    }
                }
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);

    // Sort: proses baru lebih prioritas, lalu by write bytes descending
    std::sort(suspects.begin(), suspects.end(),
        [](const SuspectProcess& a, const SuspectProcess& b) {
            if (a.is_new != b.is_new) return a.is_new; // new first
            return a.write_bytes > b.write_bytes;
        });

    return suspects;
}

// ============================================================
// Resolve PID → full executable path
// Multiple fallback methods untuk menangani proses elevated
// ============================================================
std::string RansomwareShield::get_process_path(DWORD pid) {
    if (pid == 0) return "";

    // Method 1: QueryFullProcessImageNameA
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

    // Method 2: GetModuleFileNameExA
    hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProc) {
        char path[MAX_PATH] = {};
        if (GetModuleFileNameExA(hProc, NULL, path, MAX_PATH) > 0) {
            CloseHandle(hProc);
            return std::string(path);
        }
        CloseHandle(hProc);
    }

    // Method 3: GetProcessImageFileNameA (NT path → DOS path)
    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        char path[MAX_PATH] = {};
        if (GetProcessImageFileNameA(hProc, path, MAX_PATH) > 0) {
            CloseHandle(hProc);
            std::string nt_path(path);
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
            return nt_path;
        }
        CloseHandle(hProc);
    }

    return "";
}

// ============================================================
// init — Inisialisasi shield
// ============================================================
bool RansomwareShield::init(const std::string& protected_dir) {
    m_protected_dir = protected_dir;

    // Deploy canary ke data/canary (primary)
    if (!m_canary.deploy_canaries(protected_dir, 5)) {
        Logger::instance().warning("Failed to deploy some canary files");
    }

    // BARU: Deploy canary ke folder user (Desktop/Documents/Downloads)
    // dengan nama strategis yang sort pertama secara alfabetis
    if (!m_user_canary.deploy_user_canaries()) {
        Logger::instance().warning("Failed to deploy user folder canaries");
    }

    // Ambil snapshot registry
    m_reg_monitor.take_snapshot();

    // Ambil process baseline (PID + IO counters)
    take_process_baseline();

    // Set threshold
    m_ext_monitor.set_threshold(10);
    m_io_monitor.set_write_threshold(50);

    Logger::instance().info("RansomwareShield v3 initialized for: " + protected_dir);
    Logger::instance().info("Monitored dirs: " + std::to_string(m_canary.get_monitored_dirs().size()) +
                           " primary + " + std::to_string(m_user_canary.get_monitored_dirs().size()) + " user folders");
    return true;
}

void RansomwareShield::deploy_user_folder_canaries() {
    m_user_canary.deploy_user_canaries();
}

// ============================================================
// start — Start semua thread monitoring
// ============================================================
void RansomwareShield::start() {
    if (m_running) return;
    m_running = true;

    // Thread 1: Polling loop (backup, 500ms interval)
    std::thread(&RansomwareShield::monitor_loop, this).detach();

    // Thread 2: Real-time directory watcher (ReadDirectoryChangesW)
    // Membuka handle ke directory canary dan mendeteksi perubahan INSTAN
    std::thread(&RansomwareShield::directory_watch_loop, this).detach();

    Logger::instance().info("RansomwareShield monitoring started (realtime + polling)");
}

// ============================================================
// stop — Stop semua thread
// ============================================================
void RansomwareShield::stop() {
    m_running = false;

    // Signal stop event untuk directory watcher
    if (m_hStopEvent) {
        SetEvent(m_hStopEvent);
    }

    // Tunggu sebentar agar thread sempat berhenti
    Sleep(200);

    // Cleanup handles
    if (m_hWatchDir != INVALID_HANDLE_VALUE) {
        CancelIoEx(m_hWatchDir, NULL);
        CloseHandle(m_hWatchDir);
        m_hWatchDir = INVALID_HANDLE_VALUE;
    }
    if (m_hStopEvent) {
        CloseHandle(m_hStopEvent);
        m_hStopEvent = NULL;
    }

    m_canary.remove_canaries();
    Logger::instance().info("RansomwareShield stopped");
}

// ============================================================
// directory_watch_loop — LAYER 1: Real-time monitoring
// ============================================================
// Menggunakan ReadDirectoryChangesW untuk mendeteksi perubahan
// file di directory canary secara INSTAN (bukan polling).
// Ini adalah pertahanan utama — jauh lebih cepat dari polling loop.
void RansomwareShield::directory_watch_loop() {
    Logger::instance().info("Directory watcher starting for: " + m_protected_dir);

    // Buka directory handle untuk monitoring
    m_hWatchDir = CreateFileA(
        m_protected_dir.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (m_hWatchDir == INVALID_HANDLE_VALUE) {
        Logger::instance().error("Directory watcher: cannot open directory: " + m_protected_dir);
        Logger::instance().warning("Falling back to polling-only mode");
        return;
    }

    // Event untuk menghentikan watcher
    m_hStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!m_hStopEvent) {
        CloseHandle(m_hWatchDir);
        m_hWatchDir = INVALID_HANDLE_VALUE;
        return;
    }

    BYTE buffer[4096];
    OVERLAPPED ol = {};
    ol.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

    if (!ol.hEvent) {
        CloseHandle(m_hWatchDir);
        m_hWatchDir = INVALID_HANDLE_VALUE;
        CloseHandle(m_hStopEvent);
        m_hStopEvent = NULL;
        return;
    }

    Logger::instance().info("Directory watcher ACTIVE (real-time monitoring)");

    while (m_running) {
        ResetEvent(ol.hEvent);

        BOOL ok = ReadDirectoryChangesW(
            m_hWatchDir,
            buffer,
            sizeof(buffer),
            TRUE,  // Watch subdirectories too
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_ATTRIBUTES,
            NULL,       // Bytes returned (ignored for overlapped)
            &ol,
            NULL        // Completion routine
        );

        if (!ok) {
            DWORD err = GetLastError();
            if (err != ERROR_OPERATION_ABORTED) {
                Logger::instance().error("ReadDirectoryChangesW failed: " + std::to_string(err));
            }
            break;
        }

        // Wait untuk perubahan file ATAU stop event
        HANDLE events[] = { ol.hEvent, m_hStopEvent };
        DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);

        if (wait == WAIT_OBJECT_0) {
            // === FILE CHANGE DETECTED! ===
            DWORD bytes = 0;
            GetOverlappedResult(m_hWatchDir, &ol, &bytes, FALSE);

            if (bytes > 0) {
                Logger::instance().warning("REALTIME: File change detected in canary directory!");

                // BARU: Cek entropi pada file yang berubah
                check_entropy_on_change(buffer, bytes);

                // Cek canary SEGERA
                if (!m_canary.check_canaries()) {
                    Logger::instance().critical("REALTIME: CANARY TRIGGERED! Initiating threat response...");

                    RansomwareEvent evt;
                    evt.type = RansomwareEvent::Type::CANARY_TRIGGERED;
                    evt.detail = "REALTIME: Canary file modified or deleted!";
                    evt.process_id = 0;
                    fire_event(evt);
                }
            }
        } else {
            // Stop event signaled atau error
            CancelIoEx(m_hWatchDir, &ol);
            break;
        }
    }

    CloseHandle(ol.hEvent);
    Logger::instance().info("Directory watcher stopped");
}

// ============================================================
// check_entropy_on_change — BARU: Deteksi entropy spike
// ============================================================
// Saat ReadDirectoryChangesW mendeteksi perubahan file,
// parse FILE_NOTIFY_INFORMATION dan hitung entropi file.
// Jika file berubah dari entropi rendah ke tinggi (>7.5) → ransomware!
void RansomwareShield::check_entropy_on_change(const BYTE* buffer, DWORD bytes) {
    if (!buffer || bytes == 0) return;

    const FILE_NOTIFY_INFORMATION* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buffer);
    int high_entropy_count = 0;

    while (true) {
        // Parse filename dari notification
        std::wstring wfilename(info->FileName, info->FileNameLength / sizeof(WCHAR));
        std::string filename;
        {
            int sz = WideCharToMultiByte(CP_UTF8, 0, wfilename.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (sz > 0) {
                filename.resize(sz - 1);
                WideCharToMultiByte(CP_UTF8, 0, wfilename.c_str(), -1, &filename[0], sz, nullptr, nullptr);
            }
        }

        if (!filename.empty()) {
            std::string filepath = m_protected_dir + "\\" + filename;

            // Hanya cek file yang MODIFIED (bukan deleted/renamed)
            if (info->Action == FILE_ACTION_MODIFIED ||
                info->Action == FILE_ACTION_ADDED) {

                double entropy = EntropyAnalyzer::calculate_file(filepath);

                if (entropy > 7.5) {
                    // ENTROPY TINGGI! File ini kemungkinan besar terenkripsi
                    high_entropy_count++;
                    Logger::instance().critical(
                        "ENTROPY SPIKE: " + filename +
                        " entropy=" + std::to_string(entropy) +
                        " (threshold=7.5)");
                }
            }
        }

        // Next entry dalam buffer
        if (info->NextEntryOffset == 0) break;
        info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(
            reinterpret_cast<const BYTE*>(info) + info->NextEntryOffset);
    }

    // Jika banyak file dengan entropi tinggi → pasti ransomware
    if (high_entropy_count >= 2) {
        Logger::instance().critical("Multiple high-entropy file changes detected (" +
                                   std::to_string(high_entropy_count) + ") — RANSOMWARE CONFIRMED!");
        RansomwareEvent evt;
        evt.type = RansomwareEvent::Type::ENTROPY_SPIKE;
        evt.detail = "Multiple files changed to high entropy (" +
                    std::to_string(high_entropy_count) + " files) — encryption in progress!";
        evt.process_id = 0;
        fire_event(evt);
    }
}

// ============================================================
// RM Helper — Restart Manager untuk mencari proses yang megang lock
// ============================================================
static std::vector<DWORD> get_processes_locking_file(const std::string& path) {
    std::vector<DWORD> pids;
    if (path.empty()) return pids;

    DWORD dwSession;
    WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };

    if (RmStartSession(&dwSession, 0, szSessionKey) != ERROR_SUCCESS) return pids;

    std::wstring wpath;
    int sz = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (sz > 0) {
        wpath.resize(sz - 1);
        MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], sz);
    }

    LPCWSTR rgszFileNames[] = { wpath.c_str() };
    if (RmRegisterResources(dwSession, 1, rgszFileNames, 0, NULL, 0, NULL) == ERROR_SUCCESS) {
        DWORD dwReason;
        UINT nProcInfoNeeded = 0;
        UINT nProcInfo = 0;

        DWORD res = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, NULL, &dwReason);
        if (res == ERROR_MORE_DATA && nProcInfoNeeded > 0) {
            nProcInfo = nProcInfoNeeded;
            std::vector<RM_PROCESS_INFO> info(nProcInfo);
            if (RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, info.data(), &dwReason) == ERROR_SUCCESS) {
                for (UINT i = 0; i < nProcInfo; i++) {
                    // Hanya masukan proses pihak ketiga (bukan explorer atau system biasa)
                    DWORD pid = info[i].Process.dwProcessId;
                    if (pid > 4) pids.push_back(pid);
                }
            }
        }
    }
    RmEndSession(dwSession);
    return pids;
}

// ============================================================
// respond_unknown_pid — Cari dan bunuh semua suspect
// ============================================================
// Dipanggil ketika canary triggered tapi PID tidak diketahui.
// Melakukan:
//   1. Cek Restart Manager untuk path file canary terakhir
//   2. Scan semua proses, bandingkan dengan baseline (fallback)
//   3. Kill + quarantine semua suspect
void RansomwareShield::respond_unknown_pid(RansomwareEvent& event) {
    Logger::instance().critical("=== SUSPECT HUNT START ===");

    std::vector<SuspectProcess> suspects;

    // LANGKAH 1: Lacak via Restart Manager (Sangat Akurat)
    std::string triggered_canary = m_canary.get_last_triggered_path();
    if (!triggered_canary.empty()) {
        auto locking_pids = get_processes_locking_file(triggered_canary);
        for (DWORD pid : locking_pids) {
            SuspectProcess sp;
            sp.pid = pid;
            sp.is_new = true;
            char path[MAX_PATH] = {};
            HANDLE hP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hP) {
                DWORD psz = MAX_PATH;
                if (QueryFullProcessImageNameA(hP, 0, path, &psz)) sp.exe_path = path;
                CloseHandle(hP);
            }
            if (!sp.exe_path.empty()) {
                suspects.push_back(sp);
                Logger::instance().critical("RM FOUND LOCKER: PID=" + std::to_string(pid) + " (" + sp.exe_path + ")");
            }
        }
    }

    // LANGKAH 2: Fallback ke metode lama (Baseline IO)
    if (suspects.empty()) {
        Logger::instance().warning("RM failed to find locker, using heuristic scan...");
        suspects = find_suspect_processes();
    }

    if (suspects.empty()) {
        Logger::instance().warning("No suspect processes found — ransomware may have exited");
        event.detail += " [NO_SUSPECTS]";

        // Tetap lakukan registry rollback
        auto rollbacks = m_reg_monitor.rollback_new_entries();
        for (const auto& rb : rollbacks) {
            std::string status = rb.success ? "OK" : "FAIL";
            event.detail += " | RegRollback:" + rb.name + "=" + status;
        }
        if (!rollbacks.empty()) m_reg_monitor.refresh_snapshot();

        return;
    }

    // Kill + quarantine semua suspect
    int killed = 0;
    int quarantined = 0;
    for (const auto& sp : suspects) {
        Logger::instance().critical("ENGAGING SUSPECT: PID=" + std::to_string(sp.pid) +
            " Path=" + sp.exe_path +
            " Write=" + std::to_string(sp.write_bytes / 1024) + "KB" +
            (sp.is_new ? " [NEW]" : " [IO_ANOMALY]"));

        // Update event dengan info suspect pertama (paling mencurigakan)
        if (killed == 0) {
            event.process_id = sp.pid;
            event.process_path = sp.exe_path;
            event.process_name = fs::path(sp.exe_path).filename().string();
        }

        // Kill proses
        bool k = kill_process(sp.pid);
        if (k) {
            killed++;
            Logger::instance().critical("KILLED PID " + std::to_string(sp.pid));

            // Tandai sudah di-respond
            {
                std::lock_guard<std::mutex> rl(m_responded_mtx);
                m_responded_pids.insert(sp.pid);
            }
        } else {
            // Fallback: suspend
            bool suspended = suspend_process(sp.pid);
            if (suspended) {
                Logger::instance().warning("Kill failed, SUSPENDED PID " + std::to_string(sp.pid));
                {
                    std::lock_guard<std::mutex> rl(m_responded_mtx);
                    m_responded_pids.insert(sp.pid);
                }
            }
        }

        // Quarantine executable (setelah kill)
        if (m_quarantine && !sp.exe_path.empty()) {
            // Tunggu sebentar agar process handle terlepas
            Sleep(300);
            std::string reason = "Ransomware suspect [" +
                (sp.is_new ? std::string("new_process") : std::string("io_anomaly")) +
                "] Write=" + std::to_string(sp.write_bytes / 1024) + "KB";
            bool q = m_quarantine->quarantine_file(sp.exe_path, reason);
            if (q) {
                quarantined++;
                Logger::instance().critical("QUARANTINED: " + sp.exe_path);
            } else {
                Logger::instance().warning("Failed to quarantine: " + sp.exe_path);
            }
        }
    }

    event.detail += " [KILLED:" + std::to_string(killed) +
                    " QUARANTINED:" + std::to_string(quarantined) +
                    " SUSPECTS:" + std::to_string(suspects.size()) + "]";

    // Registry rollback
    auto rollbacks = m_reg_monitor.rollback_new_entries();
    for (const auto& rb : rollbacks) {
        std::string status = rb.success ? "OK" : "FAIL";
        Logger::instance().critical("REGISTRY ROLLBACK [" + status + "]: " +
            rb.name + " from " + rb.registry_path);
        event.detail += " | RegRollback:" + rb.name + "=" + status;
    }
    if (!rollbacks.empty()) m_reg_monitor.refresh_snapshot();

    // Redeploy canary files untuk monitoring lanjutan
    Logger::instance().info("Re-deploying canary files...");
    m_canary.remove_canaries();
    Sleep(500);
    m_canary.deploy_canaries(m_protected_dir, 5);

    Logger::instance().critical("=== SUSPECT HUNT END === Killed:" + std::to_string(killed) +
        " Quarantined:" + std::to_string(quarantined));
}

// ============================================================
// respond_to_threat — Respons otomatis
// ============================================================
void RansomwareShield::respond_to_threat(RansomwareEvent& event) {
    // Debounce: jangan respons terlalu sering
    uint64_t now = GetTickCount64();
    uint64_t last = m_last_response_ms.load();
    if (now - last < RESPONSE_COOLDOWN_MS) {
        // Masih dalam cooldown — tetap log tapi skip heavy response
        event.detail += " [COOLDOWN]";
        return;
    }
    m_last_response_ms = now;

    // === Kasus 1: PID tidak diketahui (canary event) ===
    if (event.process_id == 0) {
        respond_unknown_pid(event);
        return;
    }

    // === Kasus 2: PID diketahui ===
    // Cek apakah PID sudah pernah di-respond
    {
        std::lock_guard<std::mutex> rl(m_responded_mtx);
        if (m_responded_pids.count(event.process_id)) {
            event.detail += " [ALREADY_HANDLED]";
            return;
        }
        m_responded_pids.insert(event.process_id);
    }

    // Resolve path executable SEBELUM kill
    std::string exe_path = get_process_path(event.process_id);
    event.process_path = exe_path;
    if (!exe_path.empty()) {
        event.process_name = fs::path(exe_path).filename().string();
    }

    Logger::instance().critical("=== THREAT RESPONSE START === PID=" +
        std::to_string(event.process_id) + " Path=" + exe_path);

    // Step 1: Kill proses langsung
    bool killed = kill_process(event.process_id);
    if (killed) {
        Logger::instance().critical("KILLED PID " + std::to_string(event.process_id));
        event.detail += " [KILLED]";
    } else {
        // Fallback: suspend
        bool suspended = suspend_process(event.process_id);
        if (suspended) {
            Logger::instance().warning("Kill failed, SUSPENDED PID " + std::to_string(event.process_id));
            event.detail += " [SUSPENDED]";
        } else {
            Logger::instance().error("Failed to kill/suspend PID " + std::to_string(event.process_id));
            event.detail += " [RESPONSE_FAILED]";
        }
    }

    // Step 2: Quarantine executable
    if (!exe_path.empty() && m_quarantine) {
        Sleep(300);
        std::string reason = "Ransomware detection: " + event.detail;
        bool q = m_quarantine->quarantine_file(exe_path, reason);
        if (q) {
            Logger::instance().critical("QUARANTINED: " + exe_path);
            event.detail += " [QUARANTINED]";
        } else {
            Logger::instance().warning("Failed to quarantine: " + exe_path);
            event.detail += " [QUARANTINE_FAILED]";
        }
    }

    // Step 3: Registry rollback
    auto rollbacks = m_reg_monitor.rollback_new_entries();
    for (const auto& rb : rollbacks) {
        std::string status = rb.success ? "OK" : "FAIL";
        Logger::instance().critical("REGISTRY ROLLBACK [" + status + "]: " +
            rb.name + " from " + rb.registry_path);
        event.detail += " | RegRollback:" + rb.name + "=" + status;
    }
    if (!rollbacks.empty()) m_reg_monitor.refresh_snapshot();

    // Step 4: Redeploy canary files
    Logger::instance().info("Re-deploying canary files...");
    m_canary.remove_canaries();
    Sleep(300);
    m_canary.deploy_canaries(m_protected_dir, 5);

    Logger::instance().critical("=== THREAT RESPONSE END ===");
}

// ============================================================
// fire_event — Trigger respons otomatis + notify GUI
// ============================================================
void RansomwareShield::fire_event(RansomwareEvent event) {
    event.timestamp = std::chrono::system_clock::now();

    // === OTOMASI TINDAKAN (Global Lockdown) ===
    // Cek jika >3 canary modifications dalam 5 detik = Outbreak!
    static std::deque<std::chrono::system_clock::time_point> canary_hits;
    if (event.type == RansomwareEvent::Type::CANARY_TRIGGERED || event.type == RansomwareEvent::Type::ENTROPY_SPIKE) {
        auto now = std::chrono::system_clock::now();
        canary_hits.push_back(now);

        // Hapus yang lebih dari 5 detik
        while (!canary_hits.empty() && 
               std::chrono::duration_cast<std::chrono::seconds>(now - canary_hits.front()).count() > 5) {
            canary_hits.pop_front();
        }

        if (canary_hits.size() > 3) {
            Logger::instance().critical("!!! GLOBAL LOCKDOWN INITIATED !!! (>3 hits in 5s)");
            event.detail += " [GLOBAL LOCKDOWN]";
            
            // Suspend agresif semua proses non-system!
            std::vector<DWORD> allPids;
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = { sizeof(pe) };
                if (Process32FirstW(snap, &pe)) {
                    do {
                        std::wstring name = pe.szExeFile;
                        std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                        // Jangan kill diri sendiri atau system vital
                        if (name != L"gor.exe" && name != L"gor_scanner.exe" && 
                            name != L"gor_watchdog.exe" && name != L"svchost.exe" && 
                            name != L"explorer.exe" && name != L"csrss.exe" && 
                            name != L"winlogon.exe" && name != L"smss.exe" && 
                            name != L"services.exe" && name != L"lsass.exe") {
                            suspend_process(pe.th32ProcessID);
                        }
                    } while (Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }
            canary_hits.clear(); // Reset setelah lockdown
        }
    }

    // Respons otomatis: identify → kill → quarantine → registry rollback → redeploy
    respond_to_threat(event);

    // Simpan event setelah respons (detail sudah di-update)
    {
        std::lock_guard<std::mutex> lk(m_event_mtx);
        m_events.push_back(event);
        if (m_events.size() > 100) {
            m_events.erase(m_events.begin());
        }
    }

    // Notify GUI/callback
    if (m_callback) {
        m_callback(event);
    }
}

// ============================================================
// monitor_loop — LAYER 2: Polling backup (500ms)
// ============================================================
// Ini adalah fallback jika ReadDirectoryChangesW gagal atau
// untuk mendeteksi ancaman yang tidak terlihat oleh watcher
// (VSS deletion, registry persistence, IO spike, extension rename)
void RansomwareShield::monitor_loop() {
    while (m_running) {
        try {
            // === Check 1: Canary files (primary) ===
            if (!m_canary.check_canaries()) {
                RansomwareEvent evt;
                evt.type = RansomwareEvent::Type::CANARY_TRIGGERED;
                evt.detail = "Canary file modified or deleted!";
                evt.process_id = 0;
                fire_event(evt);
            }

            // === Check 1b: User folder canaries ===
            if (!m_user_canary.check_canaries()) {
                RansomwareEvent evt;
                evt.type = RansomwareEvent::Type::CANARY_TRIGGERED;
                evt.detail = "USER FOLDER canary modified! Ransomware encrypting user files!";
                evt.process_id = 0;
                fire_event(evt);
            }

            // === Check 2: VSS deletion — AUTO-KILL ===
            auto vss_violations = VSSProtector::detect_and_respond();
            for (const auto& v : vss_violations) {
                RansomwareEvent evt;
                evt.type = RansomwareEvent::Type::VSS_DELETE_ATTEMPT;
                evt.process_id = v.pid;
                evt.process_path = v.exe_path;
                evt.detail = "VSS abuse KILLED: " + v.exe_path + " (" + v.command_hint + ")";
                fire_event(evt);
            }

            // === Check 3: Registry persistence ===
            auto new_regs = m_reg_monitor.detect_new_entries();
            if (!new_regs.empty()) {
                for (const auto& [name, value] : new_regs) {
                    RansomwareEvent evt;
                    evt.type = RansomwareEvent::Type::REGISTRY_PERSISTENCE;
                    evt.detail = "New Run entry: " + name + " = " + value;
                    evt.process_id = 0;
                    fire_event(evt);
                }
            }

            // === Check 4: I/O spike ===
            if (m_io_monitor.has_spike()) {
                DWORD pid = m_io_monitor.get_spike_pid();
                RansomwareEvent evt;
                evt.type = RansomwareEvent::Type::IO_SPIKE_DETECTED;
                evt.process_id = pid;
                evt.detail = "I/O write spike: " + std::to_string(m_io_monitor.get_write_count(pid)) + " ops/sec";
                fire_event(evt);
            }

            // === Check 5: Extension rename anomaly ===
            if (m_ext_monitor.is_anomaly_detected()) {
                DWORD pid = m_ext_monitor.get_suspect_pid();
                RansomwareEvent evt;
                evt.type = RansomwareEvent::Type::MASS_RENAME_DETECTED;
                evt.process_id = pid;
                evt.detail = "Mass file extension rename detected";
                fire_event(evt);
            }

            // Cleanup old I/O data
            m_io_monitor.cleanup();

        } catch (...) {
            Logger::instance().error("RansomwareShield monitor error (caught)");
        }

        // Interval polling: 500ms
        for (int i = 0; i < 5 && m_running; ++i) {
            Sleep(100);
        }
    }
}

RansomwareEvent RansomwareShield::check_now() {
    RansomwareEvent evt;
    evt.type = RansomwareEvent::Type::CANARY_TRIGGERED;
    evt.process_id = 0;

    if (!m_canary.check_canaries()) {
        evt.detail = "CANARY ALERT!";
        return evt;
    }

    if (VSSProtector::detect_vss_deletion_attempt()) {
        evt.type = RansomwareEvent::Type::VSS_DELETE_ATTEMPT;
        evt.detail = "VSS deletion detected!";
        return evt;
    }

    evt.detail = "All clear";
    return evt;
}

// ============================================================
// kill_process — Terminate proses langsung
// ============================================================
bool RansomwareShield::kill_process(DWORD pid) {
    if (pid == 0) return false;

    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) {
        Logger::instance().warning("Cannot open PID " + std::to_string(pid) + " for termination");
        return false;
    }

    BOOL result = TerminateProcess(hProc, 1);
    CloseHandle(hProc);

    if (result) {
        Logger::instance().critical("TERMINATED PID: " + std::to_string(pid));
        return true;
    }

    Logger::instance().warning("TerminateProcess failed for PID " + std::to_string(pid));
    return false;
}

// ============================================================
// suspend_process — Legacy suspend (fallback)
// ============================================================
bool RansomwareShield::suspend_process(DWORD pid) {
    typedef LONG(NTAPI* NtSuspendProcessFn)(HANDLE);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    auto pNtSuspendProcess = reinterpret_cast<NtSuspendProcessFn>(
        GetProcAddress(ntdll, "NtSuspendProcess"));
    if (!pNtSuspendProcess) return false;

    HANDLE hProc = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProc) {
        Logger::instance().warning("Cannot open PID " + std::to_string(pid) + " for suspend");
        return false;
    }

    LONG status = pNtSuspendProcess(hProc);
    CloseHandle(hProc);

    if (status == 0) {
        Logger::instance().critical("SUSPENDED PID: " + std::to_string(pid));
        return true;
    }

    return false;
}

// ============================================================
// quarantine_threat — Quarantine executable berdasarkan PID
// ============================================================
bool RansomwareShield::quarantine_threat(DWORD pid, const std::string& reason) {
    std::string exe_path = get_process_path(pid);
    if (exe_path.empty()) {
        Logger::instance().warning("Cannot resolve path for PID " + std::to_string(pid));
        return false;
    }

    // Kill dulu sebelum quarantine agar file tidak locked
    kill_process(pid);
    Sleep(500);

    if (m_quarantine) {
        return m_quarantine->quarantine_file(exe_path, reason);
    }

    Logger::instance().warning("QuarantineManager not set, cannot quarantine");
    return false;
}

std::vector<RansomwareEvent> RansomwareShield::get_recent_events() const {
    std::lock_guard<std::mutex> lk(m_event_mtx);
    return m_events;
}

} // namespace av
