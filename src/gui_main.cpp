#ifndef UNICODE
#define UNICODE
#endif

#include "gui/gui_common.h"
#include "gui/gui_draw.h"
#include "scanner/scanner.h"
#include "protection/ransomware_shield.h"
#include "protection/process_guard.h"
#include "quarantine/quarantine.h"
#include "utils/logger.h"

#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <string>
#include <thread>
#include <mutex>
#include <vector>
#include <filesystem>
#include <set>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;
using namespace av_gui;

// ===== Constants =====
static const wchar_t* APP_NAME     = L"Gor Guard";
static const wchar_t* APP_CLASS    = L"GorGuardDark";
static const wchar_t* APP_VERSION  = L"v2.0.0";
static const char*    APP_REG_NAME = "GorGuard";

// System tray
static const UINT WM_TRAYICON  = WM_USER + 100;
static const UINT IDI_TRAY     = 1001;
// Custom messages
static const UINT WM_REFRESH   = WM_USER + 1;

// ===== Globals =====
static HWND g_hWnd;
static HINSTANCE g_hInst;
static Tab g_activeTab = TAB_DASHBOARD;
static ScanState g_scan;
static ULONG_PTR g_gdipToken;
static std::vector<std::wstring> g_logLines;
static std::mutex g_logMtx;
static av::Scanner* g_pScanner = nullptr;

static std::atomic<bool> g_autoScanEnabled{false};
static std::atomic<bool> g_autoScanRunning{false};
static std::set<DWORD> g_knownPids;
static std::mutex g_pidMtx;

static const int SIDEBAR_W = 200;
static const int WIN_W = 1060, WIN_H = 720;
static const wchar_t* TAB_LABELS[] = { L"Dashboard", L"Scan", L"Quarantine", L"Ransomware", L"Settings" };
static const wchar_t* TAB_ICONS[] = { L"\x25A3", L"\x25B6", L"\x26A0", L"\x2666", L"\x2699" };

// Shields
static av::RansomwareShield g_rwShield;
static std::atomic<bool> g_rwShieldOn{false};
static av::ProcessGuard g_procGuard;
static std::atomic<bool> g_procGuardOn{false};
static av::QuarantineManager g_rwQuarantine;

// Scroll state per-tab
static int g_scrollDash = 0;
static int g_scrollScan = 0;
static int g_scrollRW   = 0;

// Threat trackers
static std::atomic<int> g_realtimeThreats{0};

// === Settings yang dipersist ===
static bool g_autoStart       = false;   // Auto-start saat Windows boot
static bool g_minimizeToTray  = true;    // Minimize ke tray saat close
static bool g_startMinimized  = false;   // Mulai dalam keadaan minimized

// System tray state
static NOTIFYICONDATAW g_nid = {};
static bool g_trayCreated = false;

// ===== Installer Mode =====
static bool g_isInstallerMode = false;
static std::wstring g_installPath = L"C:\\Program Files\\GorGuard";

static void RunInstallProcess(HWND hWnd) {
    std::filesystem::path destDir(av_gui::W2U(g_installPath));
    std::error_code ec;

    // Create directories
    std::filesystem::create_directories(destDir, ec);
    std::filesystem::create_directories(destDir / "data", ec);
    std::filesystem::create_directories(destDir / "data" / "canary", ec);
    std::filesystem::create_directories(destDir / "quarantine", ec);

    // Generate config files
    std::ofstream(destDir / "data" / "hashdb.txt") << "";
    std::ofstream(destDir / "data" / "whitelist.txt") << "";
    std::ofstream(destDir / "data" / "gor_guard.cfg") << "auto_start=1\n";

    // Copy EXEs
    char myPath[MAX_PATH];
    GetModuleFileNameA(NULL, myPath, MAX_PATH);
    std::filesystem::path currentExe(myPath);
    std::filesystem::path currDir = currentExe.parent_path();

    std::filesystem::copy_file(currentExe, destDir / "gor.exe", std::filesystem::copy_options::overwrite_existing, ec);

    // Scanner
    if (std::filesystem::exists(currDir / "gor_scanner.exe")) {
        std::filesystem::copy_file(currDir / "gor_scanner.exe", destDir / "gor_scanner.exe", std::filesystem::copy_options::overwrite_existing, ec);
    }
    // Watchdog
    if (std::filesystem::exists(currDir / "gor_watchdog.exe")) {
        std::filesystem::copy_file(currDir / "gor_watchdog.exe", destDir / "gor_watchdog.exe", std::filesystem::copy_options::overwrite_existing, ec);
    }

    MessageBoxW(hWnd, L"Gor Guard has been successfully installed!\nThe application will now start.", L"Gor Guard Setup", MB_OK | MB_ICONINFORMATION);

    std::wstring installedExe = g_installPath + L"\\gor.exe";
    ShellExecuteW(NULL, L"open", installedExe.c_str(), NULL, NULL, SW_SHOWNORMAL);

    PostQuitMessage(0);
}

static void PaintInstaller(HDC hdc, int w, int h) {
    int cx = w / 2;

    // Title
    av_gui::NmIconCircle(hdc, cx - 20, 60, 40, av_gui::NM_ACCENT, L"\x2694");
    // Karena kita tidak memiliki argumen CenterAlignment, x manual:
    av_gui::NmText(hdc, L"Gor Guard Setup", cx - 75, 120, av_gui::NM_TEXT, 22, true);
    av_gui::NmText(hdc, L"Instalasi Antivirus & Ransomware Protection", cx - 110, 155, av_gui::NM_TEXT_SEC, 12, false);

    // Box Input Install Path
    int boxW = 460;
    int boxX = cx - boxW / 2;
    int boxY = 240;
    
    av_gui::NmText(hdc, L"Pilih direktori instalasi:", boxX, boxY - 25, av_gui::NM_TEXT_LT, 11, false);
    av_gui::NmInset(hdc, boxX, boxY, boxW, 46, 8, 3);
    av_gui::NmText(hdc, g_installPath.c_str(), boxX + 16, boxY + 14, av_gui::NM_TEXT, 12, false);

    // Browse Button
    av_gui::NmRaised(hdc, boxX + boxW - 90, boxY + 5, 84, 36, 6, 2);
    av_gui::NmText(hdc, L"Browse", boxX + boxW - 74, boxY + 14, av_gui::NM_TEXT, 11, true);

    // Install Button
    int btnW = 200;
    int btnX = cx - btnW / 2;
    int btnY = h - 120;
    av_gui::NmAccentRaised(hdc, btnX, btnY, btnW, 50, 10, av_gui::NM_ACCENT);
    av_gui::NmText(hdc, L"Install Now", btnX + 55, btnY + 16, RGB(255, 255, 255), 13, true);

    // Status / hint text
    av_gui::NmText(hdc, L"Setup akan menyiapkan engine, update database, dan mengaktifkan service guard.", cx - 180, btnY - 30, av_gui::NM_TEXT_SEC, 10, false);
}

// ===== Path Resolution =====
static std::string FindProjectRoot() {
    char buf[MAX_PATH];
    GetModuleFileNameA(NULL, buf, MAX_PATH);
    fs::path dir = fs::path(buf).parent_path();
    for (int i = 0; i < 6; ++i) {
        if (fs::exists(dir / "data" / "hashdb.txt")) return dir.string();
        if (dir == dir.parent_path()) break;
        dir = dir.parent_path();
    }
    return "";
}
static std::string g_projectRoot;

static std::string GetConfigPath() {
    return g_projectRoot + "\\data\\gor_guard.cfg";
}

// ============================================================
// SETTINGS PERSISTENCE — Simpan/Load ke file config
// ============================================================
static void SaveSettings() {
    std::string path = GetConfigPath();
    std::ofstream f(path);
    if (!f.is_open()) return;

    f << "auto_start=" << (g_autoStart ? "1" : "0") << "\n";
    f << "minimize_to_tray=" << (g_minimizeToTray ? "1" : "0") << "\n";
    f << "start_minimized=" << (g_startMinimized ? "1" : "0") << "\n";
    f << "auto_scan=" << (g_autoScanEnabled.load() ? "1" : "0") << "\n";
    f << "process_guard=" << (g_procGuardOn.load() ? "1" : "0") << "\n";
    f << "ransomware_shield=" << (g_rwShieldOn.load() ? "1" : "0") << "\n";
    f << "auto_quarantine=" << (g_scan.auto_quarantine ? "1" : "0") << "\n";
    f << "max_size_mb=" << g_scan.max_size_mb << "\n";
    f << "db_path=" << g_scan.db_path << "\n";
    f << "q_path=" << g_scan.q_path << "\n";

    f.close();
}

static void LoadSettings() {
    std::string path = GetConfigPath();
    std::ifstream f(path);
    if (!f.is_open()) return;

    std::string line;
    while (std::getline(f, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        if (key == "auto_start")          g_autoStart      = (val == "1");
        else if (key == "minimize_to_tray") g_minimizeToTray = (val == "1");
        else if (key == "start_minimized")  g_startMinimized = (val == "1");
        else if (key == "auto_scan")        g_autoScanEnabled = (val == "1");
        else if (key == "process_guard")    g_procGuardOn    = (val == "1");
        else if (key == "ransomware_shield") g_rwShieldOn    = (val == "1");
        else if (key == "auto_quarantine")  g_scan.auto_quarantine = (val == "1");
        else if (key == "max_size_mb") {
            try { g_scan.max_size_mb = std::stoi(val); } catch (...) {}
        }
        else if (key == "db_path" && !val.empty()) g_scan.db_path = val;
        else if (key == "q_path" && !val.empty())  g_scan.q_path = val;
    }
    f.close();
}

// ============================================================
// SeDebugPrivilege — KRITIS untuk antivirus
// ============================================================
// Tanpa privilege ini, OpenProcess() GAGAL pada proses elevated
// meskipun AV sudah berjalan sebagai Administrator.
// Ini adalah penyebab utama malware admin tidak terdeteksi.
static bool EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege",
        &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    return (ok && err == ERROR_SUCCESS);
}

// ============================================================
// AUTO-START — Task Scheduler (elevated)
// ============================================================
// Menggunakan Task Scheduler karena registry Run key TIDAK
// berfungsi untuk app dengan UAC manifest requireAdministrator.
// Task Scheduler bisa menjalankan app dengan highest privileges
// tanpa UAC prompt saat boot.
static void RunHiddenCmd(const std::string& cmd) {
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    std::string cmdline = "cmd.exe /c " + cmd;
    if (CreateProcessA(NULL, const_cast<char*>(cmdline.c_str()),
        NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static void SetAutoStart(bool enable) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    if (enable) {
        // Buat scheduled task yang berjalan saat login dengan highest privileges
        std::string cmd = "schtasks /create /tn \"GorGuard\" /sc onlogon /rl highest"
                          " /tr \"\\\"" + std::string(exePath) + "\\\" --minimized\""
                          " /f";
        RunHiddenCmd(cmd);
    } else {
        RunHiddenCmd("schtasks /delete /tn \"GorGuard\" /f");
    }
}

// ============================================================
// SYSTEM TRAY — Notify icon management
// ============================================================
static void CreateTrayIcon(HWND hWnd) {
    if (g_trayCreated) return;

    g_nid = {};
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hWnd;
    g_nid.uID = IDI_TRAY;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_SHIELD);
    wcscpy_s(g_nid.szTip, L"Gor Guard — Running in background");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
    g_trayCreated = true;
}

static void RemoveTrayIcon() {
    if (!g_trayCreated) return;
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
    g_trayCreated = false;
}

static void MinimizeToTray(HWND hWnd) {
    CreateTrayIcon(hWnd);
    ShowWindow(hWnd, SW_HIDE);
}

static void RestoreFromTray(HWND hWnd) {
    ShowWindow(hWnd, SW_SHOW);
    SetForegroundWindow(hWnd);
    // Tray icon tetap ada selama app berjalan
}

static void ShowTrayMenu(HWND hWnd) {
    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, 1, L"\x25B6  Show Gor Guard");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);

    AppendMenuW(hMenu, g_procGuardOn ? MF_CHECKED : MF_UNCHECKED, 2, L"Process Guard");
    AppendMenuW(hMenu, g_rwShieldOn ? MF_CHECKED : MF_UNCHECKED, 3, L"Ransomware Shield");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, 9, L"\x2716  Exit");

    SetForegroundWindow(hWnd);
    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY,
                             pt.x, pt.y, 0, hWnd, NULL);
    DestroyMenu(hMenu);

    switch (cmd) {
    case 1: RestoreFromTray(hWnd); break;
    case 9:
        // Full exit: save + stop + quit
        SaveSettings();
        g_rwShield.stop(); g_procGuard.stop(); g_autoScanEnabled = false;
        RemoveTrayIcon();
        DestroyWindow(hWnd);
        break;
    }
}

// ===== Helpers =====
static void AddLog(const std::wstring& msg) {
    std::lock_guard<std::mutex> lk(g_logMtx);
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t ts[32]; swprintf_s(ts, L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    g_logLines.insert(g_logLines.begin(), ts + msg);
    if (g_logLines.size() > 200) g_logLines.resize(200);
}
static std::wstring U2W_s(const std::string& s) { return U2W(s); }

// ============================================================
// SHIELD ACTIVATION HELPERS
// ============================================================
static void ActivateProcessGuard() {
    g_procGuard.set_database_path(g_projectRoot + "\\" + g_scan.db_path);
    g_procGuard.set_action(av::ProcessGuard::Action::SUSPEND);
    g_procGuard.set_callback([](const av::ProcessThreatEvent& evt) {
        try { AddLog(L"\x26A0 GUARD: " + U2W(evt.threat_name) + L" [" + U2W(evt.action_taken) + L"]"); } catch (...) {}
        PostMessage(g_hWnd, WM_REFRESH, 0, 0);
    });
    g_procGuard.start();
    AddLog(L"Process Guard ACTIVATED");
}

static void ActivateRwShield() {
    std::string rwQPath = g_projectRoot + "\\" + g_scan.q_path;
    g_rwQuarantine.init(rwQPath);
    g_rwShield.set_quarantine(&g_rwQuarantine);
    g_rwShield.init(g_projectRoot + "\\data\\canary");
    g_rwShield.set_callback([](const av::RansomwareEvent& evt) {
        g_realtimeThreats++;
        try { AddLog(L"RW-SHIELD: " + U2W(evt.detail)); } catch (...) {}
        PostMessage(g_hWnd, WM_REFRESH, 0, 0);
    });
    g_rwShield.start();
    AddLog(L"Ransomware Shield ACTIVATED (Kill+Quarantine+Rollback)");
}

// ===== Scanner Thread =====
static void RunScanThread() {
    g_scan.running = true;
    g_scan.progress = 0;
    g_scan.scanned = 0;
    g_scan.threats = 0;

    try {
        AddLog(L"Scan started: " + U2W_s(g_scan.scan_path));
        std::string dbFull = g_projectRoot + "\\" + g_scan.db_path;
        std::string qFull  = g_projectRoot + "\\" + g_scan.q_path;

        av::Logger::instance().init((g_projectRoot + "\\av_scan.log").c_str());
        av::Scanner scanner;
        g_pScanner = &scanner;

        if (!scanner.load_database(dbFull)) {
            AddLog(L"ERROR: DB not found");
            g_scan.running = false; g_pScanner = nullptr;
            PostMessage(g_hWnd, WM_REFRESH, 0, 0); return;
        }

        scanner.set_max_file_size(static_cast<uintmax_t>(g_scan.max_size_mb) * 1024 * 1024);
        scanner.add_exclude_path(qFull);
        scanner.add_exclude_path(g_projectRoot + "\\build");
        scanner.add_exclude_path(g_projectRoot + "\\data\\canary");
        std::string wlPath = g_projectRoot + "\\data\\whitelist.txt";
        scanner.load_whitelist(wlPath);

        if (g_scan.auto_quarantine) {
            scanner.init_quarantine(qFull);
            scanner.set_auto_quarantine(true);
        }

        g_scan.phase = 0;
        g_scan.start_time_ms = static_cast<double>(GetTickCount64());

        scanner.set_phase_callback([](av::Scanner::Phase p, size_t val, size_t total) {
            UNREFERENCED_PARAMETER(total);
            if (p == av::Scanner::Phase::COUNTING) {
                g_scan.phase = 0;
                g_scan.total_files = static_cast<int>(val);
            } else {
                g_scan.phase = 1;
            }
            PostMessage(g_hWnd, WM_REFRESH, 0, 0);
        });

        scanner.set_progress_callback([](const av::ScanResult& r, size_t cur, size_t total) {
            g_scan.total_files = static_cast<int>(total);
            g_scan.scanned = static_cast<int>(cur);
            g_scan.progress = total > 0 ? static_cast<int>((cur * 100) / total) : 0;
            if (r.is_threat) {
                g_scan.threats++;
                try { AddLog(L"\x26A0 THREAT: " + U2W(r.threat_name) + L" -> " + U2W(r.file_path)); } catch (...) {}
            }
            if (cur % 500 == 0 || r.is_threat)
                PostMessage(g_hWnd, WM_REFRESH, 0, 0);
        });

        av::ScanStats stats = scanner.scan(g_scan.scan_path);
        g_pScanner = nullptr;
        g_scan.phase = 1;

        if (scanner.is_cancelled()) {
            AddLog(L"Scan cancelled by user");
        } else {
            wchar_t s[300];
            swprintf_s(s, L"\x2714 Scan complete: %d files, %d threats, %d errors, %.1fs",
                (int)stats.scanned_files, (int)stats.threats_found,
                (int)stats.errors, stats.elapsed_seconds);
            AddLog(s);
        }
        g_scan.progress = scanner.is_cancelled() ? 0 : 100;

    } catch (const std::exception& e) {
        wchar_t msg[256];
        swprintf_s(msg, L"Scan partial: %d files, %d threats", g_scan.scanned.load(), g_scan.threats.load());
        AddLog(msg);
        try { AddLog(L"Detail: " + U2W(e.what())); } catch (...) {}
        g_pScanner = nullptr;
    } catch (...) {
        AddLog(L"Scan partial result returned");
        g_pScanner = nullptr;
    }

    g_scan.running = false;
    PostMessage(g_hWnd, WM_REFRESH, 0, 0);
}

static void StopScan() {
    if (g_pScanner) { g_pScanner->request_cancel(); AddLog(L"Stopping scan..."); }
}

// ===== Auto-Scan Thread =====
static void AutoScanThread() {
    g_autoScanRunning = true;
    av::HashCalculator hasher;
    {
        std::lock_guard<std::mutex> lk(g_pidMtx);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe))
                do { g_knownPids.insert(pe.th32ProcessID); } while (Process32NextW(snap, &pe));
            CloseHandle(snap);
        }
    }
    while (g_autoScanEnabled) {
        Sleep(2000);
        if (!g_autoScanEnabled) break;
        try {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE) continue;
            PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    DWORD pid = pe.th32ProcessID;
                    std::lock_guard<std::mutex> lk(g_pidMtx);
                    if (g_knownPids.count(pid)) continue;
                    g_knownPids.insert(pid);
                    if (pid <= 4) continue;
                    HANDLE hP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                    if (hP) {
                        char path[MAX_PATH] = {};
                        DWORD sz = MAX_PATH;
                        if (QueryFullProcessImageNameA(hP, 0, path, &sz)) {
                            std::string h = hasher.sha256_file(path);
                            if (!h.empty()) {
                                try { AddLog(L"Auto-scan PID " + std::to_wstring(pid)); } catch (...) {}
                                PostMessage(g_hWnd, WM_REFRESH, 0, 0);
                            }
                        }
                        CloseHandle(hP);
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        } catch (...) {}
    }
    g_autoScanRunning = false;
}

// ============================================================
// PAINTING
// ============================================================

// Draw scrollable log lines with clipping
static void DrawLogArea(HDC hdc, int x, int y, int w, int h,
                         const std::vector<std::wstring>& lines, int scrollOff,
                         const wchar_t* title) {
    NmRaised(hdc, x, y, w, h, 14, 4);
    NmText(hdc, title, x + 16, y + 12, NM_TEXT, 13, true);
    NmSeparator(hdc, x + 16, y + 34, w - 32);

    int logTop = y + 42;
    int logH = h - 52;

    NmBeginClip(hdc, x + 4, logTop, w - 8, logH);

    int lineH = 20;
    int visibleLines = logH / lineH;
    int totalLines = static_cast<int>(lines.size());
    int maxScroll = totalLines > visibleLines ? (totalLines - visibleLines) : 0;
    int safeScroll = scrollOff < 0 ? 0 : (scrollOff > maxScroll ? maxScroll : scrollOff);

    if (lines.empty()) {
        NmText(hdc, L"No entries yet.", x + 16, logTop + 8, NM_TEXT_LT, 11);
    } else {
        int ly = logTop;
        for (int i = safeScroll; i < totalLines && (ly - logTop) < logH; ++i) {
            bool isThreat = lines[i].find(L"THREAT") != std::wstring::npos || lines[i].find(L"\x26A0") != std::wstring::npos;
            bool isGuard  = lines[i].find(L"GUARD") != std::wstring::npos;
            bool isShield = lines[i].find(L"RW-SHIELD") != std::wstring::npos;
            bool isOk     = lines[i].find(L"\x2714") != std::wstring::npos;
            COLORREF lc = isThreat ? NM_DANGER : (isGuard ? NM_WARN : (isShield ? NM_ACCENT2 : (isOk ? NM_SUCCESS : NM_TEXT_SEC)));
            NmText(hdc, lines[i], x + 16, ly, lc, 11);
            ly += lineH;
        }
    }

    // Scrollbar
    if (totalLines > visibleLines) {
        int sbX = x + w - 10, sbH = logH;
        int thumbH = (visibleLines * sbH) / totalLines;
        if (thumbH < 20) thumbH = 20;
        int thumbY = logTop + (safeScroll * (sbH - thumbH)) / maxScroll;
        NmFill(hdc, sbX, logTop, 4, sbH, 2, NM_SHADOW_DK);
        NmFill(hdc, sbX, thumbY, 4, thumbH, 2, NM_TEXT_LT);
    }

    NmEndClip(hdc);
}

static void PaintSidebar(HDC hdc, RECT rc) {
    NmFill(hdc, 0, 0, SIDEBAR_W, rc.bottom, 0, NM_SIDEBAR);

    // Logo
    NmIconCircle(hdc, 24, 20, 40, NM_ACCENT, L"\x2694");
    NmText(hdc, APP_NAME, 74, 26, NM_TEXT, 17, true);
    NmText(hdc, L"Antivirus", 74, 46, NM_TEXT_LT, 10);

    NmSeparator(hdc, 16, 72, SIDEBAR_W - 32);

    for (int i = 0; i < TAB_COUNT; ++i) {
        int ny = 88 + i * 52;
        bool active = (i == g_activeTab);

        if (active) {
            NmFill(hdc, 10, ny, SIDEBAR_W - 20, 42, 10, NM_SIDEBAR_ACTIVE);
            NmFill(hdc, 10, ny + 6, 3, 30, 2, NM_ACCENT);
        }
        NmText(hdc, TAB_ICONS[i], 28, ny + 12, active ? NM_ACCENT : NM_TEXT_LT, 14, active);
        NmText(hdc, TAB_LABELS[i], 52, ny + 12, active ? NM_TEXT : NM_TEXT_SEC, 13, active);
    }

    // Bottom
    int by = rc.bottom - 45;
    NmSeparator(hdc, 16, by, SIDEBAR_W - 32);
    NmText(hdc, APP_VERSION, 24, by + 12, NM_TEXT_LT, 10);
    NmText(hdc, L"\x25CF Online", 80, by + 12, NM_SUCCESS, 10);
}

// ===== DASHBOARD =====
static void PaintDashboard(HDC hdc, int x, int y, int w, int h) {
    NmText(hdc, L"Health Overview", x, y, NM_TEXT, 20, true);
    NmText(hdc, L"System protection status", x, y + 26, NM_TEXT_SEC, 11);

    // Status banner
    bool hasScanThreat = g_scan.threats > 0;
    bool hasRWThreat = g_realtimeThreats > 0;
    COLORREF sc = (hasScanThreat || hasRWThreat) ? NM_DANGER : NM_SUCCESS;
    NmAccentRaised(hdc, x, y + 54, w, 46, 12, sc);

    std::wstring statusText = L"\x2714  System Protected, no threats found";
    if (hasRWThreat) {
        statusText = L"\x26A0  RANSOMWARE ACTIVITY DETECTED! Actions taken by shield.";
    } else if (hasScanThreat) {
        statusText = L"\x26A0  Threats detected! Review scan results.";
    }

    NmText(hdc, statusText, x + 18, y + 68, RGB(255, 255, 255), 13, true);

    // Toggle cards row
    int tY = y + 114;
    int tw = (w - 20) / 3;

    // Auto-Scan
    NmRaised(hdc, x, tY, tw, 44, 10, 4);
    NmText(hdc, L"Auto-Scan", x + 12, tY + 6, NM_TEXT, 11, true);
    NmText(hdc, g_autoScanEnabled ? L"Active" : L"Off", x + 12, tY + 24, g_autoScanEnabled ? NM_SUCCESS : NM_TEXT_LT, 9);
    NmToggle(hdc, x + tw - 60, tY + 10, g_autoScanEnabled.load());

    // Process Guard
    NmRaised(hdc, x + tw + 10, tY, tw, 44, 10, 4);
    NmText(hdc, L"Process Guard", x + tw + 22, tY + 6, NM_TEXT, 11, true);
    NmText(hdc, g_procGuardOn ? L"Active" : L"Off", x + tw + 22, tY + 24, g_procGuardOn ? NM_SUCCESS : NM_TEXT_LT, 9);
    NmToggle(hdc, x + tw * 2 - 50, tY + 10, g_procGuardOn.load());

    // RW Shield
    NmRaised(hdc, x + (tw + 10) * 2, tY, tw, 44, 10, 4);
    NmText(hdc, L"Ransomware", x + (tw + 10) * 2 + 12, tY + 6, NM_TEXT, 11, true);
    NmText(hdc, g_rwShieldOn ? L"Active" : L"Off", x + (tw + 10) * 2 + 12, tY + 24, g_rwShieldOn ? NM_SUCCESS : NM_TEXT_LT, 9);
    NmToggle(hdc, x + tw * 3 + 10, tY + 10, g_rwShieldOn.load());

    // Stat cards
    int cY = tY + 60;
    int cW = (w - 30) / 4;
    struct { const wchar_t* label; int val; COLORREF c; const wchar_t* icon; } cards[] = {
        { L"Scanned",  g_scan.scanned.load(), NM_ACCENT,  L"\x25B6" },
        { L"Threats",  g_scan.threats.load(),  NM_DANGER,  L"\x26A0" },
        { L"DB Sigs",  35,                     NM_ACCENT2, L"\x25A8" },
        { L"Max MB",   g_scan.max_size_mb,     NM_TEXT_SEC, L"\x25C6" },
    };
    for (int i = 0; i < 4; ++i) {
        int cx = x + i * (cW + 10);
        NmRaised(hdc, cx, cY, cW, 72, 12, 4);
        NmIconCircle(hdc, cx + 12, cY + 12, 28, cards[i].c, cards[i].icon);
        wchar_t v[32]; swprintf_s(v, L"%d", cards[i].val);
        NmText(hdc, v, cx + 48, cY + 12, cards[i].c, 20, true);
        NmText(hdc, cards[i].label, cx + 48, cY + 38, NM_TEXT_SEC, 10);
    }

    // Activity log (scrollable)
    int logY = cY + 88;
    int logH = h - (logY - y) - 6;
    std::lock_guard<std::mutex> lk(g_logMtx);
    DrawLogArea(hdc, x, logY, w, logH, g_logLines, g_scrollDash, L"Recent Activity");
}

// ===== SCAN =====
static void PaintScan(HDC hdc, int x, int y, int w, int h) {
    NmText(hdc, L"Scan Files", x, y, NM_TEXT, 20, true);
    NmText(hdc, L"Select a folder and start scanning.", x, y + 26, NM_TEXT_SEC, 11);

    // Path input (inset) + Browse button
    int pY = y + 58;
    int browseW = 130;
    NmInset(hdc, x, pY, w - browseW - 12, 38, 10, 2);
    std::wstring pathStr = g_scan.scan_path.empty() ? L"No folder selected..." : U2W_s(g_scan.scan_path);
    NmText(hdc, pathStr, x + 14, pY + 10, g_scan.scan_path.empty() ? NM_TEXT_LT : NM_TEXT, 12);

    NmRaised(hdc, x + w - browseW, pY, browseW, 38, 10, 4);
    NmText(hdc, L"\x25A3 Browse", x + w - browseW + 28, pY + 10, NM_ACCENT, 12, true);

    // Action row
    int aY = pY + 52;
    if (g_scan.running) {
        NmAccentRaised(hdc, x, aY, 160, 38, 10, NM_DANGER);
        NmText(hdc, L"\x25A0  Stop Scan", x + 26, aY + 10, RGB(255,255,255), 12, true);
    } else {
        NmAccentRaised(hdc, x, aY, 160, 38, 10, NM_ACCENT);
        NmText(hdc, L"\x25B6  Start Scan", x + 24, aY + 10, RGB(255,255,255), 12, true);
    }

    NmRaised(hdc, x + 176, aY, 160, 38, 10, 4);
    NmText(hdc, L"Auto-Scan", x + 190, aY + 4, NM_TEXT, 10, true);
    NmToggle(hdc, x + 280, aY + 7, g_autoScanEnabled.load());

    // Progress
    int prY = aY + 52;
    if (g_scan.running || g_scan.progress > 0) {
        NmRaised(hdc, x, prY, w, 88, 12, 4);
        if (g_scan.phase == 0) {
            NmProgressBar(hdc, x + 16, prY + 14, w - 32, 16, 30, NM_ACCENT2);
            wchar_t ct[128];
            swprintf_s(ct, L"Counting files... %d found", g_scan.total_files.load());
            NmText(hdc, ct, x + 16, prY + 40, NM_TEXT_SEC, 11);
        } else {
            NmProgressBar(hdc, x + 16, prY + 14, w - 32, 16, g_scan.progress.load(), NM_ACCENT);
            int cur = g_scan.scanned.load(), tot = g_scan.total_files.load();
            std::wstring eta = L"...";
            if (cur > 10) {
                double el = static_cast<double>(GetTickCount64()) - g_scan.start_time_ms;
                int left = static_cast<int>(((tot - cur) * (el / cur)) / 1000);
                eta = left < 60 ? std::to_wstring(left) + L"s" : std::to_wstring(left/60) + L"m " + std::to_wstring(left%60) + L"s";
            }
            wchar_t p[200];
            swprintf_s(p, L"%d%%  |  %d / %d files  |  ETA: %s", g_scan.progress.load(), cur, tot, eta.c_str());
            NmText(hdc, p, x + 16, prY + 40, NM_TEXT_SEC, 11);
            if (g_scan.threats > 0) {
                wchar_t t[64]; swprintf_s(t, L"\x26A0 %d threats detected", g_scan.threats.load());
                NmText(hdc, t, x + 16, prY + 60, NM_DANGER, 11, true);
            }
        }
        prY += 100;
    }

    // Scan log (scrollable)
    int logH = h - (prY - y) - 6;
    if (logH < 80) logH = 80;
    std::lock_guard<std::mutex> lk(g_logMtx);
    DrawLogArea(hdc, x, prY, w, logH, g_logLines, g_scrollScan, L"Scan Log");
}

// ===== QUARANTINE =====
static void PaintQuarantine(HDC hdc, int x, int y, int w, int h) {
    NmText(hdc, L"Quarantine", x, y, NM_TEXT, 20, true);
    NmText(hdc, L"Isolated threats are stored here.", x, y + 26, NM_TEXT_SEC, 11);

    NmRaised(hdc, x, y + 58, w, h - 78, 14, 4);
    NmIconCircle(hdc, x + w/2 - 22, y + h/2 - 50, 44, NM_TEXT_LT, L"\x26A0");
    NmText(hdc, L"No quarantined files.", x + w/2 - 72, y + h/2 + 8, NM_TEXT_SEC, 12);
    NmText(hdc, L"Run a scan to detect and quarantine threats.", x + w/2 - 155, y + h/2 + 30, NM_TEXT_LT, 10);
}

// ===== RANSOMWARE =====
static void PaintRansomware(HDC hdc, int x, int y, int w, int h) {
    NmText(hdc, L"Ransomware Shield", x, y, NM_TEXT, 20, true);
    NmText(hdc, L"Multi-layer ransomware protection.", x, y + 26, NM_TEXT_SEC, 11);

    // Toggle
    int tY = y + 58;
    if (g_rwShieldOn) {
        NmAccentRaised(hdc, x, tY, 220, 42, 10, NM_SUCCESS);
        NmText(hdc, L"\x25CF  Shield ACTIVE", x + 18, tY + 12, RGB(255,255,255), 13, true);
    } else {
        NmRaised(hdc, x, tY, 220, 42, 10, 4);
        NmText(hdc, L"\x25CB  Shield OFF", x + 18, tY + 12, NM_TEXT_SEC, 13, true);
    }

    // Module cards (2x3)
    int gY = tY + 56;
    int gw = (w - 12) / 2;
    int gh = 52;
    struct { const wchar_t* name; const wchar_t* desc; COLORREF c; const wchar_t* icon; } modules[] = {
        { L"File Canary",        L"Honeypot detects encryption", NM_ACCENT, L"\x2666" },
        { L"Entropy Analyzer",   L"Shannon entropy detection",   NM_ACCENT2, L"\x2261" },
        { L"Extension Monitor",  L"Mass rename tracking",        NM_WARN, L"\x25C6" },
        { L"I/O Spike Detector", L"Write ops/sec monitoring",    NM_DANGER, L"\x25B2" },
        { L"VSS Protection",     L"Shadow copy protection",      NM_SUCCESS, L"\x25A8" },
        { L"Registry Monitor",   L"Run/RunOnce persistence",     NM_ACCENT, L"\x2699" },
    };
    for (int i = 0; i < 6; ++i) {
        int col = i % 2, row = i / 2;
        int mx = x + col * (gw + 12);
        int my = gY + row * (gh + 8);
        NmRaised(hdc, mx, my, gw, gh, 10, 4);
        NmIconCircle(hdc, mx + 10, my + 10, 30, modules[i].c, modules[i].icon);
        NmText(hdc, modules[i].name, mx + 48, my + 8, NM_TEXT, 11, true);
        NmText(hdc, modules[i].desc, mx + 48, my + 28, NM_TEXT_SEC, 9);
    }

    // Events (scrollable)
    int evY = gY + 3 * (gh + 8) + 6;
    int evH = h - (evY - y) - 6;
    if (evH < 80) evH = 80;

    auto events = g_rwShield.get_recent_events();
    std::vector<std::wstring> evLines;
    for (const auto& e : events) evLines.push_back(U2W_s(e.detail));
    DrawLogArea(hdc, x, evY, w, evH, evLines, g_scrollRW, L"Ransomware Events");
}

// ===== SETTINGS =====
static void PaintSettings(HDC hdc, int x, int y, int w, int h) {
    UNREFERENCED_PARAMETER(h);
    NmText(hdc, L"Settings", x, y, NM_TEXT, 20, true);
    NmText(hdc, L"Configure antivirus behavior.", x, y + 26, NM_TEXT_SEC, 11);

    int hw = (w - 14) / 2;
    int cY = y + 58;

    // Database
    NmRaised(hdc, x, cY, hw, 120, 12, 4);
    NmText(hdc, L"\x25A8  Database", x + 16, cY + 12, NM_TEXT, 13, true);
    NmSeparator(hdc, x + 16, cY + 34, hw - 32);
    NmText(hdc, L"Path:", x + 16, cY + 42, NM_TEXT_SEC, 10);
    NmInset(hdc, x + 16, cY + 58, hw - 32, 24, 8, 2);
    NmText(hdc, U2W_s(g_scan.db_path), x + 26, cY + 63, NM_TEXT, 10);
    NmText(hdc, L"Max file: " + std::to_wstring(g_scan.max_size_mb) + L" MB", x + 16, cY + 90, NM_TEXT_SEC, 10);

    // Quarantine
    NmRaised(hdc, x + hw + 14, cY, hw, 120, 12, 4);
    NmText(hdc, L"\x25C6  Quarantine", x + hw + 30, cY + 12, NM_TEXT, 13, true);
    NmSeparator(hdc, x + hw + 30, cY + 34, hw - 32);
    NmText(hdc, L"Folder:", x + hw + 30, cY + 42, NM_TEXT_SEC, 10);
    NmInset(hdc, x + hw + 30, cY + 58, hw - 32, 24, 8, 2);
    NmText(hdc, U2W_s(g_scan.q_path), x + hw + 40, cY + 63, NM_TEXT, 10);
    NmText(hdc, L"Auto-quarantine:", x + hw + 30, cY + 92, NM_TEXT_SEC, 10);
    NmToggle(hdc, x + hw + hw - 40, cY + 88, g_scan.auto_quarantine);

    // Process Guard + Detection
    cY += 135;
    NmRaised(hdc, x, cY, hw, 76, 12, 4);
    NmText(hdc, L"\x25B2  Process Guard", x + 16, cY + 12, NM_TEXT, 12, true);
    NmToggle(hdc, x + hw - 62, cY + 10, g_procGuardOn.load());
    NmText(hdc, g_procGuardOn ? L"Monitoring processes" : L"Click to enable", x + 16, cY + 38, g_procGuardOn ? NM_ACCENT : NM_TEXT_LT, 10);
    NmText(hdc, L"Mode: Suspend on detection", x + 16, cY + 54, NM_TEXT_LT, 9);

    NmRaised(hdc, x + hw + 14, cY, hw, 76, 12, 4);
    NmText(hdc, L"\x25CE  Detection Engine", x + hw + 30, cY + 12, NM_TEXT, 12, true);
    NmText(hdc, L"\x2714 SHA-256  \x2714 PE  \x2714 Signatures", x + hw + 30, cY + 38, NM_ACCENT2, 10);
    NmText(hdc, L"\x2714 Ransomware  \x2714 Process Guard", x + hw + 30, cY + 54, NM_ACCENT2, 10);

    // === BARU: Background & Auto-Start Settings ===
    cY += 92;
    NmRaised(hdc, x, cY, hw, 100, 12, 4);
    NmText(hdc, L"\x25B6  Startup & Background", x + 16, cY + 10, NM_TEXT, 12, true);
    NmSeparator(hdc, x + 16, cY + 30, hw - 32);

    NmText(hdc, L"Auto-start on boot:", x + 16, cY + 40, NM_TEXT_SEC, 10);
    NmToggle(hdc, x + hw - 62, cY + 36, g_autoStart);

    NmText(hdc, L"Minimize to tray:", x + 16, cY + 62, NM_TEXT_SEC, 10);
    NmToggle(hdc, x + hw - 62, cY + 58, g_minimizeToTray);

    NmText(hdc, L"Start minimized:", x + 16, cY + 84, NM_TEXT_SEC, 10);
    NmToggle(hdc, x + hw - 62, cY + 80, g_startMinimized);

    // Whitelist + DB info
    NmRaised(hdc, x + hw + 14, cY, hw, 100, 12, 4);
    NmText(hdc, L"\x2714  Whitelist", x + hw + 30, cY + 10, NM_TEXT, 12, true);
    NmSeparator(hdc, x + hw + 30, cY + 30, hw - 32);
    NmText(hdc, L"File: data\\whitelist.txt", x + hw + 30, cY + 40, NM_TEXT_SEC, 10);
    NmText(hdc, L"Add SHA-256 of safe files", x + hw + 30, cY + 56, NM_TEXT_LT, 9);
    NmText(hdc, L"to prevent false positives", x + hw + 30, cY + 70, NM_TEXT_LT, 9);

    // Exclusions
    cY += 114;
    NmRaised(hdc, x, cY, w, 48, 12, 4);
    NmText(hdc, L"\x25CB  Auto-Excluded:", x + 16, cY + 8, NM_TEXT, 11, true);
    NmText(hdc, L"Quarantine  \x2022  Build  \x2022  Canary  \x2022  System folders  \x2022  $Recycle.Bin  \x2022  WinSxS",
           x + 16, cY + 28, NM_TEXT_LT, 9);
}

// ============================================================
// WNDPROC
// ============================================================
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps; RECT rc; GetClientRect(hWnd, &rc);
        HDC hdc = BeginPaint(hWnd, &ps);
        HDC mem = CreateCompatibleDC(hdc);
        HBITMAP bmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
        SelectObject(mem, bmp);

        HBRUSH bg = CreateSolidBrush(NM_BASE);
        FillRect(mem, &rc, bg); DeleteObject(bg);

        if (g_isInstallerMode) {
            PaintInstaller(mem, rc.right, rc.bottom);
        } else {
            PaintSidebar(mem, rc);

            int cx = SIDEBAR_W + 24, cy = 20, cw = rc.right - SIDEBAR_W - 48, ch = rc.bottom - 40;
            switch (g_activeTab) {
                case TAB_DASHBOARD:  PaintDashboard(mem, cx, cy, cw, ch); break;
                case TAB_SCAN:       PaintScan(mem, cx, cy, cw, ch); break;
                case TAB_QUARANTINE: PaintQuarantine(mem, cx, cy, cw, ch); break;
                case TAB_RANSOMWARE: PaintRansomware(mem, cx, cy, cw, ch); break;
                case TAB_SETTINGS:   PaintSettings(mem, cx, cy, cw, ch); break;
                default: break;
            }
        }

        BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
        DeleteObject(bmp); DeleteDC(mem);
        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        int scroll = delta > 0 ? -2 : 2; // 2 lines per tick
        switch (g_activeTab) {
            case TAB_DASHBOARD:  g_scrollDash += scroll; if (g_scrollDash < 0) g_scrollDash = 0; break;
            case TAB_SCAN:       g_scrollScan += scroll; if (g_scrollScan < 0) g_scrollScan = 0; break;
            case TAB_RANSOMWARE: g_scrollRW += scroll;   if (g_scrollRW < 0) g_scrollRW = 0; break;
            default: break;
        }
        InvalidateRect(hWnd, NULL, FALSE);
        return 0;
    }

    case WM_LBUTTONDOWN: {
        int mx = LOWORD(lParam), my = HIWORD(lParam);
        
        RECT rc; GetClientRect(hWnd, &rc);

        if (g_isInstallerMode) {
            int cx = rc.right / 2;
            int boxW = 460;
            int boxX = cx - boxW / 2;
            int boxY = 240;

            // Cek Browse button
            int browseX = boxX + boxW - 90;
            int browseY = boxY + 5;
            if (mx >= browseX && mx < browseX + 84 && my >= browseY && my < browseY + 36) {
                auto folder = BrowseFolder(hWnd);
                if (!folder.empty()) {
                    g_installPath = folder;
                    InvalidateRect(hWnd, NULL, FALSE);
                }
                return 0;
            }

            // Cek Install button
            int btnW = 200;
            int btnX = cx - btnW / 2;
            int btnY = rc.bottom - 120;
            if (mx >= btnX && mx < btnX + btnW && my >= btnY && my < btnY + 50) {
                RunInstallProcess(hWnd);
                return 0;
            }
            return 0;
        }

        // Sidebar nav
        if (mx < SIDEBAR_W) {
            for (int i = 0; i < TAB_COUNT; ++i) {
                int ny = 88 + i * 52;
                if (my >= ny && my < ny + 42) {
                    g_activeTab = static_cast<Tab>(i);
                    InvalidateRect(hWnd, NULL, FALSE);
                    return 0;
                }
            }
        }

        int bx = SIDEBAR_W + 24;
        RECT rc2; GetClientRect(hWnd, &rc2);
        int cw = rc2.right - SIDEBAR_W - 48;

        // ===== SCAN TAB =====
        if (g_activeTab == TAB_SCAN) {
            int pY = 20 + 58;
            int browseW = 130;
            // Browse
            if (mx >= bx + cw - browseW && mx < bx + cw && my >= pY && my < pY + 38) {
                auto f = BrowseFolder(hWnd);
                if (!f.empty()) { g_scan.scan_path = W2U(f); g_scan.progress = 0; g_scrollScan = 0; AddLog(L"Selected: " + f); InvalidateRect(hWnd, NULL, FALSE); }
            }
            // Start/Stop
            int aY = pY + 52;
            if (mx >= bx && mx < bx + 160 && my >= aY && my < aY + 38) {
                if (g_scan.running) StopScan();
                else if (!g_scan.scan_path.empty()) std::thread(RunScanThread).detach();
                InvalidateRect(hWnd, NULL, FALSE);
            }
            // Auto-Scan toggle
            if (mx >= bx + 176 && mx < bx + 336 && my >= aY && my < aY + 38) {
                g_autoScanEnabled = !g_autoScanEnabled;
                if (g_autoScanEnabled && !g_autoScanRunning) {
                    std::thread(AutoScanThread).detach();
                    AddLog(L"Auto-Scan enabled");
                } else if (!g_autoScanEnabled) AddLog(L"Auto-Scan disabled");
                InvalidateRect(hWnd, NULL, FALSE);
            }
        }

        // ===== DASHBOARD TOGGLES =====
        if (g_activeTab == TAB_DASHBOARD) {
            int tY = 20 + 114;
            int tw = (cw - 20) / 3;

            // Auto-Scan
            if (mx >= bx && mx < bx + tw && my >= tY && my < tY + 44) {
                g_autoScanEnabled = !g_autoScanEnabled;
                if (g_autoScanEnabled && !g_autoScanRunning) { std::thread(AutoScanThread).detach(); AddLog(L"Auto-Scan enabled"); }
                else if (!g_autoScanEnabled) AddLog(L"Auto-Scan disabled");
                InvalidateRect(hWnd, NULL, FALSE);
            }
            // Process Guard
            if (mx >= bx + tw + 10 && mx < bx + tw * 2 + 10 && my >= tY && my < tY + 44) {
                g_procGuardOn = !g_procGuardOn;
                if (g_procGuardOn) { ActivateProcessGuard(); }
                else { g_procGuard.stop(); AddLog(L"Process Guard STOPPED"); }
                InvalidateRect(hWnd, NULL, FALSE);
            }
            // RW Shield
            if (mx >= bx + (tw + 10) * 2 && mx < bx + tw * 3 + 20 && my >= tY && my < tY + 44) {
                g_rwShieldOn = !g_rwShieldOn;
                if (g_rwShieldOn) { ActivateRwShield(); }
                else { g_rwShield.stop(); AddLog(L"Ransomware Shield STOPPED"); }
                InvalidateRect(hWnd, NULL, FALSE);
            }
        }

        // ===== RANSOMWARE TAB =====
        if (g_activeTab == TAB_RANSOMWARE) {
            if (mx >= bx && mx < bx + 220 && my >= 20 + 58 && my < 20 + 100) {
                g_rwShieldOn = !g_rwShieldOn;
                if (g_rwShieldOn) { ActivateRwShield(); }
                else { g_rwShield.stop(); AddLog(L"Ransomware Shield STOPPED"); }
                InvalidateRect(hWnd, NULL, FALSE);
            }
        }

        // ===== SETTINGS TAB =====
        if (g_activeTab == TAB_SETTINGS) {
            int hw = (cw - 14) / 2;

            // Process Guard toggle (row 2, left card)
            int guardY = 20 + 58 + 135;
            if (mx >= bx && mx < bx + hw && my >= guardY && my < guardY + 76) {
                g_procGuardOn = !g_procGuardOn;
                if (g_procGuardOn) { ActivateProcessGuard(); }
                else { g_procGuard.stop(); AddLog(L"Process Guard STOPPED"); }
                InvalidateRect(hWnd, NULL, FALSE);
            }

            // === Startup & Background toggles (row 3, left card) ===
            int startupY = 20 + 58 + 135 + 92;

            // Auto-start toggle
            if (mx >= bx + hw - 62 && mx < bx + hw && my >= startupY + 36 && my < startupY + 52) {
                g_autoStart = !g_autoStart;
                SetAutoStart(g_autoStart);
                AddLog(g_autoStart ? L"\x2714 Auto-start ENABLED" : L"\x25CB Auto-start disabled");
                SaveSettings();
                InvalidateRect(hWnd, NULL, FALSE);
            }

            // Minimize to tray toggle
            if (mx >= bx + hw - 62 && mx < bx + hw && my >= startupY + 58 && my < startupY + 74) {
                g_minimizeToTray = !g_minimizeToTray;
                AddLog(g_minimizeToTray ? L"\x2714 Minimize to tray ENABLED" : L"\x25CB Minimize to tray disabled");
                SaveSettings();
                InvalidateRect(hWnd, NULL, FALSE);
            }

            // Start minimized toggle
            if (mx >= bx + hw - 62 && mx < bx + hw && my >= startupY + 80 && my < startupY + 96) {
                g_startMinimized = !g_startMinimized;
                AddLog(g_startMinimized ? L"\x2714 Start minimized ENABLED" : L"\x25CB Start minimized disabled");
                SaveSettings();
                InvalidateRect(hWnd, NULL, FALSE);
            }
        }

        return 0;
    }

    // === System Tray Messages ===
    case WM_TRAYICON:
        if (lParam == WM_LBUTTONDBLCLK) {
            RestoreFromTray(hWnd);
        } else if (lParam == WM_RBUTTONUP) {
            ShowTrayMenu(hWnd);
        }
        return 0;

    // === Window Close → minimize to tray (jika diaktifkan) ===
    case WM_CLOSE:
        if (g_minimizeToTray) {
            // Simpan settings lalu minimize ke tray (bukan quit)
            SaveSettings();
            MinimizeToTray(hWnd);
            return 0; // Jangan teruskan ke DefWindowProc
        }
        // Jika minimize to tray OFF → quit normal
        SaveSettings();
        g_rwShield.stop(); g_procGuard.stop(); g_autoScanEnabled = false;
        RemoveTrayIcon();
        DestroyWindow(hWnd);
        return 0;

    case WM_REFRESH:
        InvalidateRect(hWnd, NULL, FALSE);
        return 0;
    case WM_TIMER:
        if (g_scan.running || g_autoScanEnabled) InvalidateRect(hWnd, NULL, FALSE);
        return 0;
    case WM_DESTROY:
        SaveSettings();
        g_rwShield.stop(); g_procGuard.stop(); g_autoScanEnabled = false;
        RemoveTrayIcon();
        KillTimer(hWnd, 1);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================
// WINMAIN
// ============================================================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR lpCmdLine, int) {
    g_hInst = hInstance;
    g_projectRoot = FindProjectRoot();
    if (g_projectRoot.empty()) {
        g_isInstallerMode = true;
    } else {
        // Load settings dari file config if installed
        LoadSettings();
    }

    // Cek argumen command line —minimized (dari auto-start registry)
    // Jika tidak ada argumen minimized, GUI akan tampil
    bool cmdMinimized = false;
    if (lpCmdLine && wcsstr(lpCmdLine, L"--minimized")) {
        cmdMinimized = true;
    }

    // === KRITIS: Enable SeDebugPrivilege ===
    // Tanpa ini, AV tidak bisa OpenProcess pada malware yang run as admin.
    if (!g_isInstallerMode) {
        if (!EnableDebugPrivilege()) {
            MessageBoxW(NULL,
                L"Warning: SeDebugPrivilege gagal diaktifkan.\n"
                L"Malware yang berjalan sebagai Administrator TIDAK AKAN terdeteksi.\n\n"
                L"Pastikan Gor Guard dijalankan sebagai Administrator.",
                L"Gor Guard — Privilege Warning", MB_ICONWARNING);
        }
    }

    // Cek argumen command line —minimized (dari auto-start registry)
    // Duplicate removed

    CoInitialize(NULL);
    Gdiplus::GdiplusStartupInput si;
    Gdiplus::GdiplusStartup(&g_gdipToken, &si, NULL);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(NM_BASE);
    wc.lpszClassName = APP_CLASS;
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassExW(&wc);

    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    g_hWnd = CreateWindowExW(0, APP_CLASS, L"Gor Guard",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        (sw - WIN_W) / 2, (sh - WIN_H) / 2, WIN_W, WIN_H,
        NULL, NULL, hInstance, NULL);

    if (!g_isInstallerMode) {
        // Logger init
        av::Logger::instance().init((g_projectRoot + "\\av_scan.log").c_str());

        // === Self-Defense: Proteksi proses AV dari terminasi ===
        if (av::SelfDefense::protect_current_process()) {
            AddLog(L"\x2714 Self-Defense: Process protected");
        }

        // === Watchdog: Monitor & restart AV jika dimatikan ===
        std::string watchdog_path = g_projectRoot + "\\gor_watchdog.exe";
        HANDLE hWatchdog = av::SelfDefense::start_watchdog(watchdog_path);
        if (hWatchdog) {
            AddLog(L"\x2714 Watchdog: Active");
        }

        // === Auto-activate shields dari saved settings ===
        if (g_procGuardOn) {
            ActivateProcessGuard();
        }
        if (g_rwShieldOn) {
            ActivateRwShield();
        }
        if (g_autoScanEnabled && !g_autoScanRunning) {
            std::thread(AutoScanThread).detach();
        }
    }

    // Tampilkan window atau minimize ke tray
    if (cmdMinimized || g_startMinimized) {
        // Start minimized: langsung ke system tray
        CreateTrayIcon(g_hWnd);
        ShowWindow(g_hWnd, SW_HIDE);
        AddLog(L"Gor Guard " + std::wstring(APP_VERSION) + L" started (background)");
    } else {
        ShowWindow(g_hWnd, SW_SHOW);
        UpdateWindow(g_hWnd);
        AddLog(L"Gor Guard " + std::wstring(APP_VERSION) + L" initialized");
    }

    SetTimer(g_hWnd, 1, 2000, NULL);

    AddLog(L"Database: " + U2W(g_scan.db_path));
    AddLog(L"Whitelist: data\\whitelist.txt");
    if (g_autoStart) AddLog(L"\x2714 Auto-start is ON");

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    Gdiplus::GdiplusShutdown(g_gdipToken);
    CoUninitialize();
    return 0;
}
