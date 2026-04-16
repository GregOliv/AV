#pragma once
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <gdiplus.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace av_gui {

// ============================================================
// DARK NEUMORPHISM COLOR PALETTE
// ============================================================
constexpr COLORREF NM_BASE      = RGB(28, 30, 38);
constexpr COLORREF NM_SURFACE   = RGB(34, 37, 46);
constexpr COLORREF NM_CARD      = RGB(38, 41, 52);
constexpr COLORREF NM_SHADOW_DK = RGB(16, 17, 22);
constexpr COLORREF NM_SHADOW_LT = RGB(50, 54, 65);
constexpr COLORREF NM_INSET_BG  = RGB(22, 24, 30);
constexpr COLORREF NM_INSET_LT  = RGB(32, 35, 44);

constexpr COLORREF NM_ACCENT    = RGB(88, 130, 240);
constexpr COLORREF NM_ACCENT2   = RGB(50, 190, 180);
constexpr COLORREF NM_DANGER    = RGB(235, 85, 85);
constexpr COLORREF NM_SUCCESS   = RGB(65, 195, 110);
constexpr COLORREF NM_WARN      = RGB(240, 180, 50);

constexpr COLORREF NM_TEXT      = RGB(220, 225, 235);
constexpr COLORREF NM_TEXT_SEC  = RGB(140, 148, 170);
constexpr COLORREF NM_TEXT_LT   = RGB(90, 96, 115);

constexpr COLORREF NM_SIDEBAR   = RGB(24, 26, 33);
constexpr COLORREF NM_SIDEBAR_ACTIVE = RGB(38, 42, 58);

// Tab IDs
enum Tab { TAB_DASHBOARD = 0, TAB_SCAN, TAB_QUARANTINE, TAB_RANSOMWARE, TAB_SETTINGS, TAB_COUNT };

// Scan state
struct ScanState {
    std::atomic<bool> running{false};
    std::atomic<int> progress{0};
    std::atomic<int> total_files{0};
    std::atomic<int> scanned{0};
    std::atomic<int> threats{0};
    std::atomic<int> phase{1};
    double start_time_ms{0};
    std::string current_file;
    std::string scan_path;
    std::string db_path = "data\\hashdb.txt";
    std::string q_path  = "data\\quarantine";
    bool auto_quarantine = true;
    int max_size_mb = 100;
};

} // namespace av_gui
