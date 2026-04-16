#pragma once
#include "gui_common.h"
#include <string>
#include <gdiplus.h>

namespace av_gui {

// Wide string helpers
inline std::wstring U2W(const std::string& s) {
    if (s.empty()) return L"";
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(sz - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], sz);
    return w;
}
inline std::string W2U(const std::wstring& w) {
    if (w.empty()) return "";
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(sz - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
    return s;
}

// ===== Drawing Primitives =====
void NmText(HDC hdc, const std::wstring& text, int x, int y,
            COLORREF color, int size = 13, bool bold = false);

void NmRaised(HDC hdc, int x, int y, int w, int h, int r = 14, int depth = 5);
void NmInset(HDC hdc, int x, int y, int w, int h, int r = 10, int depth = 3);
void NmPressed(HDC hdc, int x, int y, int w, int h, int r = 10);
void NmFill(HDC hdc, int x, int y, int w, int h, int r, COLORREF color);
void NmAccentRaised(HDC hdc, int x, int y, int w, int h, int r, COLORREF accent);
void NmProgressBar(HDC hdc, int x, int y, int w, int h, int percent, COLORREF fillColor = NM_ACCENT);
void NmToggle(HDC hdc, int x, int y, bool on);
void NmIconCircle(HDC hdc, int x, int y, int size, COLORREF iconColor, const wchar_t* icon);

// Separator line
void NmSeparator(HDC hdc, int x, int y, int w);

// Scrollable log clipping
void NmBeginClip(HDC hdc, int x, int y, int w, int h);
void NmEndClip(HDC hdc);

// Browse dialog
std::wstring BrowseFolder(HWND parent);

} // namespace av_gui
