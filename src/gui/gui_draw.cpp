#include "gui/gui_draw.h"
#include <shlobj.h>

namespace av_gui {

static HFONT MakeFont(int size, bool bold) {
    return CreateFontW(-size, 0, 0, 0, bold ? FW_SEMIBOLD : FW_NORMAL,
                       FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH,
                       L"Segoe UI");
}

static void RRFill(HDC hdc, int x, int y, int w, int h, int r, COLORREF fill) {
    HBRUSH br = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, fill);
    HBRUSH ob = (HBRUSH)SelectObject(hdc, br);
    HPEN op = (HPEN)SelectObject(hdc, pen);
    RoundRect(hdc, x, y, x + w, y + h, r * 2, r * 2);
    SelectObject(hdc, ob); SelectObject(hdc, op);
    DeleteObject(br); DeleteObject(pen);
}

void NmText(HDC hdc, const std::wstring& text, int x, int y,
            COLORREF color, int size, bool bold) {
    HFONT font = MakeFont(size, bold);
    HFONT old = (HFONT)SelectObject(hdc, font);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, color);
    TextOutW(hdc, x, y, text.c_str(), static_cast<int>(text.length()));
    SelectObject(hdc, old);
    DeleteObject(font);
}

void NmRaised(HDC hdc, int x, int y, int w, int h, int r, int depth) {
    // Dark shadow bottom-right
    RRFill(hdc, x + depth, y + depth, w, h, r, NM_SHADOW_DK);
    // Light highlight top-left
    RRFill(hdc, x - depth/2, y - depth/2, w, h, r, NM_SHADOW_LT);
    // Face
    RRFill(hdc, x, y, w, h, r, NM_CARD);
}

void NmInset(HDC hdc, int x, int y, int w, int h, int r, int depth) {
    RRFill(hdc, x, y, w, h, r, NM_SHADOW_DK);
    RRFill(hdc, x + 1, y + 1, w - 2, h - 2, r, NM_INSET_LT);
    RRFill(hdc, x + depth, y + depth, w - depth*2, h - depth*2, r, NM_INSET_BG);
}

void NmPressed(HDC hdc, int x, int y, int w, int h, int r) {
    NmInset(hdc, x, y, w, h, r, 3);
}

void NmFill(HDC hdc, int x, int y, int w, int h, int r, COLORREF color) {
    RRFill(hdc, x, y, w, h, r, color);
}

void NmAccentRaised(HDC hdc, int x, int y, int w, int h, int r, COLORREF accent) {
    COLORREF dk = RGB(
        GetRValue(accent) * 6 / 10,
        GetGValue(accent) * 6 / 10,
        GetBValue(accent) * 6 / 10);
    RRFill(hdc, x + 3, y + 3, w, h, r, dk);
    RRFill(hdc, x, y, w, h, r, accent);
}

void NmProgressBar(HDC hdc, int x, int y, int w, int h, int percent, COLORREF fillColor) {
    NmInset(hdc, x, y, w, h, h / 2, 2);
    if (percent > 0) {
        int fw = (w - 6) * percent / 100;
        if (fw < h - 4) fw = h - 4;
        if (fw > w - 6) fw = w - 6;
        RRFill(hdc, x + 3, y + 3, fw, h - 6, (h - 6) / 2, fillColor);
    }
}

void NmToggle(HDC hdc, int x, int y, bool on) {
    int w = 48, h = 24;
    if (on) {
        NmAccentRaised(hdc, x, y, w, h, h / 2, NM_SUCCESS);
    } else {
        NmInset(hdc, x, y, w, h, h / 2, 2);
    }
    int knobX = on ? x + w - h + 2 : x + 2;
    int ks = h - 4;
    RRFill(hdc, knobX + 1, y + 3, ks, ks, ks / 2, NM_SHADOW_DK);
    RRFill(hdc, knobX, y + 2, ks, ks, ks / 2, RGB(210, 215, 225));
}

void NmIconCircle(HDC hdc, int x, int y, int size, COLORREF iconColor, const wchar_t* icon) {
    RRFill(hdc, x + 2, y + 2, size, size, size / 2, NM_SHADOW_DK);
    RRFill(hdc, x - 1, y - 1, size, size, size / 2, NM_SHADOW_LT);
    RRFill(hdc, x, y, size, size, size / 2, NM_CARD);
    NmText(hdc, icon, x + size / 4, y + size / 6, iconColor, size / 2 + 1, true);
}

void NmSeparator(HDC hdc, int x, int y, int w) {
    RRFill(hdc, x, y, w, 1, 0, NM_SHADOW_DK);
    RRFill(hdc, x, y + 1, w, 1, 0, NM_SHADOW_LT);
}

void NmBeginClip(HDC hdc, int x, int y, int w, int h) {
    HRGN rgn = CreateRectRgn(x, y, x + w, y + h);
    SelectClipRgn(hdc, rgn);
    DeleteObject(rgn);
}

void NmEndClip(HDC hdc) {
    SelectClipRgn(hdc, NULL);
}

std::wstring BrowseFolder(HWND parent) {
    wchar_t path[MAX_PATH] = {};
    BROWSEINFOW bi = {};
    bi.hwndOwner = parent;
    bi.lpszTitle = L"Select folder to scan";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        SHGetPathFromIDListW(pidl, path);
        CoTaskMemFree(pidl);
    }
    return path;
}

} // namespace av_gui
