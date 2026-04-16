// ============================================================
// Gor Guard Watchdog — Self-Defense Process
// ============================================================
// Mutual monitoring: watchdog memantau proses utama AV.
// Jika AV dimatikan (oleh malware atau taskkill), watchdog restart AV.
// AV juga memantau watchdog — jika watchdog mati, AV restart watchdog.
//
// Penggunaan: gor_watchdog.exe --watch <AV_PID>
// ============================================================

#include <windows.h>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

// Cari path gor.exe (di folder yang sama dengan watchdog)
static std::string FindAVPath() {
    char buf[MAX_PATH];
    GetModuleFileNameA(NULL, buf, MAX_PATH);
    fs::path dir = fs::path(buf).parent_path();
    fs::path av = dir / "gor.exe";
    if (fs::exists(av)) return av.string();
    return "";
}

// Restart AV process
static bool RestartAV(const std::string& av_path) {
    if (av_path.empty()) return false;

    std::string cmdline = "\"" + av_path + "\"";

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (CreateProcessA(NULL, const_cast<char*>(cmdline.c_str()),
                       NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
    return false;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR lpCmdLine, int) {
    // Parse command line: --watch <PID>
    DWORD watchPid = 0;

    // Parse dari lpCmdLine
    if (lpCmdLine) {
        std::wstring cmd(lpCmdLine);
        auto pos = cmd.find(L"--watch ");
        if (pos != std::wstring::npos) {
            std::wstring pidStr = cmd.substr(pos + 8);
            try { watchPid = static_cast<DWORD>(std::stoul(pidStr)); } catch (...) {}
        }
    }

    if (watchPid == 0) {
        // Tidak ada PID yang di-watch — keluar
        return 1;
    }

    std::string av_path = FindAVPath();
    if (av_path.empty()) return 2;

    // Buka handle ke proses AV
    HANDLE hAVProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE, watchPid);
    if (!hAVProcess) {
        // Proses sudah mati — restart segera
        Sleep(2000); // Tunggu 2 detik agar tidak loop terlalu cepat
        RestartAV(av_path);
        return 0;
    }

    // === MAIN MONITORING LOOP ===
    // Tunggu sampai proses AV mati atau watchdog di-stop
    while (true) {
        // Tunggu max 5 detik, lalu cek ulang
        DWORD result = WaitForSingleObject(hAVProcess, 5000);

        if (result == WAIT_OBJECT_0) {
            // Proses AV MATI!
            CloseHandle(hAVProcess);

            // Cek apakah ini shutdown normal atau abnormal
            // Jika av_gui.exe sudah tidak ada di disk → normal uninstall, jangan restart
            if (!fs::exists(av_path)) return 0;

            // Tunggu sebentar untuk menghindari race condition
            Sleep(3000);

            // Restart AV
            if (RestartAV(av_path)) {
                // Berhasil restart — sekarang keluar
                // AV yang baru akan spawn watchdog baru
                return 0;
            }

            // Gagal restart — coba lagi setelah 10 detik
            Sleep(10000);
            RestartAV(av_path);
            return 0;
        }

        // WAIT_TIMEOUT — proses masih hidup, continue monitoring
        // Cek apakah proses masih benar-benar ada
        DWORD exitCode = 0;
        if (GetExitCodeProcess(hAVProcess, &exitCode) && exitCode != STILL_ACTIVE) {
            // Proses sudah exit tapi WaitForSingleObject belum trigger
            CloseHandle(hAVProcess);
            Sleep(3000);
            RestartAV(av_path);
            return 0;
        }
    }
}
