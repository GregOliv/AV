#include "scanner/pe_analyzer.h"
#include "utils/logger.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include <fstream>

namespace av {

PE_Info PEAnalyzer::analyze(const std::string& filepath) {
    PE_Info info;

#ifdef _WIN32
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) return info;

    // Dapatkan ukuran file untuk validasi bound checking
    file.seekg(0, std::ios::end);
    std::streamsize filesize = file.tellg();
    file.seekg(0, std::ios::beg);

    if (filesize < sizeof(IMAGE_DOS_HEADER)) {
        return info; // File terlalu kecil untuk menjadi PE
    }

    IMAGE_DOS_HEADER dos_header;
    if (!file.read(reinterpret_cast<char*>(&dos_header), sizeof(dos_header))) {
        return info;
    }

    // Cek magic number MZ
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        return info;
    }

    // VALIDASI KRITIKAL: Cegah Out-of-Bound Read / Buffer Overflow dari malformed PE
    if (dos_header.e_lfanew <= 0 || 
        dos_header.e_lfanew >= (filesize - static_cast<std::streamsize>(sizeof(IMAGE_NT_HEADERS32)))) {
        info.suspicious_indicators.push_back("Invalid PE Header Offset (e_lfanew)");
        return info;
    }

    file.seekg(dos_header.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS32 nt_headers;
    if (!file.read(reinterpret_cast<char*>(&nt_headers), sizeof(nt_headers))) {
        return info;
    }

    // Cek signature PE\0\0
    if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
        return info;
    }

    info.is_valid_pe = true;
    info.machine = nt_headers.FileHeader.Machine;
    info.sections_count = nt_headers.FileHeader.NumberOfSections;
    info.is_executable = (nt_headers.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0;
    info.is_dll = (nt_headers.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    // Analisis anomali sederhana (Heuristic awal)
    if (info.sections_count == 0 || info.sections_count > 15) {
        // Normalnya software biasa tidak punya lebih dari 8-10 section.
        // Jika sangat banyak, bisa jadi ulah packer/crypter malware.
        info.suspicious_indicators.push_back("Abnormal number of sections (" + std::to_string(info.sections_count) + ")");
    }
#else
    Logger::instance().warning("PE Analysis is only supported on Windows.");
#endif

    return info;
}

} // namespace av
