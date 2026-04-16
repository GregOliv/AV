#include "scanner/file_walker.h"
#include "utils/logger.h"

#include <filesystem>
#include <algorithm>
#include <windows.h>

namespace fs = std::filesystem;

namespace av {

FileWalker::FileWalker() = default;
FileWalker::~FileWalker() = default;

void FileWalker::set_max_file_size(uintmax_t max_bytes) {
    m_max_file_size = max_bytes;
}

void FileWalker::set_skip_extensions(const std::vector<std::string>& extensions) {
    m_skip_extensions = extensions;
}

bool FileWalker::should_skip(const std::string& extension) const {
    for (const auto& skip_ext : m_skip_extensions) {
        std::string ext_lower = extension;
        std::string skip_lower = skip_ext;
        std::transform(ext_lower.begin(), ext_lower.end(), ext_lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(skip_lower.begin(), skip_lower.end(), skip_lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (ext_lower == skip_lower) return true;
    }
    return false;
}

bool FileWalker::should_skip_dir(const std::string& dir_name) const {
    // Folder sistem Windows yang menyebabkan crash/hang/infinite loop
    static const char* skip_dirs[] = {
        "System Volume Information",
        "$Recycle.Bin",
        "$RECYCLE.BIN",
        "$WinREAgent",
        "$SysReset",
        "Recovery",
        "PerfLogs",
        "Config.Msi",
        "MSOCache",
        "WindowsApps",      // UWP apps — locked
        "WinSxS",           // sering sangat besar + permission denied
        "servicing",
        "assembly",
        "Installer",        // C:\Windows\Installer - biasanya locked
    };

    for (const auto& sd : skip_dirs) {
        if (dir_name == sd) return true;
    }
    if (!dir_name.empty() && dir_name[0] == '$') return true;
    return false;
}

void FileWalker::add_exclude_path(const std::string& path) {
    // Normalize to lowercase for case-insensitive comparison on Windows
    std::string normalized = path;
    std::replace(normalized.begin(), normalized.end(), '/', '\\');
    // Remove trailing backslash
    while (!normalized.empty() && normalized.back() == '\\') normalized.pop_back();
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    m_exclude_paths.push_back(normalized);
}

void FileWalker::clear_exclude_paths() {
    m_exclude_paths.clear();
}

bool FileWalker::is_excluded_path(const std::string& path) const {
    if (m_exclude_paths.empty()) return false;
    std::string normalized = path;
    std::replace(normalized.begin(), normalized.end(), '/', '\\');
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const auto& ex : m_exclude_paths) {
        // Check if path starts with excluded path
        if (normalized.length() >= ex.length() &&
            normalized.compare(0, ex.length(), ex) == 0) {
            // Exact match or path continues with backslash
            if (normalized.length() == ex.length() || normalized[ex.length()] == '\\') {
                return true;
            }
        }
    }
    return false;
}

size_t FileWalker::walk(const std::string& root_path, FileCallback callback) const {
    size_t file_count = 0;

    // Validate path
    std::error_code ec;
    if (!fs::exists(root_path, ec) || ec) {
        Logger::instance().error("Path does not exist: " + root_path);
        return 0;
    }

    // Handle single file
    if (fs::is_regular_file(root_path, ec)) {
        auto file_size = fs::file_size(root_path, ec);
        if (!ec && file_size <= m_max_file_size) {
            auto ext = fs::path(root_path).extension().string();
            if (!should_skip(ext)) {
                callback(root_path, file_size);
                return 1;
            }
        }
        return 0;
    }

    // Recursive directory iteration — ULTRA ROBUST untuk scan drive penuh
    try {
        auto it = fs::recursive_directory_iterator(
            root_path,
            fs::directory_options::skip_permission_denied,
            ec);

        if (ec) {
            Logger::instance().warning("Cannot open directory: " + root_path + " (" + ec.message() + ")");
            return 0;
        }

        for (; it != fs::recursive_directory_iterator(); ) {
            // Cancellation check
            if (m_cancel && m_cancel->load()) return file_count;

            try {
                // Ambil entry saat ini
                const auto& entry = *it;

                // Cek apakah ini directory yang harus di-skip
                if (entry.is_directory(ec)) {
                    std::string dirName = entry.path().filename().string();
                    std::string fullPath = entry.path().string();
                    if (should_skip_dir(dirName) || is_excluded_path(fullPath)) {
                        it.disable_recursion_pending();
                        it.increment(ec);
                        if (ec) { ec.clear(); }
                        continue;
                    }
                }

                // Skip non-regular files
                if (!entry.is_regular_file(ec) || ec) {
                    it.increment(ec);
                    if (ec) ec.clear();
                    continue;
                }

                auto file_size = entry.file_size(ec);
                if (ec) {
                    it.increment(ec);
                    if (ec) ec.clear();
                    continue;
                }

                // Skip files exceeding max size
                if (file_size > m_max_file_size) {
                    it.increment(ec);
                    if (ec) ec.clear();
                    continue;
                }

                // Skip excluded extensions
                auto ext = entry.path().extension().string();
                if (should_skip(ext)) {
                    it.increment(ec);
                    if (ec) ec.clear();
                    continue;
                }

                // Safe callback — wrapped in try/catch
                try {
                    callback(entry.path().string(), file_size);
                } catch (...) {
                    // Callback gagal untuk file ini, lanjutkan
                }
                ++file_count;

                // Increment iterator
                it.increment(ec);
                if (ec) {
                    ec.clear();
                    continue;
                }

            } catch (const std::exception&) {
                // Exception saat akses entry — skip dan lanjutkan
                try {
                    it.increment(ec);
                    if (ec) ec.clear();
                } catch (...) {
                    // Iterator rusak, hentikan
                    break;
                }
            } catch (...) {
                try {
                    it.increment(ec);
                    if (ec) ec.clear();
                } catch (...) {
                    break;
                }
            }
        }

    } catch (const std::exception& e) {
        Logger::instance().error("Walker exception: " + std::string(e.what()));
    } catch (...) {
        Logger::instance().error("Walker unknown exception");
    }

    return file_count;
}

} // namespace av
