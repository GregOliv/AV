#pragma once

#include <string>
#include <vector>
#include <functional>
#include <atomic>

namespace av {

using FileCallback = std::function<void(const std::string& path, uintmax_t size)>;

class FileWalker {
public:
    FileWalker();
    ~FileWalker();

    void set_max_file_size(uintmax_t max_bytes);
    void set_skip_extensions(const std::vector<std::string>& extensions);
    void set_cancel_flag(std::atomic<bool>* flag) { m_cancel = flag; }

    // Exclude specific absolute paths from walking
    void add_exclude_path(const std::string& path);
    void clear_exclude_paths();

    size_t walk(const std::string& root_path, FileCallback callback) const;

private:
    uintmax_t m_max_file_size = 100 * 1024 * 1024;
    std::vector<std::string> m_skip_extensions;
    std::vector<std::string> m_exclude_paths;
    std::atomic<bool>* m_cancel = nullptr;

    bool should_skip(const std::string& extension) const;
    bool should_skip_dir(const std::string& dir_name) const;
    bool is_excluded_path(const std::string& path) const;
};

} // namespace av
