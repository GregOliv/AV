#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <chrono>

namespace av {

enum class LogLevel {
    INFO,
    WARNING,
    ERR,
    CRITICAL
};

class Logger {
public:
    static Logger& instance();

    // Initialize logger with file path
    bool init(const std::string& log_file_path);

    // Log methods — no sensitive data (passwords, tokens) allowed in messages
    void info(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    void critical(const std::string& message);

    // Cleanup
    void shutdown();

private:
    Logger() = default;
    ~Logger();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void log(LogLevel level, const std::string& message);
    std::string level_to_string(LogLevel level) const;
    std::string get_timestamp() const;

    std::ofstream m_file;
    std::mutex m_mutex;
    bool m_initialized = false;
};

} // namespace av
