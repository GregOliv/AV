#pragma once

#include <string>

namespace av {

class QuarantineManager {
public:
    QuarantineManager();
    ~QuarantineManager();

    // Initialize quarantine folder
    // Creates the folder if it doesn't exist
    bool init(const std::string& quarantine_path);

    // Move a file to quarantine
    // Returns true if successful
    // The file is renamed with .quarantined extension and a metadata file is created
    bool quarantine_file(const std::string& file_path, const std::string& reason);

    // Restore a file from quarantine
    bool restore_file(const std::string& quarantined_name);

    // Get quarantine directory path
    const std::string& get_path() const;

    // Count quarantined files
    size_t count() const;

private:
    std::string m_quarantine_path;
    bool m_initialized = false;

    // Generate a safe filename for quarantine
    std::string generate_quarantine_name(const std::string& original_path) const;

    // Write metadata file alongside quarantined file
    bool write_metadata(const std::string& quarantine_name,
                       const std::string& original_path,
                       const std::string& reason) const;
};

} // namespace av
