#include "scanner/scanner.h"
#include "utils/logger.h"

#include <iostream>
#include <string>
#include <filesystem>
#include <iomanip>

namespace fs = std::filesystem;

void print_banner() {
    std::cout << R"(
    ___   _    __  ___
   /   | | |  / / / _ \  ___ ___ __ _ _ __  _ __   ___ _ __
  / /| | | | / / / /_\ \/ __/ __/ _` | '_ \| '_ \ / _ \ '__|
 / ___ | |/ / / /  _  |\__ \__ \ (_| | | | | | | |  __/ |
/_/  |_|___/_/  \_/ \_/|___/___/\__,_|_| |_|_| |_|\___|_|

  Hash-Based Antivirus Scanner v1.0.0
  Educational Purpose Only
)" << "\n";
}

void print_usage(const char* program_name) {
    std::cout << "Usage:\n"
              << "  " << program_name << " --scan <path> --db <hashdb.txt> [options]\n\n"
              << "Options:\n"
              << "  --scan <path>          Path to scan (file or directory)\n"
              << "  --db <file>            Path to hash database file\n"
              << "  --quarantine <path>    Quarantine directory (default: data/quarantine)\n"
              << "  --auto-quarantine      Automatically quarantine detected threats\n"
              << "  --max-size <MB>        Max file size to scan in MB (default: 100)\n"
              << "  --log <file>           Log file path (default: av_scan.log)\n"
              << "  --help                 Show this help message\n\n"
              << "Examples:\n"
              << "  " << program_name << " --scan C:\\Downloads --db data\\hashdb.txt\n"
              << "  " << program_name << " --scan D:\\ --db data\\hashdb.txt --auto-quarantine\n";
}

struct CLIOptions {
    std::string scan_path;
    std::string db_path;
    std::string quarantine_path = "data\\quarantine";
    std::string log_path = "av_scan.log";
    bool auto_quarantine = false;
    uintmax_t max_size_mb = 100;
    bool show_help = false;
};

CLIOptions parse_args(int argc, char* argv[]) {
    CLIOptions opts;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            opts.show_help = true;
        } else if (arg == "--scan" && i + 1 < argc) {
            opts.scan_path = argv[++i];
        } else if (arg == "--db" && i + 1 < argc) {
            opts.db_path = argv[++i];
        } else if (arg == "--quarantine" && i + 1 < argc) {
            opts.quarantine_path = argv[++i];
        } else if (arg == "--auto-quarantine") {
            opts.auto_quarantine = true;
        } else if (arg == "--max-size" && i + 1 < argc) {
            opts.max_size_mb = std::stoull(argv[++i]);
        } else if (arg == "--log" && i + 1 < argc) {
            opts.log_path = argv[++i];
        }
    }

    return opts;
}

void print_progress_bar(size_t current, size_t total) {
    if (total == 0) return;
    int bar_width = 40;
    float progress = static_cast<float>(current) / static_cast<float>(total);
    int filled = static_cast<int>(progress * bar_width);

    std::cout << "\r[";
    for (int i = 0; i < bar_width; ++i) {
        if (i < filled) std::cout << "█";
        else std::cout << "░";
    }
    std::cout << "] " << std::fixed << std::setprecision(1) << (progress * 100.0f) << "% "
              << "(" << current << "/" << total << ")" << std::flush;
}

int main(int argc, char* argv[]) {
    print_banner();

    CLIOptions opts = parse_args(argc, argv);

    if (opts.show_help || opts.scan_path.empty() || opts.db_path.empty()) {
        print_usage(argv[0]);
        if (argc <= 1) { // Asumsi dijalankan via double-click
            std::cout << "\n[!] Tekan ENTER untuk keluar...";
            std::cin.get();
        }
        return opts.show_help ? 0 : 1;
    }

    // Initialize logger
    auto& logger = av::Logger::instance();
    logger.init(opts.log_path);

    logger.info("=== AV Scanner Started ===");
    logger.info("Target: " + opts.scan_path);
    logger.info("Database: " + opts.db_path);

    // Initialize scanner
    av::Scanner scanner;

    // Load database
    std::cout << "[*] Loading hash database...\n";
    if (!scanner.load_database(opts.db_path)) {
        std::cerr << "[!] Failed to load hash database: " << opts.db_path << "\n";
        std::cerr << "    Make sure the file exists and contains valid SHA-256 hashes.\n";
        return 1;
    }

    // Configure
    scanner.set_max_file_size(opts.max_size_mb * 1024 * 1024);

    // Initialize quarantine
    if (opts.auto_quarantine) {
        std::cout << "[*] Initializing quarantine at: " << opts.quarantine_path << "\n";
        if (!scanner.init_quarantine(opts.quarantine_path)) {
            std::cerr << "[!] Failed to initialize quarantine directory\n";
            return 1;
        }
        scanner.set_auto_quarantine(true);
    }

    // Set progress callback
    size_t threats_so_far = 0;
    scanner.set_progress_callback([&threats_so_far](const av::ScanResult& result, size_t current, size_t total) {
        if (result.is_threat) {
            ++threats_so_far;
            // Clear progress bar line and print threat
            std::cout << "\r\033[K"; // Clear line
            std::cout << "[!] THREAT: " << result.file_path << "\n";
            std::cout << "    Hash: " << result.hash << "\n";
            std::cout << "    Type: " << result.threat_name << "\n";
        }
        print_progress_bar(current, total);
    });

    // Run scan
    std::cout << "[*] Scanning: " << opts.scan_path << "\n\n";
    av::ScanStats stats = scanner.scan(opts.scan_path);

    // Clear progress bar and print results
    std::cout << "\r\033[K\n";
    std::cout << "╔══════════════════════════════════════════╗\n";
    std::cout << "║          SCAN RESULTS SUMMARY            ║\n";
    std::cout << "╠══════════════════════════════════════════╣\n";
    std::cout << "║  Files scanned:    " << std::setw(8) << stats.scanned_files << "              ║\n";
    std::cout << "║  Threats found:    " << std::setw(8) << stats.threats_found << "              ║\n";
    std::cout << "║  Errors:           " << std::setw(8) << stats.errors << "              ║\n";
    std::cout << "║  Quarantined:      " << std::setw(8) << stats.quarantined << "              ║\n";
    std::cout << "║  Time elapsed:     " << std::fixed << std::setprecision(2) << std::setw(6) << stats.elapsed_seconds << "s" << "             ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n\n";

    if (stats.threats_found > 0) {
        std::cout << "[!] " << stats.threats_found << " threat(s) detected!\n";
        if (!opts.auto_quarantine) {
            std::cout << "    Run with --auto-quarantine to isolate detected threats.\n";
        }
        return 2; // Exit code 2 = threats found
    }

    std::cout << "[+] No threats detected. System appears clean.\n";
    return 0;
}
