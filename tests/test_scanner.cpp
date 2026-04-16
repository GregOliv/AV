#include <iostream>
#include "utils/logger.h"

// Forward declarations from other test files
extern void run_hash_calculator_tests();
extern void run_hash_database_tests();

int main() {
    std::cout << "=== AV Scanner Test Suite ===\n";

    // Initialize logger for tests
    av::Logger::instance().init("av_test.log");

    // Run all test suites
    run_hash_calculator_tests();
    run_hash_database_tests();

    std::cout << "\n=== All Test Suites Complete ===\n";

    av::Logger::instance().shutdown();
    return 0;
}
