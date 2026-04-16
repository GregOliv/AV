// Simple test framework (no external dependency)
#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <cstdint>

#include "scanner/hash_calculator.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ(a, b, msg) \
    if ((a) == (b)) { \
        ++tests_passed; \
        std::cout << "  [PASS] " << msg << "\n"; \
    } else { \
        ++tests_failed; \
        std::cerr << "  [FAIL] " << msg << " (expected: " << (b) << ", got: " << (a) << ")\n"; \
    }

#define ASSERT_TRUE(expr, msg) \
    if (expr) { \
        ++tests_passed; \
        std::cout << "  [PASS] " << msg << "\n"; \
    } else { \
        ++tests_failed; \
        std::cerr << "  [FAIL] " << msg << "\n"; \
    }

#define ASSERT_FALSE(expr, msg) \
    if (!(expr)) { \
        ++tests_passed; \
        std::cout << "  [PASS] " << msg << "\n"; \
    } else { \
        ++tests_failed; \
        std::cerr << "  [FAIL] " << msg << "\n"; \
    }

void test_sha256_empty_input() {
    std::cout << "\n[TEST] SHA-256 empty input\n";
    av::HashCalculator calc;
    
    // SHA-256 of empty string = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::string hash = calc.sha256_bytes(nullptr, 0);
    ASSERT_EQ(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              "SHA-256 of empty input matches known value");
}

void test_sha256_known_string() {
    std::cout << "\n[TEST] SHA-256 known string\n";
    av::HashCalculator calc;
    
    // SHA-256 of "hello" = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    const std::string input = "hello";
    std::string hash = calc.sha256_bytes(
        reinterpret_cast<const uint8_t*>(input.data()), input.size());
    ASSERT_EQ(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
              "SHA-256 of 'hello' matches known value");
}

void test_sha256_nonexistent_file() {
    std::cout << "\n[TEST] SHA-256 nonexistent file\n";
    av::HashCalculator calc;
    
    std::string hash = calc.sha256_file("nonexistent_file_xyz_123.txt");
    ASSERT_TRUE(hash.empty(), "Returns empty string for nonexistent file");
}

// Entry point from test_scanner.cpp (forward declaration)
extern void run_hash_calculator_tests();

void run_hash_calculator_tests() {
    std::cout << "\n=== Hash Calculator Tests ===\n";
    test_sha256_empty_input();
    test_sha256_known_string();
    test_sha256_nonexistent_file();
}
