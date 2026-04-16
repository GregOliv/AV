#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>

#include "database/hash_database.h"

static int tests_passed = 0;
static int tests_failed = 0;

// Reuse from test_hash_calculator.cpp would cause duplicates, so define locally
#define DB_ASSERT_EQ(a, b, msg) \
    if ((a) == (b)) { \
        ++tests_passed; \
        std::cout << "  [PASS] " << msg << "\n"; \
    } else { \
        ++tests_failed; \
        std::cerr << "  [FAIL] " << msg << "\n"; \
    }

#define DB_ASSERT_TRUE(expr, msg) \
    if (expr) { \
        ++tests_passed; \
        std::cout << "  [PASS] " << msg << "\n"; \
    } else { \
        ++tests_failed; \
        std::cerr << "  [FAIL] " << msg << "\n"; \
    }

#define DB_ASSERT_FALSE(expr, msg) \
    if (!(expr)) { \
        ++tests_passed; \
        std::cout << "  [PASS] " << msg << "\n"; \
    } else { \
        ++tests_failed; \
        std::cerr << "  [FAIL] " << msg << "\n"; \
    }

namespace fs = std::filesystem;

static const std::string TEST_DB_PATH = "test_hashdb_tmp.txt";

void create_test_db() {
    std::ofstream file(TEST_DB_PATH);
    file << "# Test hash database\n";
    file << "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n";
    file << "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n";
    file << "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890\n"; // uppercase
    file << "invalid_hash_here\n"; // should be skipped
    file << "\n"; // empty line
    file << "# comment line\n";
    file.close();
}

void cleanup_test_db() {
    std::error_code ec;
    fs::remove(TEST_DB_PATH, ec);
}

void test_load_database() {
    std::cout << "\n[TEST] Load hash database\n";
    av::HashDatabase db;
    create_test_db();

    size_t loaded = db.load(TEST_DB_PATH);
    DB_ASSERT_EQ(loaded, size_t(3), "Loaded 3 valid hashes (2 lowercase + 1 uppercase)");

    cleanup_test_db();
}

void test_contains_hash() {
    std::cout << "\n[TEST] Contains hash lookup\n";
    av::HashDatabase db;
    create_test_db();
    db.load(TEST_DB_PATH);

    DB_ASSERT_TRUE(db.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                   "Known hash found in database");

    DB_ASSERT_TRUE(db.contains("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
                   "Case-insensitive lookup works");

    DB_ASSERT_FALSE(db.contains("0000000000000000000000000000000000000000000000000000000000000000"),
                    "Unknown hash not found in database");

    cleanup_test_db();
}

void test_load_nonexistent() {
    std::cout << "\n[TEST] Load nonexistent database\n";
    av::HashDatabase db;
    size_t loaded = db.load("nonexistent_db_xyz.txt");
    DB_ASSERT_EQ(loaded, size_t(0), "Returns 0 for nonexistent file");
}

void test_integrity_check() {
    std::cout << "\n[TEST] Database integrity check\n";
    av::HashDatabase db;
    create_test_db();
    db.load(TEST_DB_PATH);

    DB_ASSERT_TRUE(db.verify_integrity(), "Integrity check passes");
    cleanup_test_db();
}

extern void run_hash_database_tests();

void run_hash_database_tests() {
    std::cout << "\n=== Hash Database Tests ===\n";
    tests_passed = 0;
    tests_failed = 0;

    test_load_database();
    test_contains_hash();
    test_load_nonexistent();
    test_integrity_check();

    std::cout << "\nDatabase tests: " << tests_passed << " passed, " << tests_failed << " failed\n";
}
