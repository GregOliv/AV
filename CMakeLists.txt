cmake_minimum_required(VERSION 3.20)
project(AVScanner VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Security flags
if(MSVC)
    add_compile_options(/W4 /WX /GS /guard:cf)
    add_link_options(/DYNAMICBASE /NXCOMPAT /guard:cf)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -fstack-protector-strong)
endif()

# Shared scanner source files
set(SCANNER_SOURCES
    src/scanner/scanner.cpp
    src/scanner/file_walker.cpp
    src/scanner/hash_calculator.cpp
    src/scanner/pe_analyzer.cpp
    src/scanner/signature_matcher.cpp
    src/database/hash_database.cpp
    src/quarantine/quarantine.cpp
    src/protection/ransomware_shield.cpp
    src/protection/process_guard.cpp
    src/utils/logger.cpp
)

# CLI executable
add_executable(gor_scanner src/main.cpp ${SCANNER_SOURCES})
target_include_directories(gor_scanner PRIVATE ${CMAKE_SOURCE_DIR}/src)

# GUI executable (Windows native, no console)
if(WIN32)
    add_executable(gor WIN32
        src/gui_main.cpp
        src/gui/gui_draw.cpp
        ${SCANNER_SOURCES}
    )
    target_include_directories(gor PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(gor PRIVATE bcrypt gdiplus ole32 shell32 advapi32)

    # UAC Manifest: Antivirus WAJIB berjalan sebagai Administrator
    # Tanpa ini, OpenProcess() gagal pada proses elevated → malware tidak terdeteksi
    set_target_properties(gor PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )

    # Watchdog executable — self-defense: monitor & restart AV jika dimatikan
    add_executable(gor_watchdog WIN32
        src/watchdog_main.cpp
    )
    target_include_directories(gor_watchdog PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(gor_watchdog PRIVATE advapi32)
    set_target_properties(gor_watchdog PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif()

# Link Windows crypto library
if(WIN32)
    target_link_libraries(gor_scanner PRIVATE bcrypt advapi32)
endif()

# Tests
enable_testing()
add_executable(gor_tests
    tests/test_hash_calculator.cpp
    tests/test_hash_database.cpp
    tests/test_scanner.cpp
    ${SCANNER_SOURCES}
)
target_include_directories(gor_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
if(WIN32)
    target_link_libraries(gor_tests PRIVATE bcrypt advapi32)
endif()
add_test(NAME GorTests COMMAND gor_tests)
