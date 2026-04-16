#include "scanner/hash_calculator.h"
#include "utils/logger.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#endif

namespace av {

HashCalculator::HashCalculator() = default;
HashCalculator::~HashCalculator() = default;

std::string HashCalculator::bytes_to_hex(const uint8_t* data, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

#ifdef _WIN32

std::string HashCalculator::sha256_file(const std::string& file_path) const {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status;
    std::string result;

    // Open algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) {
        Logger::instance().error("BCryptOpenAlgorithmProvider failed for file: " + file_path);
        return "";
    }

    // Get hash object size
    DWORD hashObjSize = 0;
    DWORD dataSize = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PBYTE>(&hashObjSize), sizeof(DWORD), &dataSize, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Logger::instance().error("BCryptGetProperty failed for file: " + file_path);
        return "";
    }

    // Get hash length
    DWORD hashLength = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PBYTE>(&hashLength), sizeof(DWORD), &dataSize, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Logger::instance().error("BCryptGetProperty (hash length) failed for file: " + file_path);
        return "";
    }

    // Allocate hash object
    auto hashObj = std::make_unique<uint8_t[]>(hashObjSize);

    // Create hash
    status = BCryptCreateHash(hAlg, &hHash, hashObj.get(), hashObjSize, nullptr, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Logger::instance().error("BCryptCreateHash failed for file: " + file_path);
        return "";
    }

    // Open file and read in chunks
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Logger::instance().warning("Cannot open file: " + file_path);
        return "";
    }

    uint8_t buffer[READ_BUFFER_SIZE];
    while (file.good()) {
        file.read(reinterpret_cast<char*>(buffer), READ_BUFFER_SIZE);
        auto bytesRead = file.gcount();
        if (bytesRead > 0) {
            status = BCryptHashData(hHash, buffer, static_cast<ULONG>(bytesRead), 0);
            if (!NT_SUCCESS(status)) {
                BCryptDestroyHash(hHash);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                Logger::instance().error("BCryptHashData failed for file: " + file_path);
                return "";
            }
        }
    }

    // Finalize hash
    auto hashValue = std::make_unique<uint8_t[]>(hashLength);
    status = BCryptFinishHash(hHash, hashValue.get(), hashLength, 0);
    if (NT_SUCCESS(status)) {
        result = bytes_to_hex(hashValue.get(), hashLength);
    } else {
        Logger::instance().error("BCryptFinishHash failed for file: " + file_path);
    }

    // Cleanup
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return result;
}

std::string HashCalculator::sha256_bytes(const uint8_t* data, size_t length) const {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status;
    std::string result;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) return "";

    DWORD hashObjSize = 0, dataSize = 0, hashLength = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PBYTE>(&hashObjSize), sizeof(DWORD), &dataSize, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PBYTE>(&hashLength), sizeof(DWORD), &dataSize, 0);

    auto hashObj = std::make_unique<uint8_t[]>(hashObjSize);
    status = BCryptCreateHash(hAlg, &hHash, hashObj.get(), hashObjSize, nullptr, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(length), 0);

    auto hashValue = std::make_unique<uint8_t[]>(hashLength);
    status = BCryptFinishHash(hHash, hashValue.get(), hashLength, 0);
    if (NT_SUCCESS(status)) {
        result = bytes_to_hex(hashValue.get(), hashLength);
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

#else
// Fallback for non-Windows platforms would go here
// For now, return empty strings
std::string HashCalculator::sha256_file(const std::string& /*file_path*/) const {
    Logger::instance().error("SHA-256 not implemented for this platform");
    return "";
}

std::string HashCalculator::sha256_bytes(const uint8_t* /*data*/, size_t /*length*/) const {
    return "";
}
#endif

} // namespace av
