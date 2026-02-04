#include "hash.h"
#include <windows.h>
#include <bcrypt.h>
#include <vector>

std::string sha256_hex(const void *data, size_t len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return std::string();
    DWORD obj_len = 0, hash_len = 0, reslen = 0;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(DWORD), &reslen, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(DWORD), &reslen, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    std::vector<unsigned char> obj(obj_len);
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptCreateHash(hAlg, &hHash, obj.data(), obj_len, NULL, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    if (BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0) != 0) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    std::vector<unsigned char> hash(hash_len);
    if (BCryptFinishHash(hHash, hash.data(), hash_len, 0) != 0) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg,0);
    static const char hex[] = "0123456789abcdef";
    std::string out; out.reserve(hash_len*2);
    for (DWORD i=0;i<hash_len;i++) {
        unsigned char b = hash[i];
        out.push_back(hex[b>>4]); out.push_back(hex[b&0xF]);
    }
    return out;
}

std::string hmac_sha256_hex(const std::string &key, const std::string &data) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        return std::string();
    }
    DWORD obj_len = 0, hash_len = 0, reslen = 0;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(DWORD), &reslen, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(DWORD), &reslen, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    std::vector<unsigned char> obj(obj_len);
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptCreateHash(
            hAlg,
            &hHash,
            obj.data(),
            obj_len,
            (PUCHAR)key.data(),
            static_cast<ULONG>(key.size()),
            0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    if (BCryptHashData(hHash, (PUCHAR)data.data(), static_cast<ULONG>(data.size()), 0) != 0) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    std::vector<unsigned char> hash(hash_len);
    if (BCryptFinishHash(hHash, hash.data(), hash_len, 0) != 0) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg,0);
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(hash_len * 2);
    for (DWORD i = 0; i < hash_len; ++i) {
        unsigned char b = hash[i];
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}
