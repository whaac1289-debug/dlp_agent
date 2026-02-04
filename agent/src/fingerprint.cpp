#include "fingerprint.h"
#include "hash.h"

std::string partial_sha256(const std::vector<unsigned char> &data, size_t max_bytes) {
    if (data.empty()) return std::string();
    size_t to_hash = data.size() < max_bytes ? data.size() : max_bytes;
    return sha256_hex(data.data(), to_hash);
}
