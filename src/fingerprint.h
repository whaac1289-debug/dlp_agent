#pragma once
#include <string>
#include <vector>

struct FileFingerprint {
    std::string path;
    size_t size_bytes = 0;
    std::string full_hash;
    std::string partial_hash;
};

std::string partial_sha256(const std::vector<unsigned char> &data, size_t max_bytes);
