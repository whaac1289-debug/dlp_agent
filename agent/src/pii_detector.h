#pragma once
#include <string>
#include <vector>

struct PiiDetection {
    std::string type;
    std::string value;
    size_t start = 0;
    size_t end = 0;
    bool valid = true;
};

std::vector<PiiDetection> detect_pii(const std::string &text,
                                     const std::vector<std::string> &national_patterns);
