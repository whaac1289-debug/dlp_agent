#pragma once

#include <string>
#include <vector>

namespace dlp::process {

struct TokenInfo {
    std::string user_sid;
    std::string integrity_level;
    std::vector<std::string> privileges;
};

struct ProcessAttribution {
    std::string process_name;
    uint32_t pid{0};
    uint32_t ppid{0};
    std::string command_line;
    TokenInfo token;
};

ProcessAttribution GetProcessAttribution(uint32_t pid);

}  // namespace dlp::process
