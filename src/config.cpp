#include "config.h"
#include <fstream>
#include <algorithm>
#include <sstream>

std::string g_server_url = "http://localhost:8080/api/events";
std::vector<std::string> g_extension_filter = {".txt", ".log"};
size_t g_size_threshold = 10 * 1024 * 1024;
std::vector<std::string> g_usb_allow_serials;

std::atomic<bool> g_running{false};

static std::string extract_string(const std::string &s, const std::string &key) {
    auto pos = s.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    auto colon = s.find(':', pos);
    if (colon == std::string::npos) return "";
    auto first = s.find('"', colon+1);
    if (first == std::string::npos) return "";
    auto second = s.find('"', first+1);
    if (second == std::string::npos) return "";
    return s.substr(first+1, second-first-1);
}

static std::vector<std::string> extract_array(const std::string &s, const std::string &key) {
    std::vector<std::string> out;
    auto pos = s.find("\"" + key + "\"");
    if (pos == std::string::npos) return out;
    auto colon = s.find(':', pos);
    if (colon == std::string::npos) return out;
    auto lb = s.find('[', colon);
    auto rb = s.find(']', lb);
    if (lb==std::string::npos || rb==std::string::npos) return out;
    std::string body = s.substr(lb+1, rb-lb-1);
    std::istringstream iss(body);
    std::string token;
    while (std::getline(iss, token, ',')) {
        auto first = token.find('"');
        if (first==std::string::npos) continue;
        auto second = token.find('"', first+1);
        if (second==std::string::npos) continue;
        out.push_back(token.substr(first+1, second-first-1));
    }
    return out;
}

bool load_config(const char *path) {
    std::ifstream ifs(path);
    if (!ifs) return false;
    std::ostringstream oss;
    oss << ifs.rdbuf();
    std::string s = oss.str();

    auto url = extract_string(s, "server_url");
    if (!url.empty()) g_server_url = url;
    auto exts = extract_array(s, "extension_filter");
    if (!exts.empty()) g_extension_filter = exts;
    auto serials = extract_array(s, "usb_allow_serials");
    if (!serials.empty()) g_usb_allow_serials = serials;

    // size_threshold (number)
    auto pos = s.find("\"size_threshold\"");
    if (pos != std::string::npos) {
        auto colon = s.find(':', pos);
        if (colon != std::string::npos) {
            size_t i = colon+1;
            while (i<s.size() && isspace((unsigned char)s[i])) ++i;
            size_t j = i;
            while (j<s.size() && (isdigit((unsigned char)s[j]))) ++j;
            if (j>i) g_size_threshold = std::stoull(s.substr(i,j-i));
        }
    }

    return true;
}
