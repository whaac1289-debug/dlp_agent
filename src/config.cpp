#include "config.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <unordered_set>

std::string g_server_url = "http://localhost:8080/api/events";
std::vector<std::string> g_extension_filter = {".txt", ".log"};
size_t g_size_threshold = 10 * 1024 * 1024;
std::vector<std::string> g_usb_allow_serials;
std::vector<std::string> g_content_keywords = {"confidential", "secret"};
size_t g_max_scan_bytes = 64 * 1024;
size_t g_hash_max_bytes = 1024 * 1024;
bool g_block_on_match = false;
bool g_alert_on_removable = true;
std::string g_rules_path = "rules.json";
std::vector<std::string> g_national_id_patterns;

std::atomic<bool> g_running{false};

static std::string trim_copy(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

static std::string to_lower_copy(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return out;
}

static void normalize_list(std::vector<std::string> &items, bool lower) {
    std::unordered_set<std::string> seen;
    std::vector<std::string> out;
    out.reserve(items.size());
    for (const auto &raw : items) {
        std::string entry = trim_copy(raw);
        if (lower) {
            entry = to_lower_copy(entry);
        }
        if (entry.empty()) continue;
        if (seen.insert(entry).second) {
            out.push_back(entry);
        }
    }
    items.swap(out);
}

static void normalize_extension_filter(std::vector<std::string> &exts) {
    std::unordered_set<std::string> seen;
    std::vector<std::string> out;
    out.reserve(exts.size());
    for (const auto &raw : exts) {
        std::string entry = trim_copy(raw);
        entry = to_lower_copy(entry);
        if (entry.empty()) continue;
        if (entry[0] != '.') {
            entry.insert(entry.begin(), '.');
        }
        if (seen.insert(entry).second) {
            out.push_back(entry);
        }
    }
    exts.swap(out);
}

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

static bool extract_bool(const std::string &s, const std::string &key, bool default_value) {
    auto pos = s.find("\"" + key + "\"");
    if (pos == std::string::npos) return default_value;
    auto colon = s.find(':', pos);
    if (colon == std::string::npos) return default_value;
    size_t i = colon + 1;
    while (i < s.size() && isspace((unsigned char)s[i])) ++i;
    if (s.compare(i, 4, "true") == 0) return true;
    if (s.compare(i, 5, "false") == 0) return false;
    return default_value;
}

static size_t extract_number(const std::string &s, const std::string &key, size_t default_value) {
    auto pos = s.find("\"" + key + "\"");
    if (pos == std::string::npos) return default_value;
    auto colon = s.find(':', pos);
    if (colon == std::string::npos) return default_value;
    size_t i = colon + 1;
    while (i < s.size() && isspace((unsigned char)s[i])) ++i;
    size_t j = i;
    while (j < s.size() && (isdigit((unsigned char)s[j]))) ++j;
    if (j > i) {
        return std::stoull(s.substr(i, j - i));
    }
    return default_value;
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
    auto keywords = extract_array(s, "content_keywords");
    if (!keywords.empty()) g_content_keywords = keywords;
    auto national_patterns = extract_array(s, "national_id_patterns");
    if (!national_patterns.empty()) g_national_id_patterns = national_patterns;
    auto rules_path = extract_string(s, "rules_config");
    if (!rules_path.empty()) g_rules_path = rules_path;

    // size_threshold (number)
    g_size_threshold = extract_number(s, "size_threshold", g_size_threshold);
    g_max_scan_bytes = extract_number(s, "max_scan_bytes", g_max_scan_bytes);
    g_hash_max_bytes = extract_number(s, "hash_max_bytes", g_hash_max_bytes);
    g_block_on_match = extract_bool(s, "block_on_match", g_block_on_match);
    g_alert_on_removable = extract_bool(s, "alert_on_removable", g_alert_on_removable);

    normalize_extension_filter(g_extension_filter);
    normalize_list(g_usb_allow_serials, true);
    normalize_list(g_content_keywords, true);
    normalize_list(g_national_id_patterns, false);

    if (g_extension_filter.empty()) {
        g_extension_filter = {".txt", ".log"};
        fprintf(stderr, "config warning: extension_filter empty, using defaults\n");
    }
    if (g_max_scan_bytes == 0) {
        g_max_scan_bytes = 64 * 1024;
        fprintf(stderr, "config warning: max_scan_bytes invalid, using default\n");
    }
    if (g_hash_max_bytes == 0) {
        g_hash_max_bytes = 1024 * 1024;
        fprintf(stderr, "config warning: hash_max_bytes invalid, using default\n");
    }
    if (g_server_url.empty()) {
        g_server_url = "http://localhost:8080/api/events";
        fprintf(stderr, "config warning: server_url empty, using default\n");
    }
    if (g_rules_path.empty()) {
        g_rules_path = "rules.json";
        fprintf(stderr, "config warning: rules_config empty, using default\n");
    }

    return true;
}
