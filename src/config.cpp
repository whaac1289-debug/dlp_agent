#include "config.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <unordered_set>

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
std::string g_telemetry_endpoint = "https://localhost:8443/api/v2/telemetry";
std::string g_telemetry_spool_path = "telemetry_spool";
std::string g_telemetry_ca_bundle;
std::string g_telemetry_client_cert;
std::string g_telemetry_client_key;
std::string g_telemetry_pinned_spki;
std::string g_quarantine_dir = "C:\\ProgramData\\DLPAgent\\Quarantine";
std::string g_shadow_copy_dir = "C:\\ProgramData\\DLPAgent\\ShadowCopy";
std::string g_policy_endpoint;
std::string g_policy_api_key;
std::string g_policy_hmac_key;
std::string g_policy_public_key;
std::string g_policy_store_path = "policy_snapshot.json";
std::string g_policy_version;
std::mutex g_policy_mutex;
std::string g_config_signature_path = "config.json.sig";
std::string g_expected_binary_hash;
int g_block_severity_threshold = 8;
int g_quarantine_severity_threshold = 9;
int g_shadow_copy_severity_threshold = 6;
bool g_enable_shadow_copy = true;
bool g_enable_quarantine = true;

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
    auto telemetry_endpoint = extract_string(s, "telemetry_endpoint");
    if (!telemetry_endpoint.empty()) g_telemetry_endpoint = telemetry_endpoint;
    auto telemetry_spool = extract_string(s, "telemetry_spool_path");
    if (!telemetry_spool.empty()) g_telemetry_spool_path = telemetry_spool;
    auto telemetry_ca = extract_string(s, "telemetry_ca_bundle");
    if (!telemetry_ca.empty()) g_telemetry_ca_bundle = telemetry_ca;
    auto telemetry_cert = extract_string(s, "telemetry_client_cert");
    if (!telemetry_cert.empty()) g_telemetry_client_cert = telemetry_cert;
    auto telemetry_key = extract_string(s, "telemetry_client_key");
    if (!telemetry_key.empty()) g_telemetry_client_key = telemetry_key;
    auto telemetry_spki = extract_string(s, "telemetry_pinned_spki");
    if (!telemetry_spki.empty()) g_telemetry_pinned_spki = telemetry_spki;
    auto quarantine_dir = extract_string(s, "quarantine_dir");
    if (!quarantine_dir.empty()) g_quarantine_dir = quarantine_dir;
    auto shadow_copy_dir = extract_string(s, "shadow_copy_dir");
    if (!shadow_copy_dir.empty()) g_shadow_copy_dir = shadow_copy_dir;
    auto policy_endpoint = extract_string(s, "policy_endpoint");
    if (!policy_endpoint.empty()) g_policy_endpoint = policy_endpoint;
    auto policy_api_key = extract_string(s, "policy_api_key");
    if (!policy_api_key.empty()) g_policy_api_key = policy_api_key;
    auto policy_hmac_key = extract_string(s, "policy_hmac_key");
    if (!policy_hmac_key.empty()) g_policy_hmac_key = policy_hmac_key;
    auto policy_public_key = extract_string(s, "policy_public_key");
    if (!policy_public_key.empty()) g_policy_public_key = policy_public_key;
    auto policy_store_path = extract_string(s, "policy_store_path");
    if (!policy_store_path.empty()) g_policy_store_path = policy_store_path;
    auto config_sig = extract_string(s, "config_signature_path");
    if (!config_sig.empty()) g_config_signature_path = config_sig;
    auto expected_hash = extract_string(s, "expected_binary_hash");
    if (!expected_hash.empty()) g_expected_binary_hash = expected_hash;

    // size_threshold (number)
    g_size_threshold = extract_number(s, "size_threshold", g_size_threshold);
    g_max_scan_bytes = extract_number(s, "max_scan_bytes", g_max_scan_bytes);
    g_hash_max_bytes = extract_number(s, "hash_max_bytes", g_hash_max_bytes);
    g_block_on_match = extract_bool(s, "block_on_match", g_block_on_match);
    g_alert_on_removable = extract_bool(s, "alert_on_removable", g_alert_on_removable);
    g_block_severity_threshold = static_cast<int>(extract_number(s, "block_severity_threshold", g_block_severity_threshold));
    g_quarantine_severity_threshold = static_cast<int>(extract_number(s, "quarantine_severity_threshold", g_quarantine_severity_threshold));
    g_shadow_copy_severity_threshold = static_cast<int>(extract_number(s, "shadow_copy_severity_threshold", g_shadow_copy_severity_threshold));
    g_enable_shadow_copy = extract_bool(s, "enable_shadow_copy", g_enable_shadow_copy);
    g_enable_quarantine = extract_bool(s, "enable_quarantine", g_enable_quarantine);

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
    if (g_rules_path.empty()) {
        g_rules_path = "rules.json";
        fprintf(stderr, "config warning: rules_config empty, using default\n");
    }
    if (g_telemetry_endpoint.empty()) {
        g_telemetry_endpoint = "https://localhost:8443/api/v2/telemetry";
        fprintf(stderr, "config warning: telemetry_endpoint empty, using default\n");
    }
    if (g_telemetry_spool_path.empty()) {
        g_telemetry_spool_path = "telemetry_spool";
        fprintf(stderr, "config warning: telemetry_spool_path empty, using default\n");
    }

    return true;
}
