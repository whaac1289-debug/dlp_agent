#pragma once
#include <string>
#include <vector>
#include <atomic>

extern std::string g_server_url;
extern std::vector<std::string> g_extension_filter;
extern size_t g_size_threshold;
extern std::vector<std::string> g_usb_allow_serials;
extern std::vector<std::string> g_content_keywords;
extern size_t g_max_scan_bytes;
extern size_t g_hash_max_bytes;
extern bool g_block_on_match;
extern bool g_alert_on_removable;
extern std::string g_rules_path;
extern std::vector<std::string> g_national_id_patterns;

extern std::atomic<bool> g_running;

bool load_config(const char *path);
