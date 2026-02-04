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
extern std::string g_telemetry_endpoint;
extern std::string g_telemetry_spool_path;
extern std::string g_telemetry_ca_bundle;
extern std::string g_telemetry_client_cert;
extern std::string g_telemetry_client_key;
extern std::string g_telemetry_pinned_spki;
extern std::string g_quarantine_dir;
extern std::string g_shadow_copy_dir;
extern std::string g_policy_endpoint;
extern std::string g_policy_api_key;
extern std::string g_policy_hmac_key;
extern std::string g_policy_public_key;
extern std::string g_policy_store_path;
extern std::string g_config_signature_path;
extern std::string g_expected_binary_hash;
extern int g_block_severity_threshold;
extern int g_quarantine_severity_threshold;
extern int g_shadow_copy_severity_threshold;
extern bool g_enable_shadow_copy;
extern bool g_enable_quarantine;

extern std::atomic<bool> g_running;

bool load_config(const char *path);
