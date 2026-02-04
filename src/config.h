#pragma once
#include <string>
#include <vector>
#include <atomic>

extern std::string g_server_url;
extern std::vector<std::string> g_extension_filter;
extern size_t g_size_threshold;
extern std::vector<std::string> g_usb_allow_serials;

extern std::atomic<bool> g_running;

bool load_config(const char *path);
