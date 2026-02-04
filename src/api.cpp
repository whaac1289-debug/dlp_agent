#include "api.h"
#include "config.h"
#include "log.h"
#include "sqlite_store.h"

#include <curl/curl.h>
#include <string>
#include <thread>
#include <windows.h>

static std::string get_hostname() {
    char buf[256];
    DWORD size = sizeof(buf);
    if (GetComputerNameA(buf, &size)) {
        return std::string(buf, size);
    }
    return "unknown";
}

void api_sender_thread() {
    log_info("API sender thread started");
    CURL *curl = curl_easy_init();
    if (!curl) return;
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dlp_agent/1.0");
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    std::string hostname = get_hostname();
    while (g_running) {
        // minimal: send heartbeat POST
        curl_easy_setopt(curl, CURLOPT_URL, g_server_url.c_str());
        std::string payload = "{\"ping\":1,\"host\":\"" + hostname + "\"}";
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            log_error("curl failed: %s", curl_easy_strerror(res));
        } else {
            long code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            log_info("sent heartbeat to %s (http %ld)", g_server_url.c_str(), code);
        }
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
    if (headers) {
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);
}
