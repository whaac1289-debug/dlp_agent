#include "api.h"
#include "config.h"
#include "log.h"
#include "sqlite_store.h"

#include <curl/curl.h>
#include <string>
#include <thread>

void api_sender_thread() {
    log_info("API sender thread started");
    CURL *curl = curl_easy_init();
    if (!curl) return;
    while (g_running) {
        // minimal: send heartbeat POST
        curl_easy_setopt(curl, CURLOPT_URL, g_server_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"ping\":1}");
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            log_error("curl failed: %s", curl_easy_strerror(res));
        } else {
            log_info("sent heartbeat to %s", g_server_url.c_str());
        }
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
    curl_easy_cleanup(curl);
}
