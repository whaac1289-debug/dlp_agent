#include "api.h"
#include "config.h"
#include "log.h"
#include "enterprise/telemetry/secure_telemetry.h"

#include <atomic>
#include <chrono>
#include <curl/curl.h>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <windows.h>

using dlp::telemetry::RetryPolicy;
using dlp::telemetry::SecureTelemetry;
using dlp::telemetry::TelemetryConfig;
using dlp::telemetry::TelemetryEvent;

static std::string get_hostname() {
    char buf[256];
    DWORD size = sizeof(buf);
    if (GetComputerNameA(buf, &size)) {
        return std::string(buf, size);
    }
    return "unknown";
}

static std::mutex g_telemetry_mutex;
static std::unique_ptr<SecureTelemetry> g_telemetry;
static std::atomic<uint64_t> g_event_counter{0};

void telemetry_enqueue(const std::string &type, const std::string &payload_json) {
    std::lock_guard<std::mutex> lock(g_telemetry_mutex);
    if (!g_telemetry) return;
    TelemetryEvent ev;
    ev.type = type;
    ev.payload_json = payload_json;
    ev.timestamp = std::chrono::system_clock::now();
    ev.id = std::to_string(++g_event_counter);
    g_telemetry->EnqueueEvent(ev);
}

void api_sender_thread() {
    log_info("Telemetry sender thread started");
    TelemetryConfig cfg;
    cfg.endpoint = g_telemetry_endpoint;
    cfg.ca_bundle_path = g_telemetry_ca_bundle;
    cfg.client_cert_path = g_telemetry_client_cert;
    cfg.client_key_path = g_telemetry_client_key;
    cfg.pinned_spki_hash = g_telemetry_pinned_spki;
    cfg.spool_path = g_telemetry_spool_path;

    RetryPolicy retry;
    {
        std::lock_guard<std::mutex> lock(g_telemetry_mutex);
        g_telemetry = std::make_unique<SecureTelemetry>(cfg, retry);
    }

    std::string hostname = get_hostname();
    while (g_running) {
        std::string payload = "{\"type\":\"heartbeat\",\"host\":\"" + hostname + "\"}";
        telemetry_enqueue("heartbeat", payload);
        {
            std::lock_guard<std::mutex> lock(g_telemetry_mutex);
            if (g_telemetry) {
                g_telemetry->Flush();
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
    std::lock_guard<std::mutex> lock(g_telemetry_mutex);
    if (g_telemetry) {
        g_telemetry->Flush();
    }
}
