#include "config.h"
#include "log.h"
#include "service_loop.h"
#include "usb_scan.h"
#include "file_watch.h"
#include "api.h"
#include "sqlite_store.h"
#include "enterprise/anti_tamper/anti_tamper.h"

#include <windows.h>
#include <chrono>
#include <thread>
#include <vector>

int main() {
    if (!load_config("config.json")) {
        fprintf(stderr, "Failed to load config.json\n");
        return 1;
    }

    if (!log_init("dlp_agent.log")) {
        fprintf(stderr, "Failed to init logger\n");
        return 1;
    }

    dlp::security::AntiTamper anti_tamper(g_expected_binary_hash);
    char module_path[MAX_PATH];
    if (GetModuleFileNameA(nullptr, module_path, MAX_PATH)) {
        auto result = anti_tamper.VerifyBinaryIntegrity(module_path);
        if (!result.ok) {
            log_error("Binary integrity check failed: %s", result.detail.c_str());
            log_shutdown();
            return 1;
        }
    }
    if (!anti_tamper.VerifyConfigSignature("config.json", g_config_signature_path)) {
        log_error("Config signature verification failed");
        log_shutdown();
        return 1;
    }
    if (anti_tamper.IsDebuggerPresent()) {
        log_error("Debugger detected, exiting");
        log_shutdown();
        return 1;
    }
    anti_tamper.StartServiceWatchdog("DlpAgent");

    if (!sqlite_init("dlp_agent.db")) {
        log_error("Failed to initialize sqlite database");
        log_shutdown();
        return 1;
    }

    // Start worker threads
    g_running = true;
    std::vector<std::thread> workers;
    workers.emplace_back(usb_scan_thread);
    workers.emplace_back(file_watch_thread);
    workers.emplace_back(driver_policy_thread);
    workers.emplace_back(api_sender_thread);
    workers.emplace_back([anti_tamper]() mutable {
        while (g_running) {
            if (anti_tamper.IsDebuggerPresent()) {
                log_error("Anti-tamper: debugger detected");
            }
            if (!anti_tamper.VerifyConfigSignature("config.json", g_config_signature_path)) {
                log_error("Anti-tamper: config signature invalid");
            }
            char module_path[MAX_PATH];
            if (GetModuleFileNameA(nullptr, module_path, MAX_PATH)) {
                auto result = anti_tamper.VerifyBinaryIntegrity(module_path);
                if (!result.ok) {
                    log_error("Anti-tamper: binary integrity failure (%s)", result.detail.c_str());
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    });

    // Run service loop in its own thread so main can accept user input
    std::thread svc(service_loop);

    printf("dlp_agent running — press 'q' then Enter to quit.\n");
    for (;;) {
        int c = getchar();
        if (c == 'q' || c == 'Q') break;
    }

    // signal shutdown and join
    g_running = false;
    if (svc.joinable()) svc.join();
    for (auto &t : workers) {
        if (t.joinable()) t.join();
    }

    sqlite_shutdown();
    log_shutdown();
    return 0;
}
