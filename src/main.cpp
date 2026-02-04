#include "config.h"
#include "log.h"
#include "service_loop.h"
#include "usb_scan.h"
#include "file_watch.h"
#include "api.h"
#include "sqlite_store.h"

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

    sqlite_init("dlp_agent.db");

    // Start worker threads
    g_running = true;
    std::vector<std::thread> workers;
    workers.emplace_back(usb_scan_thread);
    workers.emplace_back(file_watch_thread);
    workers.emplace_back(api_sender_thread);

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

    log_shutdown();
    return 0;
}
