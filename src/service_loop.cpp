#include "service_loop.h"
#include "log.h"
#include "config.h"
#include <windows.h>

void service_loop() {
    log_info("Service loop started");
    while (g_running) {
        // simple heartbeat
        log_info("heartbeat");
        Sleep(15000);
    }
    log_info("Service loop exiting");
}
