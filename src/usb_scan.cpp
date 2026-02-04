#include "usb_scan.h"
#include "log.h"
#include "sqlite_store.h"
#include "event_bus.h"
#include "policy.h"

#include <windows.h>
#include "config.h"
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

static std::string get_volume_serial(char drive) {
    char root[4] = { (char)drive, ':', '\\', '\0' };
    DWORD volser = 0;
        if (GetVolumeInformationA(root, nullptr, 0, &volser, nullptr, nullptr, nullptr, 0)) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%08lX", (unsigned long)volser);
        return std::string(buf);
    }
    return std::string();
}

void usb_scan_thread() {
    log_info("USB scan thread started");
    std::unordered_map<char, std::pair<std::string, bool>> last_seen;
    while (g_running) {
        std::unordered_map<char, std::pair<std::string, bool>> current_seen;
        DWORD mask = GetLogicalDrives();
        for (int i=0;i<26;i++) {
            if (mask & (1<<i)) {
                char drv = 'A' + i;
                char root[4] = { drv, ':', '\\', '\0' };
                UINT type = GetDriveTypeA(root);
                if (type == DRIVE_REMOVABLE) {
                    std::string serial = get_volume_serial(drv);
                    DeviceEvent ev;
                    ev.drive_letter = std::string(1, drv);
                    ev.serial = serial;
                    ev.allowed = serial.empty() ? false : is_usb_allowed(serial);
                    current_seen[drv] = {serial, ev.allowed};
                    auto it = last_seen.find(drv);
                    if (it == last_seen.end() || it->second.first != serial || it->second.second != ev.allowed) {
                        emit_device_event(ev);
                    }
                }
            }
        }
        last_seen.swap(current_seen);
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}
