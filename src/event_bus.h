#pragma once
#include <string>

struct FileEvent {
    std::string event_type;
    std::string action;
    std::string path;
    std::string user;
    std::string drive_type;
    size_t size_bytes = 0;
    std::string sha256;
    std::string decision;
    std::string reason;
};

struct DeviceEvent {
    std::string drive_letter;
    std::string serial;
    bool allowed = false;
};

void emit_event(const std::string &ev);
void emit_file_event(const FileEvent &ev);
void emit_device_event(const DeviceEvent &ev);
