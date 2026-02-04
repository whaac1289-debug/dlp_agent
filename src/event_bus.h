#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

struct FileEvent {
    std::string event_type;
    std::string action;
    std::string path;
    std::string user;
    std::string user_sid;
    std::string drive_type;
    std::string process_name;
    uint32_t pid = 0;
    uint32_t ppid = 0;
    std::string command_line;
    size_t size_bytes = 0;
    std::string sha256;
    std::string rule_id;
    std::string rule_name;
    int severity = 0;
    std::string content_flags;
    std::string device_context;
    std::string decision;
    std::string reason;
};

struct DeviceEvent {
    std::string drive_letter;
    std::string serial;
    bool allowed = false;
    std::string decision;
    std::string reason;
};

void emit_event(const std::string &ev);
void emit_file_event(const FileEvent &ev);
void emit_device_event(const DeviceEvent &ev);
