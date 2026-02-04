#include "event_bus.h"
#include "sqlite_store.h"
#include "log.h"
#include <sstream>

static std::string json_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
    return out;
}

void emit_event(const std::string &ev) {
    log_info("event: %s", ev.c_str());
    sqlite_insert_event(ev);
}

void emit_file_event(const FileEvent &ev) {
    std::ostringstream oss;
    oss << "{"
        << "\"type\":\"" << json_escape(ev.event_type) << "\","
        << "\"action\":\"" << json_escape(ev.action) << "\","
        << "\"path\":\"" << json_escape(ev.path) << "\","
        << "\"user\":\"" << json_escape(ev.user) << "\","
        << "\"drive_type\":\"" << json_escape(ev.drive_type) << "\","
        << "\"size_bytes\":" << ev.size_bytes << ","
        << "\"sha256\":\"" << json_escape(ev.sha256) << "\","
        << "\"decision\":\"" << json_escape(ev.decision) << "\","
        << "\"reason\":\"" << json_escape(ev.reason) << "\""
        << "}";
    log_info("file_event: %s", oss.str().c_str());
    sqlite_insert_file_event(ev);
    sqlite_insert_event(oss.str());
}

void emit_device_event(const DeviceEvent &ev) {
    std::ostringstream oss;
    oss << "{"
        << "\"type\":\"device\","
        << "\"drive\":\"" << json_escape(ev.drive_letter) << "\","
        << "\"serial\":\"" << json_escape(ev.serial) << "\","
        << "\"allowed\":" << (ev.allowed ? "true" : "false")
        << "}";
    log_info("device_event: %s", oss.str().c_str());
    sqlite_insert_device_event(ev.drive_letter, ev.serial, ev.allowed);
    sqlite_insert_event(oss.str());
}
