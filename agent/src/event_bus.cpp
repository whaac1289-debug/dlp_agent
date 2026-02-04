#include "event_bus.h"
#include "sqlite_store.h"
#include "log.h"
#include "api.h"
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
        << "\"user_sid\":\"" << json_escape(ev.user_sid) << "\","
        << "\"drive_type\":\"" << json_escape(ev.drive_type) << "\","
        << "\"process_name\":\"" << json_escape(ev.process_name) << "\","
        << "\"pid\":" << ev.pid << ","
        << "\"ppid\":" << ev.ppid << ","
        << "\"command_line\":\"" << json_escape(ev.command_line) << "\","
        << "\"size_bytes\":" << ev.size_bytes << ","
        << "\"sha256\":\"" << json_escape(ev.sha256) << "\","
        << "\"rule_id\":\"" << json_escape(ev.rule_id) << "\","
        << "\"rule_name\":\"" << json_escape(ev.rule_name) << "\","
        << "\"severity\":" << ev.severity << ","
        << "\"content_flags\":\"" << json_escape(ev.content_flags) << "\","
        << "\"device_context\":\"" << json_escape(ev.device_context) << "\","
        << "\"decision\":\"" << json_escape(ev.decision) << "\","
        << "\"reason\":\"" << json_escape(ev.reason) << "\""
        << "}";
    log_info("file_event: %s", oss.str().c_str());
    sqlite_insert_file_event(ev);
    sqlite_insert_event(oss.str());
    telemetry_enqueue("file_event", oss.str());
}

void emit_device_event(const DeviceEvent &ev) {
    std::ostringstream oss;
    oss << "{"
        << "\"type\":\"device\","
        << "\"drive\":\"" << json_escape(ev.drive_letter) << "\","
        << "\"serial\":\"" << json_escape(ev.serial) << "\","
        << "\"allowed\":" << (ev.allowed ? "true" : "false") << ","
        << "\"decision\":\"" << json_escape(ev.decision) << "\","
        << "\"reason\":\"" << json_escape(ev.reason) << "\""
        << "}";
    log_info("device_event: %s", oss.str().c_str());
    sqlite_insert_device_event(ev);
    sqlite_insert_event(oss.str());
    telemetry_enqueue("device_event", oss.str());
}
