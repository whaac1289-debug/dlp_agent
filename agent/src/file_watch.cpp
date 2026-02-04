#include "file_watch.h"
#include "log.h"
#include "config.h"
#include "sqlite_store.h"
#include "filter.h"
#include "event_bus.h"
#include "hash.h"
#include "policy.h"
#include "pii_detector.h"
#include "fingerprint.h"
#include "enterprise/process_attribution.h"
#include "enterprise/extraction/content_extractor.h"
#include "enterprise/rules/rule_engine_v2.h"

#include <windows.h>
#include <fltuser.h>
#include <string>
#include <chrono>
#include <thread>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cwchar>

static std::string wc_to_utf8(const wchar_t *w, int len) {
    if (!w) return std::string();
    if (len < 0) {
        len = static_cast<int>(wcslen(w));
    }
    int needed = WideCharToMultiByte(CP_UTF8, 0, w, len, NULL, 0, NULL, NULL);
    if (needed <= 0) return std::string();
    std::string out(needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, len, &out[0], needed, NULL, NULL);
    return out;
}

static std::string to_lower_str_fw(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c){ return std::tolower(c); });
    return out;
}

static bool should_ignore_name(const std::string &name) {
    if (name.empty()) return true;
    std::string lower = to_lower_str_fw(name);
    if (lower.rfind("~$", 0) == 0) return true;
    if (lower.size() >= 4 && lower.compare(lower.size() - 4, 4, ".tmp") == 0) return true;
    return false;
}

static bool path_is_directory(const std::string &path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static std::string get_username() {
    char buf[256];
    DWORD len = sizeof(buf);
    if (GetUserNameA(buf, &len)) {
        if (len > 0 && buf[len - 1] == '\0') {
            return std::string(buf);
        }
        return std::string(buf, len);
    }
    return "unknown";
}

static std::string drive_type_for_path(const std::string &path) {
    if (path.size() < 3 || path[1] != ':' || path[2] != '\\') return "UNKNOWN";
    char root[4] = { path[0], ':', '\\', '\0' };
    UINT type = GetDriveTypeA(root);
    switch (type) {
        case DRIVE_REMOVABLE: return "REMOVABLE";
        case DRIVE_FIXED: return "FIXED";
        case DRIVE_REMOTE: return "REMOTE";
        case DRIVE_CDROM: return "CDROM";
        case DRIVE_RAMDISK: return "RAMDISK";
        default: return "UNKNOWN";
    }
}

static std::string file_extension(const std::string &path) {
    auto pos = path.find_last_of('.');
    if (pos == std::string::npos) return "";
    std::string ext = path.substr(pos);
    return to_lower_str_fw(ext);
}

struct DlpPolicyQuery {
    uint32_t process_id;
    uint32_t parent_process_id;
    uint32_t session_id;
    uint32_t desired_access;
    uint32_t create_options;
    uint32_t file_attributes;
    wchar_t file_path[512];
};

enum class DlpPolicyAction : uint32_t {
    Allow = 0,
    Block = 1,
    Alert = 2,
    Quarantine = 3
};

struct DlpPolicyDecision {
    DlpPolicyAction action;
    uint32_t rule_id;
    uint32_t severity;
};

struct DlpMessage {
    FILTER_MESSAGE_HEADER header;
    DlpPolicyQuery query;
};

struct DlpReply {
    FILTER_REPLY_HEADER header;
    DlpPolicyDecision decision;
};

static bool ensure_directory(const std::string &path) {
    if (path.empty()) return false;
    if (CreateDirectoryA(path.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS) {
        return true;
    }
    return false;
}

static std::string build_storage_path(const std::string &root, const std::string &original_path) {
    if (root.empty()) return {};
    size_t pos = original_path.find_last_of("\\/");
    std::string filename = (pos == std::string::npos) ? original_path : original_path.substr(pos + 1);
    SYSTEMTIME st;
    GetSystemTime(&st);
    char stamp[64];
    snprintf(stamp, sizeof(stamp), "%04u%02u%02u%02u%02u%02u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return root + "\\" + stamp + "_" + filename;
}

static bool copy_to_shadow(const std::string &path, const std::string &shadow_root, std::string &out_path) {
    if (!ensure_directory(shadow_root)) return false;
    out_path = build_storage_path(shadow_root, path);
    return CopyFileA(path.c_str(), out_path.c_str(), FALSE) == TRUE;
}

static bool move_to_quarantine(const std::string &path, const std::string &quarantine_root, std::string &out_path) {
    if (!ensure_directory(quarantine_root)) return false;
    out_path = build_storage_path(quarantine_root, path);
    if (MoveFileExA(path.c_str(), out_path.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
        return true;
    }
    if (CopyFileA(path.c_str(), out_path.c_str(), FALSE)) {
        DeleteFileA(path.c_str());
        return true;
    }
    return false;
}

static bool read_file_bytes(const std::string &path, size_t max_bytes, std::vector<unsigned char> &out, size_t &size_out) {
    HANDLE hFile = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hFile, &file_size)) {
        CloseHandle(hFile);
        return false;
    }
    size_out = static_cast<size_t>(file_size.QuadPart);
    size_t to_read = size_out < max_bytes ? size_out : max_bytes;
    out.resize(to_read);
    DWORD read = 0;
    BOOL ok = ReadFile(hFile, out.data(), static_cast<DWORD>(to_read), &read, NULL);
    CloseHandle(hFile);
    if (!ok) return false;
    out.resize(read);
    return true;
}

static std::string hash_file_if_small(const std::string &path, size_t max_bytes) {
    HANDLE hFile = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) return std::string();
    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hFile, &file_size)) {
        CloseHandle(hFile);
        return std::string();
    }
    size_t size = static_cast<size_t>(file_size.QuadPart);
    if (size > max_bytes) {
        CloseHandle(hFile);
        return std::string();
    }
    std::vector<unsigned char> buf(size);
    DWORD read = 0;
    BOOL ok = ReadFile(hFile, buf.data(), static_cast<DWORD>(size), &read, NULL);
    CloseHandle(hFile);
    if (!ok || read != size) return std::string();
    return sha256_hex(buf.data(), buf.size());
}

static std::string keyword_hit_text(const std::string &text) {
    if (g_content_keywords.empty()) return {};
    auto lower = to_lower_str_fw(text);
    for (const auto &kw : g_content_keywords) {
        if (!kw.empty() && lower.find(kw) != std::string::npos) {
            return kw;
        }
    }
    return {};
}

static std::string summarize_rule_hits(const std::vector<RuleMatch> &hits) {
    if (hits.empty()) return std::string();
    std::ostringstream oss;
    oss << "rule_hits=" << hits.size();
    size_t limit = 3;
    size_t count = 0;
    for (const auto &hit : hits) {
        if (count == 0) oss << " [";
        if (count >= limit) break;
        if (count > 0) oss << ", ";
        oss << (hit.rule_name.empty() ? hit.rule_id : hit.rule_name);
        oss << ":sev" << hit.severity;
        oss << ":conf" << hit.confidence;
        count++;
    }
    if (count > 0) oss << "]";
    return oss.str();
}

static std::string summarize_pii_hits(const std::vector<PiiDetection> &hits) {
    if (hits.empty()) return std::string();
    std::ostringstream oss;
    oss << "pii_hits=" << hits.size();
    size_t limit = 3;
    size_t count = 0;
    for (const auto &hit : hits) {
        if (count == 0) oss << " [";
        if (count >= limit) break;
        if (count > 0) oss << ", ";
        oss << hit.type;
        if (!hit.valid) oss << "(invalid)";
        count++;
    }
    if (count > 0) oss << "]";
    return oss.str();
}

static std::string summarize_fingerprint_match(bool matched, const std::string &existing_path) {
    if (!matched) return std::string();
    if (!existing_path.empty()) {
        return "fingerprint_match=" + existing_path;
    }
    return "fingerprint_match=yes";
}

static std::string build_content_flags(bool contains_pii,
                                       bool keyword_found,
                                       bool size_exceeded,
                                       bool fingerprint_matched) {
    std::ostringstream oss;
    bool first = true;
    auto append = [&](const std::string &flag) {
        if (!first) oss << ",";
        oss << flag;
        first = false;
    };
    if (contains_pii) append("pii");
    if (keyword_found) append("keyword");
    if (size_exceeded) append("size");
    if (fingerprint_matched) append("fingerprint");
    return oss.str();
}

static std::string build_device_context(const std::string &drive_type, bool removable) {
    std::ostringstream oss;
    oss << "drive_type=" << drive_type << ";removable=" << (removable ? "true" : "false");
    return oss.str();
}

static uint32_t rule_id_hash(const std::string &rule_id) {
    uint32_t hash = 2166136261u;
    for (unsigned char c : rule_id) {
        hash ^= c;
        hash *= 16777619u;
    }
    return hash;
}

struct PipelineResult {
    PolicyDecision policy_decision;
    RuleDecision rule_decision;
    std::vector<RuleMatch> rule_hits;
    std::vector<PiiDetection> pii_hits;
    std::string partial_hash;
    bool keyword_found{false};
    bool size_exceeded{false};
    bool fingerprint_matched{false};
    std::string fingerprint_path;
};

static PipelineResult evaluate_pipeline(const std::string &path,
                                        const std::string &extension,
                                        const std::string &user,
                                        const std::string &drive_type,
                                        const std::string &process_name,
                                        bool removable,
                                        std::string &sha256_out,
                                        size_t &size_out) {
    PipelineResult result;
    std::vector<unsigned char> data;
    size_out = 0;
    if (read_file_bytes(path, g_max_scan_bytes, data, size_out)) {
        result.size_exceeded = (size_out >= g_size_threshold);
        sha256_out = hash_file_if_small(path, g_hash_max_bytes);
    }

    std::string text(reinterpret_cast<const char*>(data.data()), data.size());
    if (text.empty()) {
        auto extractor = dlp::extract::CreateExtractorForExtension(extension);
        if (extractor) {
            text = extractor->ExtractText(path);
        }
    }

    std::string keyword = keyword_hit_text(text);
    result.keyword_found = !keyword.empty();
    result.partial_hash = partial_sha256(data, g_max_scan_bytes);
    result.rule_hits = dlp::rules::g_rule_engine_v2.ScanText(text);
    auto hash_hits = dlp::rules::g_rule_engine_v2.ScanHashes(sha256_out, result.partial_hash);
    result.rule_hits.insert(result.rule_hits.end(), hash_hits.begin(), hash_hits.end());
    result.pii_hits = detect_pii(text, g_national_id_patterns);

    if (!data.empty()) {
        result.fingerprint_matched = sqlite_find_fingerprint(sha256_out, result.partial_hash, size_out, result.fingerprint_path);
        FileFingerprint fp;
        fp.path = path;
        fp.size_bytes = size_out;
        fp.full_hash = sha256_out;
        fp.partial_hash = result.partial_hash;
        sqlite_insert_fingerprint(fp);
    }

    RuleContext rule_context;
    rule_context.path = path;
    rule_context.extension = extension;
    rule_context.user = user;
    rule_context.drive_type = drive_type;
    rule_context.process_name = process_name;
    rule_context.destination = drive_type;
    rule_context.contains_pii = !result.pii_hits.empty();
    rule_context.keyword_hit = result.keyword_found;
    rule_context.size_exceeded = result.size_exceeded;
    rule_context.removable_drive = removable;
    rule_context.fingerprint_matched = result.fingerprint_matched;

    result.rule_decision = dlp::rules::g_rule_engine_v2.Evaluate(rule_context, result.rule_hits);
    result.policy_decision = resolve_rule_decision(result.rule_decision, removable, g_alert_on_removable);
    return result;
}

static void process_notifications(BYTE *buf, DWORD bytes, const std::string &basepath) {
    FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION*)buf;
    while (true) {
        int nameLen = fni->FileNameLength / sizeof(wchar_t);
        std::string name = wc_to_utf8(fni->FileName, nameLen);
        std::string fullpath;
        if (!basepath.empty()) {
            fullpath = basepath + "\\" + name;
        } else fullpath = name;

        // ignore temporary Office lockfiles starting with ~$ and .tmp
        if (should_ignore_name(name)) goto next_item;
        // extension filter
        if (extension_allowed(name)) {
            const char *action = "UNKNOWN";
            switch (fni->Action) {
                case FILE_ACTION_ADDED: action = "ADDED"; break;
                case FILE_ACTION_REMOVED: action = "REMOVED"; break;
                case FILE_ACTION_MODIFIED: action = "MODIFIED"; break;
                case FILE_ACTION_RENAMED_OLD_NAME: action = "RENAMED_FROM"; break;
                case FILE_ACTION_RENAMED_NEW_NAME: action = "RENAMED_TO"; break;
            }

            FileEvent ev;
            ev.event_type = "file";
            ev.action = action;
            ev.path = fullpath;
            ev.user = get_username();
            ev.drive_type = drive_type_for_path(fullpath);
            ev.size_bytes = 0;
            auto proc_info = dlp::process::GetProcessAttribution(GetCurrentProcessId());
            ev.process_name = proc_info.process_name;
            ev.pid = proc_info.pid;
            ev.ppid = proc_info.ppid;
            ev.command_line = proc_info.command_line;
            ev.user_sid = proc_info.token.user_sid;

            bool is_removable = (ev.drive_type == "REMOVABLE");
            std::string extension = file_extension(fullpath);
            PipelineResult result;
            if (fni->Action != FILE_ACTION_REMOVED && fni->Action != FILE_ACTION_RENAMED_OLD_NAME) {
                if (path_is_directory(fullpath)) goto next_item;
                result = evaluate_pipeline(fullpath,
                                           extension,
                                           ev.user,
                                           ev.drive_type,
                                           ev.process_name,
                                           is_removable,
                                           ev.sha256,
                                           ev.size_bytes);
            } else {
                result.policy_decision = resolve_rule_decision({}, is_removable, g_alert_on_removable);
            }

            ev.rule_id = result.rule_decision.rule_id;
            ev.rule_name = result.rule_decision.rule_name;
            ev.severity = result.rule_decision.severity;
            ev.content_flags = build_content_flags(!result.pii_hits.empty(),
                                                   result.keyword_found,
                                                   result.size_exceeded,
                                                   result.fingerprint_matched);
            ev.device_context = build_device_context(ev.drive_type, is_removable);
            ev.decision = result.policy_decision.decision;
            std::vector<std::string> extra_reasons;
            extra_reasons.push_back(result.policy_decision.reason);
            auto rules_summary = summarize_rule_hits(result.rule_hits);
            if (!rules_summary.empty()) extra_reasons.push_back(rules_summary);
            auto pii_summary = summarize_pii_hits(result.pii_hits);
            if (!pii_summary.empty()) extra_reasons.push_back(pii_summary);
            auto fp_summary = summarize_fingerprint_match(result.fingerprint_matched, result.fingerprint_path);
            if (!fp_summary.empty()) extra_reasons.push_back(fp_summary);
            std::ostringstream reason_stream;
            for (size_t i = 0; i < extra_reasons.size(); ++i) {
                if (i > 0) reason_stream << " | ";
                reason_stream << extra_reasons[i];
            }
            ev.reason = reason_stream.str();

            if (fni->Action == FILE_ACTION_ADDED || fni->Action == FILE_ACTION_MODIFIED ||
                fni->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                std::string enforcement_detail;
                if (result.policy_decision.action == RuleAction::ShadowCopy && g_enable_shadow_copy) {
                    std::string shadow_path;
                    if (copy_to_shadow(fullpath, g_shadow_copy_dir, shadow_path)) {
                        enforcement_detail = "shadow_copy=" + shadow_path;
                    }
                } else if (result.policy_decision.action == RuleAction::Quarantine && g_enable_quarantine) {
                    std::string quarantine_path;
                    if (move_to_quarantine(fullpath, g_quarantine_dir, quarantine_path)) {
                        enforcement_detail = "quarantine=" + quarantine_path;
                    }
                } else if (result.policy_decision.action == RuleAction::Block) {
                    if (DeleteFileA(fullpath.c_str()) == TRUE) {
                        enforcement_detail = "blocked_deleted";
                    } else {
                        enforcement_detail = "block_failed";
                    }
                }
                if (!enforcement_detail.empty()) {
                    if (!ev.reason.empty()) ev.reason += " | ";
                    ev.reason += enforcement_detail;
                }
            }
            emit_file_event(ev);
        }
next_item:
        if (fni->NextEntryOffset == 0) break;
        fni = (FILE_NOTIFY_INFORMATION*)(((BYTE*)fni) + fni->NextEntryOffset);
    }
}

static void watch_path_thread(const std::string &path) {
    std::wstring wpath;
    int n = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, NULL, 0);
    wpath.resize(n);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], n);

    HANDLE hDir = CreateFileW(wpath.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
        log_error("Failed to open watch path %s", path.c_str());
        return;
    }
    const DWORD bufSize = 64*1024;
    std::vector<BYTE> buf(bufSize);
    DWORD bytes = 0;
    while (g_running) {
        BOOL ok = ReadDirectoryChangesW(hDir, buf.data(), bufSize, TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
            &bytes, NULL, NULL);
        if (ok && bytes > 0) {
            process_notifications(buf.data(), bytes, path);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    CloseHandle(hDir);
}

void file_watch_thread() {
    log_info("File watch thread started");
    std::vector<std::thread> workers;
    // always watch local user folder
    workers.emplace_back(watch_path_thread, std::string("C:\\Users"));

    // enumerate logical drives and watch removable drives
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (mask & (1u << i)) {
            char drv = 'A' + i;
            char rootPath[4] = { drv, ':', '\\', '\0' };
            UINT type = GetDriveTypeA(rootPath);
            if (type == DRIVE_REMOVABLE) {
                std::string path(rootPath);
                workers.emplace_back(watch_path_thread, path);
                log_info("Watching removable drive %s", path.c_str());
            }
        }
    }

    for (auto &t : workers) if (t.joinable()) t.join();
}

void driver_policy_thread() {
    log_info("Driver policy thread started");
    HANDLE port = nullptr;
    HRESULT hr = FilterConnectCommunicationPort(L"\\DlpMinifilterPort", 0, nullptr, 0, nullptr, &port);
    if (FAILED(hr)) {
        log_info("Minifilter port not available, driver policy thread exiting");
        return;
    }
    while (g_running) {
        DlpMessage msg = {};
        OVERLAPPED ov = {};
        ov.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) {
            break;
        }
        hr = FilterGetMessage(port, &msg.header, sizeof(msg), &ov);
        if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
            DWORD wait = WaitForSingleObject(ov.hEvent, 2000);
            if (wait == WAIT_TIMEOUT) {
                CloseHandle(ov.hEvent);
                continue;
            }
        }
        CloseHandle(ov.hEvent);
        if (FAILED(hr)) {
            if (!g_running) break;
            continue;
        }

        std::string path = wc_to_utf8(msg.query.file_path, -1);
        std::string extension = file_extension(path);
        auto proc_info = dlp::process::GetProcessAttribution(msg.query.process_id);
        std::string user = get_username();
        std::string drive_type = drive_type_for_path(path);
        bool is_removable = (drive_type == "REMOVABLE");
        FileEvent ev;
        ev.event_type = "file";
        ev.action = "DRIVER_CREATE";
        ev.path = path;
        ev.user = user;
        ev.user_sid = proc_info.token.user_sid;
        ev.drive_type = drive_type;
        ev.process_name = proc_info.process_name;
        ev.pid = proc_info.pid;
        ev.ppid = proc_info.ppid;
        ev.command_line = proc_info.command_line;

        PipelineResult result;
        if (!path.empty()) {
            result = evaluate_pipeline(path,
                                       extension,
                                       user,
                                       drive_type,
                                       ev.process_name,
                                       is_removable,
                                       ev.sha256,
                                       ev.size_bytes);
        } else {
            result.policy_decision = resolve_rule_decision({}, is_removable, g_alert_on_removable);
        }

        ev.rule_id = result.rule_decision.rule_id;
        ev.rule_name = result.rule_decision.rule_name;
        ev.severity = result.rule_decision.severity;
        ev.content_flags = build_content_flags(!result.pii_hits.empty(),
                                               result.keyword_found,
                                               result.size_exceeded,
                                               result.fingerprint_matched);
        ev.device_context = build_device_context(drive_type, is_removable);
        ev.decision = result.policy_decision.decision;
        ev.reason = result.policy_decision.reason;
        emit_file_event(ev);

        DlpReply reply = {};
        reply.header.MessageId = msg.header.MessageId;
        reply.decision.rule_id = rule_id_hash(result.rule_decision.rule_id);
        reply.decision.severity = static_cast<uint32_t>(result.rule_decision.severity);
        if (should_block_driver(result.policy_decision)) {
            reply.decision.action = DlpPolicyAction::Block;
        } else if (result.policy_decision.action == RuleAction::Alert) {
            reply.decision.action = DlpPolicyAction::Alert;
        } else {
            reply.decision.action = DlpPolicyAction::Allow;
        }
        FilterReplyMessage(port, &reply.header, sizeof(reply));
    }
    CloseHandle(port);
}
