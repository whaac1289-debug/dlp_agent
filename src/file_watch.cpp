#include "file_watch.h"
#include "log.h"
#include "config.h"
#include "sqlite_store.h"
#include "filter.h"
#include "event_bus.h"
#include "hash.h"
#include "policy.h"
#include "rule_engine.h"
#include "pii_detector.h"
#include "fingerprint.h"

#include <windows.h>
#include <string>
#include <chrono>
#include <thread>
#include <vector>
#include <sstream>
#include <algorithm>

static std::string wc_to_utf8(const wchar_t *w, int len) {
    if (!w) return std::string();
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

static bool keyword_hit(const std::vector<unsigned char> &data) {
    if (g_content_keywords.empty()) return false;
    std::string hay(reinterpret_cast<const char*>(data.data()), data.size());
    hay = to_lower_str_fw(hay);
    for (const auto &kw : g_content_keywords) {
        if (!kw.empty() && hay.find(kw) != std::string::npos) return true;
    }
    return false;
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

            bool size_exceeded = false;
            bool keyword_found = false;
            bool is_removable = (ev.drive_type == "REMOVABLE");
            std::vector<unsigned char> data;

            if (fni->Action != FILE_ACTION_REMOVED && fni->Action != FILE_ACTION_RENAMED_OLD_NAME) {
                if (path_is_directory(fullpath)) goto next_item;
                size_t file_size = 0;
                if (read_file_bytes(fullpath, g_max_scan_bytes, data, file_size)) {
                    ev.size_bytes = file_size;
                    size_exceeded = (file_size >= g_size_threshold);
                    keyword_found = keyword_hit(data);
                    ev.sha256 = hash_file_if_small(fullpath, g_hash_max_bytes);
                }
            }

            std::string text(reinterpret_cast<const char*>(data.data()), data.size());
            auto rule_hits = g_rule_engine.scan_text(text);
            std::string partial_hash = partial_sha256(data, g_max_scan_bytes);
            auto hash_hits = g_rule_engine.scan_hashes(ev.sha256, partial_hash);
            rule_hits.insert(rule_hits.end(), hash_hits.begin(), hash_hits.end());
            auto pii_hits = detect_pii(text, g_national_id_patterns);

            bool fingerprint_matched = false;
            std::string fingerprint_path;
            if (!data.empty()) {
                fingerprint_matched = sqlite_find_fingerprint(ev.sha256, partial_hash, ev.size_bytes, fingerprint_path);
                FileFingerprint fp;
                fp.path = fullpath;
                fp.size_bytes = ev.size_bytes;
                fp.full_hash = ev.sha256;
                fp.partial_hash = partial_hash;
                sqlite_insert_fingerprint(fp);
            }

            PolicyDecision decision = evaluate_file_policy(
                size_exceeded,
                keyword_found,
                is_removable,
                g_block_on_match,
                g_alert_on_removable);
            ev.decision = decision.decision;
            std::vector<std::string> extra_reasons;
            extra_reasons.push_back(decision.reason);
            auto rules_summary = summarize_rule_hits(rule_hits);
            if (!rules_summary.empty()) extra_reasons.push_back(rules_summary);
            auto pii_summary = summarize_pii_hits(pii_hits);
            if (!pii_summary.empty()) extra_reasons.push_back(pii_summary);
            auto fp_summary = summarize_fingerprint_match(fingerprint_matched, fingerprint_path);
            if (!fp_summary.empty()) extra_reasons.push_back(fp_summary);
            std::ostringstream reason_stream;
            for (size_t i = 0; i < extra_reasons.size(); ++i) {
                if (i > 0) reason_stream << " | ";
                reason_stream << extra_reasons[i];
            }
            ev.reason = reason_stream.str();
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
