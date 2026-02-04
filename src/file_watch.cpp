#include "file_watch.h"
#include "log.h"
#include "config.h"
#include "sqlite_store.h"
#include "filter.h"
#include "event_bus.h"

#include <windows.h>
#include <string>
#include <thread>
#include <vector>
#include <sstream>

static std::string wc_to_utf8(const wchar_t *w, int len) {
    if (!w) return std::string();
    int needed = WideCharToMultiByte(CP_UTF8, 0, w, len, NULL, 0, NULL, NULL);
    if (needed <= 0) return std::string();
    std::string out(needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, len, &out[0], needed, NULL, NULL);
    return out;
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
        if (!name.empty()) {
            if (name.rfind("~$", 0) == 0) goto next_item;
        }
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
            std::ostringstream oss;
            oss << "file_event:" << action << ":" << fullpath;
            emit_event(oss.str());
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
