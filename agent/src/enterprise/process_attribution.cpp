#include "process_attribution.h"

#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <vector>

namespace dlp::process {

static std::string wide_to_utf8(const wchar_t *w) {
    if (!w) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) return {};
    std::string out(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &out[0], needed, nullptr, nullptr);
    return out;
}

static uint32_t lookup_parent_pid(uint32_t pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32First(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                CloseHandle(snapshot);
                return entry.th32ParentProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

static std::string lookup_process_path(HANDLE process) {
    wchar_t buffer[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(process, 0, buffer, &size)) {
        return wide_to_utf8(buffer);
    }
    return {};
}

static std::string lookup_user_sid(HANDLE process) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        return {};
    }
    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    if (!len) {
        CloseHandle(token);
        return {};
    }
    std::vector<unsigned char> buf(len);
    if (!GetTokenInformation(token, TokenUser, buf.data(), len, &len)) {
        CloseHandle(token);
        return {};
    }
    auto *user = reinterpret_cast<TOKEN_USER *>(buf.data());
    LPSTR sid_str = nullptr;
    std::string result;
    if (ConvertSidToStringSidA(user->User.Sid, &sid_str)) {
        result = sid_str;
        LocalFree(sid_str);
    }
    CloseHandle(token);
    return result;
}

ProcessAttribution GetProcessAttribution(uint32_t pid) {
    ProcessAttribution result;
    result.pid = pid;
    result.ppid = lookup_parent_pid(pid);
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        return result;
    }
    std::string full_path = lookup_process_path(process);
    if (!full_path.empty()) {
        result.command_line = full_path;
        size_t pos = full_path.find_last_of("\\/");
        if (pos != std::string::npos) {
            result.process_name = full_path.substr(pos + 1);
        } else {
            result.process_name = full_path;
        }
    }
    result.token.user_sid = lookup_user_sid(process);
    CloseHandle(process);
    return result;
}

}  // namespace dlp::process
