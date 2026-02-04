#include "anti_tamper.h"

#include "hash.h"
#include "log.h"
#include "config.h"

#include <fstream>
#include <chrono>
#include <thread>
#include <vector>
#include <windows.h>

namespace dlp::security {

AntiTamper::AntiTamper(std::string expected_hash) : expected_hash_(std::move(expected_hash)) {}

static std::string read_file_hash(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        return {};
    }
    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(input)),
                                      std::istreambuf_iterator<char>());
    if (buffer.empty()) return {};
    return sha256_hex(buffer.data(), buffer.size());
}

IntegrityCheckResult AntiTamper::VerifyBinaryIntegrity(const std::string& path) const {
    if (expected_hash_.empty()) {
        return {true, "no_expected_hash"};
    }
    std::string hash = read_file_hash(path);
    if (hash.empty()) {
        return {false, "hash_read_failed"};
    }
    if (hash != expected_hash_) {
        return {false, "hash_mismatch"};
    }
    return {true, "hash_ok"};
}

bool AntiTamper::VerifyConfigSignature(const std::string& config_path, const std::string& signature_path) const {
    std::ifstream sig(signature_path, std::ios::in);
    if (!sig.is_open()) {
        return false;
    }
    std::string expected;
    std::getline(sig, expected);
    if (expected.empty()) return false;
    std::string actual = read_file_hash(config_path);
    return !actual.empty() && actual == expected;
}

bool AntiTamper::IsDebuggerPresent() const {
    return ::IsDebuggerPresent() == TRUE;
}

void AntiTamper::StartServiceWatchdog(const std::string& service_name) const {
    std::thread([service_name]() {
        while (g_running) {
            SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!scm) {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                continue;
            }
            SC_HANDLE svc = OpenServiceA(scm, service_name.c_str(), SERVICE_QUERY_STATUS);
            if (svc) {
                SERVICE_STATUS status;
                if (!QueryServiceStatus(svc, &status) || status.dwCurrentState != SERVICE_RUNNING) {
                    log_error("Service watchdog: %s not running", service_name.c_str());
                }
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }).detach();
}

}  // namespace dlp::security
