#pragma once

#include <string>
#include <vector>

namespace dlp::security {

struct IntegrityCheckResult {
    bool ok{false};
    std::string detail;
};

class AntiTamper {
public:
    explicit AntiTamper(std::string expected_hash);

    IntegrityCheckResult VerifyBinaryIntegrity(const std::string& path) const;
    bool VerifyConfigSignature(const std::string& config_path, const std::string& signature_path) const;
    bool IsDebuggerPresent() const;
    void StartServiceWatchdog(const std::string& service_name) const;

private:
    std::string expected_hash_;
};

}  // namespace dlp::security
