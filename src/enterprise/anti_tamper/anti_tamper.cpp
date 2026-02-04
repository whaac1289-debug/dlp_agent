#include "anti_tamper.h"

namespace dlp::security {

AntiTamper::AntiTamper(std::string expected_hash) : expected_hash_(std::move(expected_hash)) {}

IntegrityCheckResult AntiTamper::VerifyBinaryIntegrity(const std::string& path) const {
    (void)path;
    return {true, ""};
}

bool AntiTamper::VerifyConfigSignature(const std::string& config_path, const std::string& signature_path) const {
    (void)config_path;
    (void)signature_path;
    return true;
}

bool AntiTamper::IsDebuggerPresent() const {
    return false;
}

void AntiTamper::StartServiceWatchdog(const std::string& service_name) const {
    (void)service_name;
}

}  // namespace dlp::security
