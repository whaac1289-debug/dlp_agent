#pragma once

#include <chrono>
#include <optional>
#include <string>

namespace dlp::policy {

struct PolicyPayload {
    std::string version;
    std::string json;
    std::string signature;
};

struct PolicyFetchConfig {
    std::string endpoint;
    std::string api_key;
    std::string hmac_key;
    std::string public_key_pem;
    std::chrono::seconds refresh_interval{300};
};

class PolicyFetcher {
public:
    explicit PolicyFetcher(PolicyFetchConfig config);
    std::optional<PolicyPayload> Fetch();
    bool VerifySignature(const PolicyPayload& payload);

private:
    PolicyFetchConfig config_;
};

}  // namespace dlp::policy
