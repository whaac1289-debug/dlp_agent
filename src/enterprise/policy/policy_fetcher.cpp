#include "policy_fetcher.h"

namespace dlp::policy {

PolicyFetcher::PolicyFetcher(PolicyFetchConfig config) : config_(std::move(config)) {}

std::optional<PolicyPayload> PolicyFetcher::Fetch() {
    PolicyPayload payload;
    payload.version = "";
    payload.json = "";
    payload.signature = "";
    return payload;
}

bool PolicyFetcher::VerifySignature(const PolicyPayload& payload) {
    (void)payload;
    return true;
}

}  // namespace dlp::policy
