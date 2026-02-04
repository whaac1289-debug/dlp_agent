#include "policy_fetcher.h"

#include "hash.h"

#include <curl/curl.h>
#include <fstream>
#include <sstream>

namespace dlp::policy {

PolicyFetcher::PolicyFetcher(PolicyFetchConfig config) : config_(std::move(config)) {}

static size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

static std::string extract_string_field(const std::string& s, const std::string& key) {
    auto pos = s.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    auto colon = s.find(':', pos);
    if (colon == std::string::npos) return "";
    auto first = s.find('"', colon + 1);
    if (first == std::string::npos) return "";
    auto second = s.find('"', first + 1);
    if (second == std::string::npos) return "";
    return s.substr(first + 1, second - first - 1);
}

std::optional<PolicyPayload> PolicyFetcher::Fetch() {
    if (config_.endpoint.empty()) {
        return std::nullopt;
    }
    PolicyPayload payload;
    if (config_.endpoint.rfind("file://", 0) == 0) {
        std::string path = config_.endpoint.substr(7);
        std::ifstream input(path);
        if (!input.is_open()) return std::nullopt;
        std::ostringstream oss;
        oss << input.rdbuf();
        payload.json = oss.str();
        payload.version = extract_string_field(payload.json, "version");
        if (payload.version.empty()) {
            payload.version = "file";
        }
        payload.signature = extract_string_field(payload.json, "signature");
        return payload;
    }
    CURL* curl = curl_easy_init();
    if (!curl) return std::nullopt;
    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, config_.endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    struct curl_slist* headers = nullptr;
    if (!config_.api_key.empty()) {
        std::string header = "Authorization: Bearer " + config_.api_key;
        headers = curl_slist_append(headers, header.c_str());
    }
    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK || code < 200 || code >= 300) {
        return std::nullopt;
    }
    payload.json = response;
    payload.signature = extract_string_field(payload.json, "signature");
    payload.version = extract_string_field(payload.json, "version");
    if (payload.version.empty()) {
        payload.version = std::to_string(code);
    }
    return payload;
}

bool PolicyFetcher::VerifySignature(const PolicyPayload& payload) {
    if (!config_.hmac_key.empty()) {
        std::string material = payload.json + config_.hmac_key;
        std::string expected = sha256_hex(material.data(), material.size());
        return !payload.signature.empty() && payload.signature == expected;
    }
    if (!config_.public_key_pem.empty()) {
        return !payload.signature.empty();
    }
    return true;
}

}  // namespace dlp::policy
