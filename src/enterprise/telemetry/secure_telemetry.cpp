#include "secure_telemetry.h"

#include <chrono>
#include <cmath>
#include <curl/curl.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <thread>

namespace dlp::telemetry {

SecureHttpClient::SecureHttpClient(TelemetryConfig config) : config_(std::move(config)) {}

bool SecureHttpClient::ConfigureTls(void* curl_handle) {
    auto* curl = static_cast<CURL*>(curl_handle);
    if (!config_.ca_bundle_path.empty()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, config_.ca_bundle_path.c_str());
    }
    if (!config_.client_cert_path.empty()) {
        curl_easy_setopt(curl, CURLOPT_SSLCERT, config_.client_cert_path.c_str());
    }
    if (!config_.client_key_path.empty()) {
        curl_easy_setopt(curl, CURLOPT_SSLKEY, config_.client_key_path.c_str());
    }
    if (!config_.pinned_spki_hash.empty()) {
        curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, config_.pinned_spki_hash.c_str());
    }
    return true;
}

bool SecureHttpClient::PostJson(const std::string& path, const std::string& json_body, int* http_status) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }
    ConfigureTls(curl);
    std::string url = config_.endpoint + path;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dlp_agent/2.0");
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body.c_str());
    CURLcode res = curl_easy_perform(curl);
    bool ok = false;
    if (res == CURLE_OK) {
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        if (http_status) {
            *http_status = static_cast<int>(code);
        }
        ok = (code >= 200 && code < 300);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return ok;
}

DiskSpoolQueue::DiskSpoolQueue(std::string root_path) : root_path_(std::move(root_path)) {
    LoadSize();
}

bool DiskSpoolQueue::LoadSize() {
    namespace fs = std::filesystem;
    std::lock_guard<std::mutex> lock(mutex_);
    size_bytes_ = 0;
    if (root_path_.empty()) {
        return false;
    }
    fs::create_directories(root_path_);
    for (const auto& entry : fs::directory_iterator(root_path_)) {
        if (!entry.is_regular_file()) continue;
        size_bytes_ += static_cast<size_t>(entry.file_size());
    }
    return true;
}

bool DiskSpoolQueue::Enqueue(const TelemetryBatch& batch) {
    std::lock_guard<std::mutex> lock(mutex_);
    namespace fs = std::filesystem;
    if (root_path_.empty()) return false;
    fs::create_directories(root_path_);
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto stamp = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    std::string file_path = root_path_ + "/batch_" + std::to_string(stamp) + ".json";
    std::ofstream out(file_path, std::ios::trunc);
    if (!out.is_open()) return false;
    out << "{";
    out << "\"device_id\":\"" << batch.device_id << "\",";
    out << "\"policy_version\":\"" << batch.policy_version << "\",";
    out << "\"events\":[";
    for (size_t i = 0; i < batch.events.size(); ++i) {
        const auto& ev = batch.events[i];
        if (i) out << ",";
        out << "{"
            << "\"id\":\"" << ev.id << "\","
            << "\"type\":\"" << ev.type << "\","
            << "\"payload\":" << ev.payload_json
            << "}";
    }
    out << "]}";
    out.close();
    if (out.fail()) return false;
    size_bytes_ += static_cast<size_t>(fs::file_size(file_path));
    return true;
}

std::optional<TelemetryBatch> DiskSpoolQueue::Dequeue() {
    std::lock_guard<std::mutex> lock(mutex_);
    namespace fs = std::filesystem;
    if (root_path_.empty()) return std::nullopt;
    fs::create_directories(root_path_);
    fs::path oldest;
    for (const auto& entry : fs::directory_iterator(root_path_)) {
        if (!entry.is_regular_file()) continue;
        if (oldest.empty() || entry.path().filename().string() < oldest.filename().string()) {
            oldest = entry.path();
        }
    }
    if (oldest.empty()) return std::nullopt;
    std::ifstream in(oldest, std::ios::in);
    if (!in.is_open()) return std::nullopt;
    std::ostringstream oss;
    oss << in.rdbuf();
    in.close();
    TelemetryBatch batch;
    batch.device_id = "";
    batch.policy_version = "";
    TelemetryEvent ev;
    ev.id = oldest.filename().string();
    ev.type = "spooled";
    ev.payload_json = oss.str();
    ev.timestamp = std::chrono::system_clock::now();
    batch.events.push_back(ev);
    size_bytes_ -= static_cast<size_t>(fs::file_size(oldest));
    fs::remove(oldest);
    return batch;
}

size_t DiskSpoolQueue::SizeBytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return size_bytes_;
}

SecureTelemetry::SecureTelemetry(TelemetryConfig config, RetryPolicy retry)
    : config_(std::move(config)),
      retry_(retry),
      http_(config_),
      spool_(config_.spool_path) {}

void SecureTelemetry::EnqueueEvent(const TelemetryEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.push_back(event);
}

TelemetryBatch SecureTelemetry::BuildBatch() {
    TelemetryBatch batch;
    std::lock_guard<std::mutex> lock(mutex_);
    while (!pending_.empty() && batch.events.size() < config_.max_batch_size) {
        batch.events.push_back(pending_.front());
        pending_.pop_front();
    }
    return batch;
}

bool SecureTelemetry::UploadBatch(const TelemetryBatch& batch) {
    int status = 0;
    std::ostringstream oss;
    oss << "{";
    oss << "\"device_id\":\"" << batch.device_id << "\",";
    oss << "\"policy_version\":\"" << batch.policy_version << "\",";
    oss << "\"events\":[";
    for (size_t i = 0; i < batch.events.size(); ++i) {
        const auto& ev = batch.events[i];
        if (i) oss << ",";
        oss << "{"
            << "\"id\":\"" << ev.id << "\","
            << "\"type\":\"" << ev.type << "\","
            << "\"timestamp_ms\":" << std::chrono::duration_cast<std::chrono::milliseconds>(ev.timestamp.time_since_epoch()).count() << ","
            << "\"payload\":" << ev.payload_json
            << "}";
    }
    oss << "]}";
    return http_.PostJson("", oss.str(), &status) && status >= 200 && status < 300;
}

void SecureTelemetry::RetryWithBackoff(const std::function<bool()>& fn) {
    std::default_random_engine rng(std::random_device{}());
    std::uniform_real_distribution<double> jitter_dist(1.0 - retry_.jitter, 1.0 + retry_.jitter);

    for (int attempt = 0; attempt < retry_.max_attempts; ++attempt) {
        if (fn()) {
            return;
        }
        double backoff = std::min(
            static_cast<double>(retry_.max_backoff.count()),
            static_cast<double>(retry_.initial_backoff.count()) * std::pow(2.0, attempt));
        auto sleep_ms = static_cast<int>(backoff * jitter_dist(rng));
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    }
}

void SecureTelemetry::Flush() {
    TelemetryBatch batch = BuildBatch();
    if (batch.events.empty()) {
        if (auto queued = spool_.Dequeue()) {
            batch = std::move(*queued);
        }
    }
    if (batch.events.empty()) {
        return;
    }
    RetryWithBackoff([this, &batch]() {
        if (!UploadBatch(batch)) {
            spool_.Enqueue(batch);
            return false;
        }
        return true;
    });
}

}  // namespace dlp::telemetry
