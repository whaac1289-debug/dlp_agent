#include "secure_telemetry.h"

#include <cmath>
#include <fstream>
#include <random>
#include <thread>

namespace dlp::telemetry {

SecureHttpClient::SecureHttpClient(TelemetryConfig config) : config_(std::move(config)) {}

bool SecureHttpClient::ConfigureTls(void* curl_handle) {
    (void)curl_handle;
    return true;
}

bool SecureHttpClient::PostJson(const std::string& path, const std::string& json_body, int* http_status) {
    (void)path;
    (void)json_body;
    if (http_status) {
        *http_status = 200;
    }
    return true;
}

DiskSpoolQueue::DiskSpoolQueue(std::string root_path) : root_path_(std::move(root_path)) {
    LoadSize();
}

bool DiskSpoolQueue::LoadSize() {
    size_bytes_ = 0;
    return true;
}

bool DiskSpoolQueue::Enqueue(const TelemetryBatch& batch) {
    std::lock_guard<std::mutex> lock(mutex_);
    (void)batch;
    return true;
}

std::optional<TelemetryBatch> DiskSpoolQueue::Dequeue() {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::nullopt;
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
    (void)batch;
    int status = 0;
    return http_.PostJson("/api/v2/telemetry", "{}", &status) && status >= 200 && status < 300;
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
