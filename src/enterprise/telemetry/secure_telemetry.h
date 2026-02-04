#pragma once

#include <chrono>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace dlp::telemetry {

struct TelemetryEvent {
    std::string id;
    std::string type;
    std::string payload_json;
    std::chrono::system_clock::time_point timestamp;
};

struct TelemetryBatch {
    std::vector<TelemetryEvent> events;
    std::string device_id;
    std::string policy_version;
};

struct RetryPolicy {
    std::chrono::milliseconds initial_backoff{500};
    std::chrono::milliseconds max_backoff{30000};
    double jitter{0.2};
    int max_attempts{8};
};

struct TelemetryConfig {
    std::string endpoint;
    std::string client_cert_path;
    std::string client_key_path;
    std::string ca_bundle_path;
    std::string pinned_spki_hash;
    std::string spool_path;
    size_t max_batch_size{250};
    size_t max_spool_size_bytes{50 * 1024 * 1024};
};

class SecureHttpClient {
public:
    explicit SecureHttpClient(TelemetryConfig config);
    bool PostJson(const std::string& path, const std::string& json_body, int* http_status);

private:
    TelemetryConfig config_;
    bool ConfigureTls(void* curl_handle);
};

class DiskSpoolQueue {
public:
    explicit DiskSpoolQueue(std::string root_path);
    bool Enqueue(const TelemetryBatch& batch);
    std::optional<TelemetryBatch> Dequeue();
    size_t SizeBytes() const;

private:
    std::string root_path_;
    mutable std::mutex mutex_;
    size_t size_bytes_{0};
    bool LoadSize();
};

class SecureTelemetry {
public:
    SecureTelemetry(TelemetryConfig config, RetryPolicy retry);
    void EnqueueEvent(const TelemetryEvent& event);
    void Flush();

private:
    TelemetryBatch BuildBatch();
    bool UploadBatch(const TelemetryBatch& batch);
    void RetryWithBackoff(const std::function<bool()>& fn);

    TelemetryConfig config_;
    RetryPolicy retry_;
    SecureHttpClient http_;
    DiskSpoolQueue spool_;
    std::mutex mutex_;
    std::deque<TelemetryEvent> pending_;
};

}  // namespace dlp::telemetry
