#include <cassert>
#include <chrono>

#include "../src/enterprise/telemetry/secure_telemetry.h"

#if defined(DLP_ENABLE_TESTS)

using dlp::telemetry::RetryPolicy;
using dlp::telemetry::SecureTelemetry;
using dlp::telemetry::TelemetryConfig;
using dlp::telemetry::TelemetryEvent;

int main() {
    TelemetryConfig config;
    config.endpoint = "https://telemetry.example";
    config.spool_path = "spool";

    RetryPolicy retry;
    SecureTelemetry telemetry{config, retry};
    telemetry.EnqueueEvent({"1", "test", "{}", std::chrono::system_clock::now()});
    telemetry.Flush();
    assert(true);
    return 0;
}

#endif
