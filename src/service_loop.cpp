#include "service_loop.h"
#include "log.h"
#include "config.h"
#include "rule_engine.h"
#include "enterprise/policy/policy_fetcher.h"
#include "enterprise/policy/policy_version_manager.h"

#include <chrono>
#include <thread>

void service_loop() {
    log_info("Service loop started");
    dlp::policy::PolicyFetchConfig fetch_cfg;
    fetch_cfg.endpoint = g_policy_endpoint;
    fetch_cfg.api_key = g_policy_api_key;
    fetch_cfg.hmac_key = g_policy_hmac_key;
    fetch_cfg.public_key_pem = g_policy_public_key;
    dlp::policy::PolicyFetcher fetcher(fetch_cfg);
    dlp::policy::PolicyVersionManager version_manager(g_policy_store_path);
    dlp::policy::PolicySnapshot snapshot;
    if (version_manager.LoadLastKnown(&snapshot)) {
        if (!snapshot.json.empty()) {
            g_rule_engine.load_from_string(snapshot.json);
        }
    }

    while (g_running) {
        if (!g_policy_endpoint.empty()) {
            auto payload = fetcher.Fetch();
            if (payload && fetcher.VerifySignature(*payload)) {
                dlp::policy::PolicySnapshot incoming;
                incoming.version = payload->version;
                incoming.json = payload->json;
                version_manager.ApplyAndPersist(incoming, [](const dlp::policy::PolicySnapshot &snap) {
                    return g_rule_engine.load_from_string(snap.json);
                });
            }
        }
        log_info("heartbeat");
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }
    log_info("Service loop exiting");
}
