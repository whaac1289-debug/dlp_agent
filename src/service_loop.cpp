#include "service_loop.h"
#include "log.h"
#include "config.h"
#include "enterprise/rules/rule_engine_v2.h"
#include "enterprise/policy/policy_fetcher.h"
#include "enterprise/policy/policy_version_manager.h"

#include <chrono>
#include <thread>
#include <unordered_set>

namespace {

std::vector<Rule> BuildDefaultRules() {
    std::vector<Rule> defaults;
    if (!g_content_keywords.empty()) {
        Rule keyword_rule;
        keyword_rule.id = "default_keyword";
        keyword_rule.name = "Default Keyword Policy";
        keyword_rule.type = "keyword";
        keyword_rule.keywords = g_content_keywords;
        keyword_rule.severity = g_block_on_match ? g_block_severity_threshold : 4;
        keyword_rule.actions.push_back(g_block_on_match ? RuleAction::Block : RuleAction::Alert);
        defaults.push_back(keyword_rule);
    }
    Rule size_rule;
    size_rule.id = "default_size_threshold";
    size_rule.name = "Default Size Threshold";
    size_rule.severity = 3;
    size_rule.conditions.push_back({"size_exceeded", "==", "true"});
    size_rule.actions.push_back(RuleAction::Alert);
    defaults.push_back(size_rule);

    if (g_alert_on_removable) {
        Rule removable_rule;
        removable_rule.id = "default_removable_drive";
        removable_rule.name = "Default Removable Drive";
        removable_rule.severity = 2;
        removable_rule.conditions.push_back({"removable_drive", "==", "true"});
        removable_rule.actions.push_back(RuleAction::Alert);
        defaults.push_back(removable_rule);
    }
    return defaults;
}

void MergeDefaultRules(std::vector<Rule>& rules, const std::vector<Rule>& defaults) {
    std::unordered_set<std::string> existing_ids;
    for (const auto& rule : rules) {
        if (!rule.id.empty()) {
            existing_ids.insert(rule.id);
        }
    }
    for (const auto& rule : defaults) {
        if (rule.id.empty() || existing_ids.insert(rule.id).second) {
            rules.push_back(rule);
        }
    }
}

bool ApplyRulesFromPayload(const std::string& payload_json) {
    dlp::rules::RuleEngineV2 temp;
    if (!temp.LoadFromString(payload_json)) {
        return false;
    }
    auto rules = temp.SnapshotRules();
    auto defaults = BuildDefaultRules();
    MergeDefaultRules(rules, defaults);
    dlp::rules::g_rule_engine_v2.LoadRules(rules);
    return true;
}

bool LoadRulesFromFile(const std::string& path) {
    dlp::rules::RuleEngineV2 temp;
    if (!temp.LoadFromFile(path)) {
        return false;
    }
    auto rules = temp.SnapshotRules();
    auto defaults = BuildDefaultRules();
    MergeDefaultRules(rules, defaults);
    dlp::rules::g_rule_engine_v2.LoadRules(rules);
    return true;
}

}  // namespace

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
            if (ApplyRulesFromPayload(snapshot.json)) {
                std::lock_guard<std::mutex> lock(g_policy_mutex);
                g_policy_version = snapshot.version;
            }
        }
    } else {
        if (LoadRulesFromFile(g_rules_path)) {
            std::lock_guard<std::mutex> lock(g_policy_mutex);
            g_policy_version = "local";
        }
    }

    auto next_fetch = std::chrono::steady_clock::now();
    std::chrono::seconds refresh_interval = fetch_cfg.refresh_interval;

    while (g_running) {
        auto now = std::chrono::steady_clock::now();
        if (!g_policy_endpoint.empty() && now >= next_fetch) {
            next_fetch = now + refresh_interval;
            auto payload = fetcher.Fetch();
            if (payload && fetcher.VerifySignature(*payload)) {
                std::string current_version;
                {
                    std::lock_guard<std::mutex> lock(g_policy_mutex);
                    current_version = g_policy_version;
                }
                if (payload->version != current_version) {
                    dlp::policy::PolicySnapshot incoming;
                    incoming.version = payload->version;
                    incoming.json = payload->json;
                    bool applied = version_manager.ApplyAndPersist(incoming, [](const dlp::policy::PolicySnapshot &snap) {
                        return ApplyRulesFromPayload(snap.json);
                    });
                    if (!applied) {
                        version_manager.Rollback([](const dlp::policy::PolicySnapshot &snap) {
                            return ApplyRulesFromPayload(snap.json);
                        });
                    } else {
                        {
                            std::lock_guard<std::mutex> lock(g_policy_mutex);
                            g_policy_version = incoming.version;
                        }
                    }
                }
            }
        }
        log_info("heartbeat");
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    log_info("Service loop exiting");
}
