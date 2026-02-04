#include "rule_engine_v2.h"

namespace dlp::rules {

RuleEngineV2 g_rule_engine_v2;

bool RuleEngineV2::LoadFromFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    return engine_.load_from_file(path);
}

bool RuleEngineV2::LoadFromString(const std::string& body) {
    std::lock_guard<std::mutex> lock(mutex_);
    return engine_.load_from_string(body);
}

void RuleEngineV2::LoadRules(const std::vector<Rule>& rules) {
    std::lock_guard<std::mutex> lock(mutex_);
    engine_.load_from_rules(rules);
}

RuleDecision RuleEngineV2::Evaluate(const RuleContext& context, const std::vector<RuleMatch>& matches) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return engine_.evaluate(context, matches);
}

std::vector<RuleMatch> RuleEngineV2::ScanText(const std::string& text) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return engine_.scan_text(text);
}

std::vector<RuleMatch> RuleEngineV2::ScanHashes(const std::string& full_hash,
                                                const std::string& partial_hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return engine_.scan_hashes(full_hash, partial_hash);
}

std::vector<Rule> RuleEngineV2::SnapshotRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return engine_.rules();
}

}  // namespace dlp::rules
