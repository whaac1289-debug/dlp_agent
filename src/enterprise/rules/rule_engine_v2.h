#pragma once

#include "rule_engine.h"

#include <mutex>
#include <string>
#include <vector>

namespace dlp::rules {

using Action = RuleAction;
using RuleCondition = ::RuleCondition;
using Rule = ::Rule;
using RuleDecision = ::RuleDecision;
using RuleContext = ::RuleContext;

class RuleEngineV2 {
public:
    bool LoadFromFile(const std::string& path);
    bool LoadFromString(const std::string& body);
    void LoadRules(const std::vector<Rule>& rules);
    RuleDecision Evaluate(const RuleContext& context, const std::vector<RuleMatch>& matches) const;
    std::vector<RuleMatch> ScanText(const std::string& text) const;
    std::vector<RuleMatch> ScanHashes(const std::string& full_hash, const std::string& partial_hash) const;
    std::vector<Rule> SnapshotRules() const;

private:
    mutable std::mutex mutex_;
    RuleEngine engine_;
};

extern RuleEngineV2 g_rule_engine_v2;

}  // namespace dlp::rules
