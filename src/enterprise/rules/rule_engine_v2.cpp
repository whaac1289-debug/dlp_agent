#include "rule_engine_v2.h"

#include <algorithm>

namespace dlp::rules {

void RuleEngineV2::LoadRules(const std::vector<Rule>& rules) {
    rules_ = rules;
    std::sort(rules_.begin(), rules_.end(), [](const Rule& a, const Rule& b) {
        return a.priority > b.priority;
    });
}

bool RuleEngineV2::MatchCondition(const RuleCondition& condition, const RuleContext& context) const {
    if (condition.field == "file.extension") {
        return context.file_extension == condition.value;
    }
    if (condition.field == "contains_pii") {
        return (condition.value == "true") == context.contains_pii;
    }
    if (condition.field == "process.name") {
        return context.process_name == condition.value;
    }
    if (condition.field == "destination") {
        return context.destination == condition.value;
    }
    auto it = context.attributes.find(condition.field);
    if (it == context.attributes.end()) {
        return false;
    }
    return it->second == condition.value;
}

RuleDecision RuleEngineV2::Evaluate(const RuleContext& context) const {
    for (const auto& rule : rules_) {
        bool match = true;
        for (const auto& condition : rule.conditions) {
            if (!MatchCondition(condition, context)) {
                match = false;
                break;
            }
        }
        if (!match) {
            continue;
        }
        RuleDecision decision;
        decision.rule_id = rule.id;
        decision.severity = rule.severity;
        if (!rule.actions.empty()) {
            decision.action = rule.actions.front();
        }
        return decision;
    }
    return {};
}

}  // namespace dlp::rules
