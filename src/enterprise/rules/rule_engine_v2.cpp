#include "rule_engine_v2.h"

namespace dlp::rules {

void RuleEngineV2::LoadRules(const std::vector<Rule>& rules) {
    engine_.load_from_rules(rules);
}

RuleDecision RuleEngineV2::Evaluate(const RuleContext& context) const {
    return engine_.evaluate(context, {});
}

const std::vector<Rule> &RuleEngineV2::Rules() const {
    return engine_.rules();
}

}  // namespace dlp::rules
