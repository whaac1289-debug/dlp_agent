#pragma once

#include "rule_engine.h"

#include <vector>

namespace dlp::rules {

using Action = RuleAction;
using RuleCondition = ::RuleCondition;
using Rule = ::Rule;
using RuleDecision = ::RuleDecision;
using RuleContext = ::RuleContext;

class RuleEngineV2 {
public:
    void LoadRules(const std::vector<Rule>& rules);
    RuleDecision Evaluate(const RuleContext& context) const;
    const std::vector<Rule> &Rules() const;

private:
    RuleEngine engine_;
};

}  // namespace dlp::rules
