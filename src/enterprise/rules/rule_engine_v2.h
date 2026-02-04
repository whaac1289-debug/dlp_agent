#pragma once

#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dlp::rules {

enum class Action {
    Allow,
    Alert,
    Block,
    Quarantine
};

struct RuleCondition {
    std::string field;
    std::string op;
    std::string value;
};

struct Rule {
    std::string id;
    int priority{0};
    std::string severity;
    std::vector<RuleCondition> conditions;
    std::vector<Action> actions;
    std::vector<std::string> chain_to;
};

struct RuleDecision {
    Action action{Action::Allow};
    std::string rule_id;
    std::string severity;
};

struct RuleContext {
    std::string file_extension;
    bool contains_pii{false};
    std::string process_name;
    std::string destination;
    std::unordered_map<std::string, std::string> attributes;
};

class RuleEngineV2 {
public:
    void LoadRules(const std::vector<Rule>& rules);
    RuleDecision Evaluate(const RuleContext& context) const;

private:
    std::vector<Rule> rules_;
    bool MatchCondition(const RuleCondition& condition, const RuleContext& context) const;
};

}  // namespace dlp::rules
