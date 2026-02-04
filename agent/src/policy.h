#pragma once
#include <string>

#include "rule_engine.h"

struct PolicyDecision {
    RuleAction action{RuleAction::Allow};
    std::string decision;
    std::string reason;
    int severity{0};
};

bool is_usb_allowed(const std::string &serial);
PolicyDecision resolve_rule_decision(const RuleDecision &rule_decision,
                                     bool removable_drive,
                                     bool alert_on_removable);

const char *action_to_string(RuleAction action);
bool should_block_driver(const PolicyDecision &decision);
