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
PolicyDecision evaluate_file_policy(bool size_exceeded,
                                    bool keyword_hit,
                                    bool removable_drive,
                                    bool block_on_match,
                                    bool alert_on_removable);

PolicyDecision resolve_rule_decision(const RuleDecision &rule_decision,
                                     bool removable_drive,
                                     bool alert_on_removable);

const char *action_to_string(RuleAction action);
