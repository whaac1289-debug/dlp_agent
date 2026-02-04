#include "policy.h"
#include "config.h"
#include <algorithm>
#include <cctype>

static std::string to_lower_str_pol(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c){ return std::tolower(c); });
    return out;
}

bool is_usb_allowed(const std::string &serial) {
    std::string ser_l = to_lower_str_pol(serial);
    for (auto &s : g_usb_allow_serials) {
        if (to_lower_str_pol(s) == ser_l) return true;
    }
    return false;
}

const char *action_to_string(RuleAction action) {
    switch (action) {
        case RuleAction::Allow: return "ALLOW";
        case RuleAction::Alert: return "ALERT";
        case RuleAction::Block: return "BLOCK";
        case RuleAction::Quarantine: return "QUARANTINE";
        case RuleAction::ShadowCopy: return "SHADOW_COPY";
    }
    return "ALLOW";
}

bool should_block_driver(const PolicyDecision &decision) {
    return decision.action == RuleAction::Block || decision.action == RuleAction::Quarantine;
}

PolicyDecision resolve_rule_decision(const RuleDecision &rule_decision,
                                     bool removable_drive,
                                     bool alert_on_removable) {
    PolicyDecision out;
    out.action = rule_decision.action;
    out.severity = rule_decision.severity;
    if (out.action == RuleAction::Allow && removable_drive && alert_on_removable) {
        out.action = RuleAction::Alert;
        out.reason = "removable_drive";
    } else {
        out.reason = rule_decision.reason;
    }
    if (out.reason.empty()) {
        out.reason = "no_match";
    }
    out.decision = action_to_string(out.action);
    return out;
}
