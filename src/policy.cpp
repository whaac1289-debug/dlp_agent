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

PolicyDecision evaluate_file_policy(bool size_exceeded,
                                    bool keyword_hit,
                                    bool removable_drive,
                                    bool block_on_match,
                                    bool alert_on_removable) {
    PolicyDecision out;
    std::vector<std::string> reasons;
    if (size_exceeded) reasons.push_back("size_threshold");
    if (keyword_hit) reasons.push_back("content_keyword");
    if (removable_drive && alert_on_removable) reasons.push_back("removable_drive");

    if (!reasons.empty()) {
        out.reason.clear();
        for (size_t i = 0; i < reasons.size(); ++i) {
            if (i) out.reason += ",";
            out.reason += reasons[i];
        }
        if (keyword_hit && block_on_match) {
            out.decision = "BLOCK";
        } else {
            out.decision = "ALERT";
        }
    } else {
        out.decision = "ALLOW";
        out.reason = "policy_ok";
    }
    return out;
}
