#pragma once
#include <string>

struct PolicyDecision {
    std::string decision;
    std::string reason;
};

bool is_usb_allowed(const std::string &serial);
PolicyDecision evaluate_file_policy(bool size_exceeded,
                                    bool keyword_hit,
                                    bool removable_drive,
                                    bool block_on_match,
                                    bool alert_on_removable);
