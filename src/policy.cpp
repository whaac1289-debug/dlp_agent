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
