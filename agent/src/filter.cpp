#include "filter.h"
#include "config.h"
#include <algorithm>
#include <cctype>

static std::string to_lower_str(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c){ return std::tolower(c); });
    return out;
}

bool extension_allowed(const std::string &name) {
    auto pos = name.rfind('.');
    if (pos == std::string::npos) return false;
    std::string ext = name.substr(pos);
    std::string ext_l = to_lower_str(ext);
    for (auto &e : g_extension_filter) {
        if (to_lower_str(e) == ext_l) return true;
    }
    return false;
}
