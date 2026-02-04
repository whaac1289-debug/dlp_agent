#include "rule_engine.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <regex>
#include <sstream>

RuleEngine g_rule_engine;

static std::string trim_copy(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) ++start;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) --end;
    return s.substr(start, end - start);
}

static std::string to_lower_copy(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return out;
}

static std::string extract_string_field(const std::string &s, const std::string &key) {
    auto pos = s.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    auto colon = s.find(':', pos);
    if (colon == std::string::npos) return "";
    auto first = s.find('"', colon + 1);
    if (first == std::string::npos) return "";
    auto second = s.find('"', first + 1);
    if (second == std::string::npos) return "";
    return s.substr(first + 1, second - first - 1);
}

static int extract_int_field(const std::string &s, const std::string &key, int default_value) {
    auto pos = s.find("\"" + key + "\"");
    if (pos == std::string::npos) return default_value;
    auto colon = s.find(':', pos);
    if (colon == std::string::npos) return default_value;
    size_t i = colon + 1;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    size_t j = i;
    if (j < s.size() && s[j] == '-') ++j;
    while (j < s.size() && std::isdigit(static_cast<unsigned char>(s[j]))) ++j;
    if (j > i) {
        return std::stoi(s.substr(i, j - i));
    }
    return default_value;
}

static std::vector<std::string> extract_array_field(const std::string &s, const std::string &key) {
    std::vector<std::string> out;
    auto pos = s.find("\"" + key + "\"");
    if (pos == std::string::npos) return out;
    auto colon = s.find(':', pos);
    if (colon == std::string::npos) return out;
    auto lb = s.find('[', colon);
    auto rb = s.find(']', lb);
    if (lb == std::string::npos || rb == std::string::npos) return out;
    std::string body = s.substr(lb + 1, rb - lb - 1);
    std::istringstream iss(body);
    std::string token;
    while (std::getline(iss, token, ',')) {
        auto first = token.find('"');
        if (first == std::string::npos) continue;
        auto second = token.find('"', first + 1);
        if (second == std::string::npos) continue;
        out.push_back(token.substr(first + 1, second - first - 1));
    }
    return out;
}

static std::vector<Rule> parse_json_rules(const std::string &s) {
    std::vector<Rule> rules;
    auto rules_pos = s.find("\"rules\"");
    if (rules_pos == std::string::npos) return rules;
    auto lb = s.find('[', rules_pos);
    if (lb == std::string::npos) return rules;
    size_t i = lb + 1;
    int depth = 0;
    size_t obj_start = std::string::npos;
    for (; i < s.size(); ++i) {
        char c = s[i];
        if (c == '{') {
            if (depth == 0) obj_start = i;
            depth++;
        } else if (c == '}') {
            depth--;
            if (depth == 0 && obj_start != std::string::npos) {
                std::string obj = s.substr(obj_start, i - obj_start + 1);
                Rule rule;
                rule.id = extract_string_field(obj, "id");
                rule.name = extract_string_field(obj, "name");
                rule.type = to_lower_copy(extract_string_field(obj, "type"));
                rule.priority = extract_int_field(obj, "priority", 0);
                rule.severity = extract_int_field(obj, "severity", 0);
                rule.pattern = extract_string_field(obj, "pattern");
                rule.keywords = extract_array_field(obj, "keywords");
                rule.hashes = extract_array_field(obj, "hashes");
                if (!rule.type.empty()) {
                    rules.push_back(rule);
                }
                obj_start = std::string::npos;
            }
        } else if (c == ']') {
            if (depth == 0) break;
        }
    }
    return rules;
}

static std::vector<std::string> parse_yaml_inline_list(const std::string &value) {
    std::vector<std::string> out;
    auto lb = value.find('[');
    auto rb = value.find(']');
    if (lb == std::string::npos || rb == std::string::npos || rb <= lb) return out;
    std::string body = value.substr(lb + 1, rb - lb - 1);
    std::istringstream iss(body);
    std::string token;
    while (std::getline(iss, token, ',')) {
        token = trim_copy(token);
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.size() - 2);
        }
        if (!token.empty()) out.push_back(token);
    }
    return out;
}

static std::vector<Rule> parse_yaml_rules(const std::string &s) {
    std::vector<Rule> rules;
    std::istringstream iss(s);
    std::string line;
    Rule current;
    bool in_rule = false;
    while (std::getline(iss, line)) {
        auto trimmed = trim_copy(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;
        if (trimmed.rfind("-", 0) == 0) {
            if (in_rule && !current.type.empty()) {
                rules.push_back(current);
            }
            current = Rule();
            in_rule = true;
            auto rest = trim_copy(trimmed.substr(1));
            if (!rest.empty()) {
                auto colon = rest.find(':');
                if (colon != std::string::npos) {
                    auto key = trim_copy(rest.substr(0, colon));
                    auto value = trim_copy(rest.substr(colon + 1));
                    if (key == "id") current.id = value;
                    if (key == "name") current.name = value;
                    if (key == "type") current.type = to_lower_copy(value);
                }
            }
            continue;
        }
        if (!in_rule) continue;
        auto colon = trimmed.find(':');
        if (colon == std::string::npos) continue;
        auto key = trim_copy(trimmed.substr(0, colon));
        auto value = trim_copy(trimmed.substr(colon + 1));
        if (key == "id") current.id = value;
        else if (key == "name") current.name = value;
        else if (key == "type") current.type = to_lower_copy(value);
        else if (key == "pattern") current.pattern = value;
        else if (key == "priority") current.priority = std::stoi(value);
        else if (key == "severity") current.severity = std::stoi(value);
        else if (key == "keywords") current.keywords = parse_yaml_inline_list(value);
        else if (key == "hashes") current.hashes = parse_yaml_inline_list(value);
    }
    if (in_rule && !current.type.empty()) {
        rules.push_back(current);
    }
    return rules;
}

static double compute_confidence(const Rule &rule, size_t match_count) {
    double base = std::min(1.0, std::max(0.0, rule.severity / 10.0));
    double boost = 0.0;
    if (rule.type == "regex") boost = 0.2;
    else if (rule.type == "keyword") boost = match_count > 1 ? 0.15 : 0.1;
    else if (rule.type == "hash") boost = 0.4;
    double conf = base + boost;
    if (match_count > 3) conf += 0.05;
    return std::min(1.0, conf);
}

bool RuleEngine::load_from_file(const std::string &path) {
    std::ifstream ifs(path);
    if (!ifs) {
        rules_.clear();
        return false;
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    std::string body = oss.str();
    std::string trimmed = trim_copy(body);
    if (trimmed.empty()) {
        rules_.clear();
        return true;
    }
    if (!trimmed.empty() && (trimmed[0] == '{' || trimmed[0] == '[')) {
        rules_ = parse_json_rules(body);
    } else {
        rules_ = parse_yaml_rules(body);
    }
    return true;
}

std::vector<RuleMatch> RuleEngine::scan_text(const std::string &text) const {
    std::vector<RuleMatch> hits;
    if (text.empty()) return hits;
    std::string lower = to_lower_copy(text);
    for (const auto &rule : rules_) {
        if (rule.type == "regex" && !rule.pattern.empty()) {
            try {
                std::regex re(rule.pattern, std::regex::ECMAScript);
                auto begin = std::sregex_iterator(text.begin(), text.end(), re);
                auto end = std::sregex_iterator();
                size_t count = static_cast<size_t>(std::distance(begin, end));
                if (count > 0) {
                    RuleMatch match;
                    match.rule_id = rule.id;
                    match.rule_name = rule.name;
                    match.type = rule.type;
                    match.priority = rule.priority;
                    match.severity = rule.severity;
                    match.match_count = count;
                    match.match = begin->str();
                    match.confidence = compute_confidence(rule, count);
                    hits.push_back(match);
                }
            } catch (const std::regex_error &) {
                continue;
            }
        } else if (rule.type == "keyword" && !rule.keywords.empty()) {
            size_t count = 0;
            std::string first_hit;
            for (const auto &kw : rule.keywords) {
                auto kw_lower = to_lower_copy(kw);
                if (!kw_lower.empty() && lower.find(kw_lower) != std::string::npos) {
                    count++;
                    if (first_hit.empty()) first_hit = kw;
                }
            }
            if (count > 0) {
                RuleMatch match;
                match.rule_id = rule.id;
                match.rule_name = rule.name;
                match.type = rule.type;
                match.priority = rule.priority;
                match.severity = rule.severity;
                match.match_count = count;
                match.match = first_hit;
                match.confidence = compute_confidence(rule, count);
                hits.push_back(match);
            }
        }
    }
    return hits;
}

std::vector<RuleMatch> RuleEngine::scan_hashes(const std::string &full_hash,
                                               const std::string &partial_hash) const {
    std::vector<RuleMatch> hits;
    if (full_hash.empty() && partial_hash.empty()) return hits;
    for (const auto &rule : rules_) {
        if (rule.type != "hash" || rule.hashes.empty()) continue;
        for (const auto &hash : rule.hashes) {
            if ((!full_hash.empty() && hash == full_hash) ||
                (!partial_hash.empty() && hash == partial_hash)) {
                RuleMatch match;
                match.rule_id = rule.id;
                match.rule_name = rule.name;
                match.type = rule.type;
                match.priority = rule.priority;
                match.severity = rule.severity;
                match.match_count = 1;
                match.match = hash;
                match.confidence = compute_confidence(rule, 1);
                hits.push_back(match);
                break;
            }
        }
    }
    return hits;
}

const std::vector<Rule> &RuleEngine::rules() const {
    return rules_;
}
