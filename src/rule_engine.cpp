#include "rule_engine.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <regex>
#include <sstream>

#include "config.h"

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

static bool extract_bool_field(const std::string &s, const std::string &key, bool default_value) {
    auto pos = s.find("\"" + key + "\"");
    if (pos == std::string::npos) return default_value;
    auto colon = s.find(':', pos);
    if (colon == std::string::npos) return default_value;
    size_t i = colon + 1;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    if (s.compare(i, 4, "true") == 0) return true;
    if (s.compare(i, 5, "false") == 0) return false;
    return default_value;
}

static int severity_from_string(const std::string &value, int fallback) {
    std::string lower = to_lower_copy(value);
    if (lower == "low") return 3;
    if (lower == "medium") return 6;
    if (lower == "high") return 8;
    if (lower == "critical") return 10;
    if (lower.empty()) return fallback;
    bool numeric = std::all_of(lower.begin(), lower.end(), [](unsigned char c){ return std::isdigit(c) || c == '-'; });
    if (numeric) return std::stoi(lower);
    return fallback;
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

static std::vector<RuleCondition> extract_conditions_field(const std::string &s, const std::string &key) {
    std::vector<RuleCondition> out;
    auto pos = s.find("\"" + key + "\"");
    if (pos == std::string::npos) return out;
    auto colon = s.find(':', pos);
    if (colon == std::string::npos) return out;
    auto lb = s.find('[', colon);
    auto rb = s.find(']', lb);
    if (lb == std::string::npos || rb == std::string::npos) return out;
    size_t i = lb + 1;
    int depth = 0;
    size_t obj_start = std::string::npos;
    for (; i < rb; ++i) {
        char c = s[i];
        if (c == '{') {
            if (depth == 0) obj_start = i;
            depth++;
        } else if (c == '}') {
            depth--;
            if (depth == 0 && obj_start != std::string::npos) {
                std::string obj = s.substr(obj_start, i - obj_start + 1);
                RuleCondition cond;
                cond.field = extract_string_field(obj, "field");
                cond.op = extract_string_field(obj, "op");
                cond.value = extract_string_field(obj, "value");
                if (!cond.field.empty()) {
                    out.push_back(cond);
                }
                obj_start = std::string::npos;
            }
        }
    }
    return out;
}

static RuleAction parse_action(const std::string &action) {
    std::string lower = to_lower_copy(action);
    if (lower == "allow") return RuleAction::Allow;
    if (lower == "alert") return RuleAction::Alert;
    if (lower == "block") return RuleAction::Block;
    if (lower == "quarantine") return RuleAction::Quarantine;
    if (lower == "shadow-copy" || lower == "shadow_copy" || lower == "shadowcopy") return RuleAction::ShadowCopy;
    return RuleAction::Allow;
}

static std::vector<RuleAction> extract_actions_field(const std::string &s, const std::string &key) {
    std::vector<RuleAction> out;
    auto items = extract_array_field(s, key);
    for (const auto &item : items) {
        out.push_back(parse_action(item));
    }
    if (out.empty()) {
        auto single = extract_string_field(s, key);
        if (!single.empty()) {
            out.push_back(parse_action(single));
        }
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
                if (rule.severity == 0) {
                    rule.severity = severity_from_string(extract_string_field(obj, "severity"), rule.severity);
                }
                rule.pattern = extract_string_field(obj, "pattern");
                rule.keywords = extract_array_field(obj, "keywords");
                rule.hashes = extract_array_field(obj, "hashes");
                rule.conditions = extract_conditions_field(obj, "conditions");
                rule.actions = extract_actions_field(obj, "actions");
                rule.enabled = extract_bool_field(obj, "enabled", true);
                if (!rule.type.empty() || !rule.conditions.empty()) {
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
        else if (key == "actions") {
            auto actions = parse_yaml_inline_list(value);
            current.actions.clear();
            for (const auto &action : actions) {
                current.actions.push_back(parse_action(action));
            }
        } else if (key == "enabled") {
            current.enabled = (value == "true" || value == "1");
        }
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

static int action_rank(RuleAction action) {
    switch (action) {
        case RuleAction::Block: return 5;
        case RuleAction::Quarantine: return 4;
        case RuleAction::ShadowCopy: return 3;
        case RuleAction::Alert: return 2;
        case RuleAction::Allow: return 1;
    }
    return 0;
}

static RuleAction default_action_for_severity(int severity) {
    if (g_enable_quarantine && severity >= g_quarantine_severity_threshold) {
        return RuleAction::Quarantine;
    }
    if (severity >= g_block_severity_threshold) {
        return RuleAction::Block;
    }
    if (g_enable_shadow_copy && severity >= g_shadow_copy_severity_threshold) {
        return RuleAction::ShadowCopy;
    }
    if (severity > 0) {
        return RuleAction::Alert;
    }
    return RuleAction::Allow;
}

static bool bool_value_match(const std::string &value, bool actual) {
    std::string lower = to_lower_copy(value);
    if (lower == "true" || lower == "1") return actual;
    if (lower == "false" || lower == "0") return !actual;
    return false;
}

static bool string_match(const std::string &op, const std::string &actual, const std::string &expected) {
    std::string op_lower = to_lower_copy(op);
    if (op_lower.empty() || op_lower == "equals" || op_lower == "eq" || op_lower == "==") {
        return actual == expected;
    }
    if (op_lower == "contains") {
        return actual.find(expected) != std::string::npos;
    }
    if (op_lower == "starts_with") {
        return actual.rfind(expected, 0) == 0;
    }
    if (op_lower == "ends_with") {
        if (expected.size() > actual.size()) return false;
        return actual.compare(actual.size() - expected.size(), expected.size(), expected) == 0;
    }
    return actual == expected;
}

static bool match_condition(const RuleCondition &condition, const RuleContext &context) {
    std::string field = to_lower_copy(condition.field);
    if (field == "file.extension") {
        return string_match(condition.op, context.extension, condition.value);
    }
    if (field == "file.path") {
        return string_match(condition.op, context.path, condition.value);
    }
    if (field == "user") {
        return string_match(condition.op, context.user, condition.value);
    }
    if (field == "drive_type") {
        return string_match(condition.op, context.drive_type, condition.value);
    }
    if (field == "process.name") {
        return string_match(condition.op, context.process_name, condition.value);
    }
    if (field == "destination") {
        return string_match(condition.op, context.destination, condition.value);
    }
    if (field == "contains_pii") {
        return bool_value_match(condition.value, context.contains_pii);
    }
    if (field == "keyword_hit") {
        return bool_value_match(condition.value, context.keyword_hit);
    }
    if (field == "size_exceeded") {
        return bool_value_match(condition.value, context.size_exceeded);
    }
    if (field == "removable_drive") {
        return bool_value_match(condition.value, context.removable_drive);
    }
    if (field == "fingerprint_matched") {
        return bool_value_match(condition.value, context.fingerprint_matched);
    }
    return false;
}

bool RuleEngine::load_from_file(const std::string &path) {
    std::ifstream ifs(path);
    if (!ifs) {
        rules_.clear();
        return false;
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return load_from_string(oss.str());
}

bool RuleEngine::load_from_string(const std::string &body) {
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

void RuleEngine::load_from_rules(const std::vector<Rule> &rules) {
    rules_ = rules;
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

RuleDecision RuleEngine::evaluate(const RuleContext &context,
                                  const std::vector<RuleMatch> &matches) const {
    RuleDecision best;
    bool has_best = false;
    for (const auto &rule : rules_) {
        if (!rule.enabled) continue;
        bool matched = false;
        if (rule.type == "regex" || rule.type == "keyword" || rule.type == "hash") {
            for (const auto &hit : matches) {
                if ((!rule.id.empty() && hit.rule_id == rule.id) ||
                    (!rule.name.empty() && hit.rule_name == rule.name)) {
                    matched = true;
                    break;
                }
            }
        } else if (!rule.conditions.empty()) {
            matched = true;
        }

        if (!matched) {
            continue;
        }

        for (const auto &cond : rule.conditions) {
            if (!match_condition(cond, context)) {
                matched = false;
                break;
            }
        }
        if (!matched) {
            continue;
        }

        RuleDecision decision;
        decision.rule_id = rule.id;
        decision.rule_name = rule.name;
        decision.priority = rule.priority;
        decision.severity = rule.severity;
        if (decision.severity == 0) {
            for (const auto &hit : matches) {
                if ((!rule.id.empty() && hit.rule_id == rule.id) ||
                    (!rule.name.empty() && hit.rule_name == rule.name)) {
                    decision.severity = std::max(decision.severity, hit.severity);
                }
            }
        }
        if (!rule.actions.empty()) {
            decision.action = rule.actions.front();
        } else {
            decision.action = default_action_for_severity(decision.severity);
        }
        if (!rule.name.empty()) {
            decision.reason = rule.name;
        } else if (!rule.id.empty()) {
            decision.reason = rule.id;
        } else {
            decision.reason = "rule_match";
        }

        if (!has_best) {
            best = decision;
            has_best = true;
            continue;
        }
        if (decision.priority > best.priority) {
            best = decision;
            continue;
        }
        if (decision.priority == best.priority && decision.severity > best.severity) {
            best = decision;
            continue;
        }
        if (decision.priority == best.priority && decision.severity == best.severity &&
            action_rank(decision.action) > action_rank(best.action)) {
            best = decision;
        }
    }
    if (!has_best) {
        best.action = RuleAction::Allow;
        best.reason = "no_match";
    }
    return best;
}

const std::vector<Rule> &RuleEngine::rules() const {
    return rules_;
}
