#pragma once
#include <string>
#include <vector>

enum class RuleAction {
    Allow,
    Alert,
    Block,
    Quarantine,
    ShadowCopy
};

struct RuleCondition {
    std::string field;
    std::string op;
    std::string value;
};

struct Rule {
    std::string id;
    std::string name;
    std::string type;
    int priority = 0;
    int severity = 0;
    std::string pattern;
    std::vector<std::string> keywords;
    std::vector<std::string> hashes;
    std::vector<RuleCondition> conditions;
    std::vector<RuleAction> actions;
    bool enabled = true;
};

struct RuleMatch {
    std::string rule_id;
    std::string rule_name;
    std::string type;
    int priority = 0;
    int severity = 0;
    double confidence = 0.0;
    std::string match;
    size_t match_count = 0;
};

struct RuleContext {
    std::string path;
    std::string extension;
    std::string user;
    std::string drive_type;
    std::string process_name;
    std::string destination;
    bool contains_pii = false;
    bool keyword_hit = false;
    bool size_exceeded = false;
    bool removable_drive = false;
    bool fingerprint_matched = false;
};

struct RuleDecision {
    RuleAction action = RuleAction::Allow;
    std::string rule_id;
    std::string rule_name;
    int severity = 0;
    int priority = 0;
    std::string reason;
};

class RuleEngine {
public:
    bool load_from_file(const std::string &path);
    bool load_from_string(const std::string &body);
    void load_from_rules(const std::vector<Rule> &rules);
    std::vector<RuleMatch> scan_text(const std::string &text) const;
    std::vector<RuleMatch> scan_hashes(const std::string &full_hash,
                                       const std::string &partial_hash) const;
    RuleDecision evaluate(const RuleContext &context,
                          const std::vector<RuleMatch> &matches) const;
    const std::vector<Rule> &rules() const;

private:
    std::vector<Rule> rules_;
};

extern RuleEngine g_rule_engine;
