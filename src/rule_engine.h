#pragma once
#include <string>
#include <vector>

struct Rule {
    std::string id;
    std::string name;
    std::string type;
    int priority = 0;
    int severity = 0;
    std::string pattern;
    std::vector<std::string> keywords;
    std::vector<std::string> hashes;
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

class RuleEngine {
public:
    bool load_from_file(const std::string &path);
    std::vector<RuleMatch> scan_text(const std::string &text) const;
    std::vector<RuleMatch> scan_hashes(const std::string &full_hash,
                                       const std::string &partial_hash) const;
    const std::vector<Rule> &rules() const;

private:
    std::vector<Rule> rules_;
};

extern RuleEngine g_rule_engine;
