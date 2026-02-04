#include <cassert>

#include "../src/enterprise/rules/rule_engine_v2.h"

#if defined(DLP_ENABLE_TESTS)

using dlp::rules::Action;
using dlp::rules::Rule;
using dlp::rules::RuleCondition;
using dlp::rules::RuleContext;
using dlp::rules::RuleEngineV2;

int main() {
    RuleEngineV2 engine;
    Rule high{"high", 10, "high", {{"file.extension", "==", ".docx"}}, {Action::Block}, {}};
    Rule low{"low", 1, "low", {{"contains_pii", "==", "true"}}, {Action::Alert}, {}};
    engine.LoadRules({low, high});

    RuleContext context{".docx", true, "word.exe", "removable", {}};
    auto decision = engine.Evaluate(context);
    assert(decision.rule_id == "high");
    return 0;
}

#endif
