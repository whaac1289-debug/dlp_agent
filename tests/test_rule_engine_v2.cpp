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
    Rule high;
    high.id = "high";
    high.priority = 10;
    high.severity = 8;
    high.conditions = {{"file.extension", "==", ".docx"}};
    high.actions = {Action::Block};

    Rule low;
    low.id = "low";
    low.priority = 1;
    low.severity = 3;
    low.conditions = {{"contains_pii", "==", "true"}};
    low.actions = {Action::Alert};

    engine.LoadRules({low, high});

    RuleContext context;
    context.extension = ".docx";
    context.contains_pii = true;
    context.process_name = "word.exe";
    context.drive_type = "FIXED";
    auto decision = engine.Evaluate(context, {});
    assert(decision.rule_id == "high");
    return 0;
}

#endif
