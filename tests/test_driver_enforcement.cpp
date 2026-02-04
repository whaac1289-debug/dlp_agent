#include <cassert>

#include "../src/policy.h"

#if defined(DLP_ENABLE_TESTS)

int main() {
    PolicyDecision decision;
    decision.action = RuleAction::Block;
    assert(should_block_driver(decision));
    decision.action = RuleAction::Alert;
    assert(!should_block_driver(decision));
    return 0;
}

#endif
