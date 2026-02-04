#include <cassert>

#include "../src/enterprise/policy/policy_fetcher.h"
#include "../src/enterprise/policy/policy_version_manager.h"

#if defined(DLP_ENABLE_TESTS)

using dlp::policy::PolicySnapshot;
using dlp::policy::PolicyVersionManager;

int main() {
    PolicyVersionManager manager{"policy_store.txt"};
    PolicySnapshot snapshot{"v1", "{}"};
    bool applied = manager.ApplyAndPersist(snapshot, [](const PolicySnapshot&) { return true; });
    assert(applied);
    return 0;
}

#endif
