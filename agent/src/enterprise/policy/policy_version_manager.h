#pragma once

#include <functional>
#include <optional>
#include <string>

namespace dlp::policy {

struct PolicySnapshot {
    std::string version;
    std::string json;
};

class PolicyVersionManager {
public:
    using ApplyCallback = std::function<bool(const PolicySnapshot&)>;

    explicit PolicyVersionManager(std::string store_path);

    bool LoadLastKnown(PolicySnapshot* snapshot);
    bool ApplyAndPersist(const PolicySnapshot& snapshot, const ApplyCallback& apply);
    bool Rollback(const ApplyCallback& apply);

private:
    std::string store_path_;
    std::optional<PolicySnapshot> last_good_;
    bool Persist(const PolicySnapshot& snapshot);
};

}  // namespace dlp::policy
