#include "policy_version_manager.h"

#include <fstream>

namespace dlp::policy {

PolicyVersionManager::PolicyVersionManager(std::string store_path)
    : store_path_(std::move(store_path)) {}

bool PolicyVersionManager::LoadLastKnown(PolicySnapshot* snapshot) {
    if (!snapshot) {
        return false;
    }
    std::ifstream input(store_path_);
    if (!input.is_open()) {
        return false;
    }
    std::getline(input, snapshot->version);
    snapshot->json.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    last_good_ = *snapshot;
    return true;
}

bool PolicyVersionManager::Persist(const PolicySnapshot& snapshot) {
    std::ofstream output(store_path_, std::ios::trunc);
    if (!output.is_open()) {
        return false;
    }
    output << snapshot.version << "\n" << snapshot.json;
    return true;
}

bool PolicyVersionManager::ApplyAndPersist(const PolicySnapshot& snapshot, const ApplyCallback& apply) {
    if (!apply(snapshot)) {
        return false;
    }
    if (!Persist(snapshot)) {
        return false;
    }
    last_good_ = snapshot;
    return true;
}

bool PolicyVersionManager::Rollback(const ApplyCallback& apply) {
    if (!last_good_) {
        return false;
    }
    return apply(*last_good_);
}

}  // namespace dlp::policy
