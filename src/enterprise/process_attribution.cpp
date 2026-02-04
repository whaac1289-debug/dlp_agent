#include "process_attribution.h"

namespace dlp::process {

ProcessAttribution GetProcessAttribution(uint32_t pid) {
    ProcessAttribution result;
    result.pid = pid;
    return result;
}

}  // namespace dlp::process
