#include "event_bus.h"
#include "sqlite_store.h"
#include "log.h"

void emit_event(const std::string &ev) {
    log_info("event: %s", ev.c_str());
    sqlite_insert_event(ev);
}
