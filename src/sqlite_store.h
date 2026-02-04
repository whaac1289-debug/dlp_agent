#pragma once
#include <string>

bool sqlite_init(const char *path);
void sqlite_insert_event(const std::string &ev);
void sqlite_insert_log(const char *ts, const char *level, const char *msg);
