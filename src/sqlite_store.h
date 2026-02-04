#pragma once
#include <string>

struct FileEvent;

bool sqlite_init(const char *path);
void sqlite_insert_event(const std::string &ev);
void sqlite_insert_log(const char *ts, const char *level, const char *msg);
void sqlite_insert_file_event(const struct FileEvent &ev);
void sqlite_insert_device_event(const std::string &drive, const std::string &serial, bool allowed);
