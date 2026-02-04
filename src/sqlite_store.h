#pragma once
#include <string>

struct FileEvent;
struct FileFingerprint;

bool sqlite_init(const char *path);
void sqlite_shutdown();
void sqlite_insert_event(const std::string &ev);
void sqlite_insert_log(const char *ts, const char *level, const char *msg);
void sqlite_insert_file_event(const struct FileEvent &ev);
void sqlite_insert_device_event(const std::string &drive, const std::string &serial, bool allowed);
void sqlite_insert_fingerprint(const FileFingerprint &fp);
bool sqlite_find_fingerprint(const std::string &full_hash,
                             const std::string &partial_hash,
                             size_t size_bytes,
                             std::string &path_out);
