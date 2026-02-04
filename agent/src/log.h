#pragma once
#include <string>

bool log_init(const char *path);
void log_shutdown();
void log_info(const char *fmt, ...);
void log_error(const char *fmt, ...);
