#include "log.h"
#include "sqlite_store.h"

#include <mutex>
#include <cstdarg>
#include <cstdio>
#include <ctime>

static FILE *g_logf = nullptr;
static std::mutex g_log_mtx;

bool log_init(const char *path) {
    std::lock_guard<std::mutex> lk(g_log_mtx);
    g_logf = fopen(path, "a");
    return g_logf != nullptr;
}

void log_shutdown() {
    std::lock_guard<std::mutex> lk(g_log_mtx);
    if (g_logf) fclose(g_logf);
    g_logf = nullptr;
}

static void vlog_and_store(const char *level, const char *fmt, va_list ap) {
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    time_t t = time(NULL);
    struct tm tmv;
    localtime_s(&tmv, &t);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tmv);
    std::lock_guard<std::mutex> lk(g_log_mtx);
    if (g_logf) fprintf(g_logf, "%s [%s] %s\n", timestr, level, buf);
    fflush(g_logf);
    // also store into sqlite minimal events table
    sqlite_insert_log(timestr, level, buf);
}

void log_info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vlog_and_store("INFO", fmt, ap); va_end(ap);
}

void log_error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vlog_and_store("ERROR", fmt, ap); va_end(ap);
}
