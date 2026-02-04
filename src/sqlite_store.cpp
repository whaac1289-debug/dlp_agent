#include "sqlite_store.h"
#include <sqlite3.h>
#include <mutex>

static sqlite3 *g_db = nullptr;
static std::mutex g_db_mtx;

bool sqlite_init(const char *path) {
    std::lock_guard<std::mutex> lk(g_db_mtx);
    if (sqlite3_open(path, &g_db) != SQLITE_OK) return false;
    const char *schema =
        "CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, data TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY, ts TEXT, level TEXT, msg TEXT);";
    char *err = nullptr;
    sqlite3_exec(g_db, schema, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); }
    return true;
}

void sqlite_insert_event(const std::string &ev) {
    std::lock_guard<std::mutex> lk(g_db_mtx);
    if (!g_db) return;
    sqlite3_stmt *st = nullptr;
    sqlite3_prepare_v2(g_db, "INSERT INTO events(data) VALUES(?);", -1, &st, nullptr);
    if (!st) return;
    sqlite3_bind_text(st, 1, ev.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

void sqlite_insert_log(const char *ts, const char *level, const char *msg) {
    std::lock_guard<std::mutex> lk(g_db_mtx);
    if (!g_db) return;
    sqlite3_stmt *st = nullptr;
    sqlite3_prepare_v2(g_db, "INSERT INTO logs(ts, level, msg) VALUES(?, ?, ?);", -1, &st, nullptr);
    if (!st) return;
    sqlite3_bind_text(st, 1, ts, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, level, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, msg, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}
