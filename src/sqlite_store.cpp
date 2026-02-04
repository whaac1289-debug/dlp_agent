#include "sqlite_store.h"
#include "event_bus.h"
#include "fingerprint.h"
#include <sqlite3.h>
#include <mutex>

static sqlite3 *g_db = nullptr;
static std::mutex g_db_mtx;

bool sqlite_init(const char *path) {
    std::lock_guard<std::mutex> lk(g_db_mtx);
    if (sqlite3_open(path, &g_db) != SQLITE_OK) return false;
    const char *schema =
        "CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, data TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY, ts TEXT, level TEXT, msg TEXT);"
        "CREATE TABLE IF NOT EXISTS events_v2("
        "id INTEGER PRIMARY KEY,"
        "ts DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "event_type TEXT,"
        "action TEXT,"
        "path TEXT,"
        "user TEXT,"
        "drive_type TEXT,"
        "size_bytes INTEGER,"
        "sha256 TEXT,"
        "decision TEXT,"
        "reason TEXT);"
        "CREATE TABLE IF NOT EXISTS device_events("
        "id INTEGER PRIMARY KEY,"
        "ts DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "drive TEXT,"
        "serial TEXT,"
        "allowed INTEGER);"
        "CREATE TABLE IF NOT EXISTS file_fingerprints("
        "id INTEGER PRIMARY KEY,"
        "ts DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "path TEXT,"
        "size_bytes INTEGER,"
        "full_hash TEXT,"
        "partial_hash TEXT);"
        "CREATE INDEX IF NOT EXISTS idx_fingerprints_full_hash ON file_fingerprints(full_hash);"
        "CREATE INDEX IF NOT EXISTS idx_fingerprints_partial_hash ON file_fingerprints(partial_hash);";
    char *err = nullptr;
    int rc = sqlite3_exec(g_db, schema, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); }
    return rc == SQLITE_OK;
}

void sqlite_shutdown() {
    std::lock_guard<std::mutex> lk(g_db_mtx);
    if (!g_db) return;
    sqlite3_close(g_db);
    g_db = nullptr;
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

void sqlite_insert_file_event(const FileEvent &ev) {
    std::lock_guard<std::mutex> lk(g_db_mtx);
    if (!g_db) return;
    sqlite3_stmt *st = nullptr;
    sqlite3_prepare_v2(
        g_db,
        "INSERT INTO events_v2(event_type, action, path, user, drive_type, size_bytes, sha256, decision, reason) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);",
        -1,
        &st,
        nullptr);
    if (!st) return;
    sqlite3_bind_text(st, 1, ev.event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ev.action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ev.path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, ev.user.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, ev.drive_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, static_cast<sqlite3_int64>(ev.size_bytes));
    sqlite3_bind_text(st, 7, ev.sha256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, ev.decision.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, ev.reason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

void sqlite_insert_device_event(const std::string &drive, const std::string &serial, bool allowed) {
    std::lock_guard<std::mutex> lk(g_db_mtx);
    if (!g_db) return;
    sqlite3_stmt *st = nullptr;
    sqlite3_prepare_v2(
        g_db,
        "INSERT INTO device_events(drive, serial, allowed) VALUES(?, ?, ?);",
        -1,
        &st,
        nullptr);
    if (!st) return;
    sqlite3_bind_text(st, 1, drive.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, serial.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, allowed ? 1 : 0);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

void sqlite_insert_fingerprint(const FileFingerprint &fp) {
    std::lock_guard<std::mutex> lk(g_db_mtx);
    if (!g_db) return;
    sqlite3_stmt *st = nullptr;
    sqlite3_prepare_v2(
        g_db,
        "INSERT INTO file_fingerprints(path, size_bytes, full_hash, partial_hash) VALUES(?, ?, ?, ?);",
        -1,
        &st,
        nullptr);
    if (!st) return;
    sqlite3_bind_text(st, 1, fp.path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, static_cast<sqlite3_int64>(fp.size_bytes));
    sqlite3_bind_text(st, 3, fp.full_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, fp.partial_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

bool sqlite_find_fingerprint(const std::string &full_hash,
                             const std::string &partial_hash,
                             size_t size_bytes,
                             std::string &path_out) {
    std::lock_guard<std::mutex> lk(g_db_mtx);
    if (!g_db) return false;
    sqlite3_stmt *st = nullptr;
    sqlite3_prepare_v2(
        g_db,
        "SELECT path FROM file_fingerprints "
        "WHERE (full_hash = ? AND ? != '') OR (partial_hash = ? AND size_bytes = ?) "
        "LIMIT 1;",
        -1,
        &st,
        nullptr);
    if (!st) return false;
    sqlite3_bind_text(st, 1, full_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, full_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, partial_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, static_cast<sqlite3_int64>(size_bytes));
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(st, 0);
        if (text) {
            path_out = reinterpret_cast<const char *>(text);
            found = true;
        }
    }
    sqlite3_finalize(st);
    return found;
}
