#include "sqlite_store.h"
#include "event_bus.h"
#include "fingerprint.h"
#include <sqlite3.h>
#include <mutex>

static sqlite3 *g_db = nullptr;
static std::mutex g_db_mtx;

static bool column_exists(sqlite3 *db, const std::string &table, const std::string &column) {
    sqlite3_stmt *st = nullptr;
    std::string query = "PRAGMA table_info(" + table + ");";
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &st, nullptr) != SQLITE_OK) {
        return false;
    }
    bool found = false;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(st, 1);
        if (text && column == reinterpret_cast<const char *>(text)) {
            found = true;
            break;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static void ensure_column(sqlite3 *db, const std::string &table, const std::string &column, const std::string &type) {
    if (column_exists(db, table, column)) return;
    std::string sql = "ALTER TABLE " + table + " ADD COLUMN " + column + " " + type + ";";
    char *err = nullptr;
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
    if (err) {
        sqlite3_free(err);
    }
}

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
        "user_sid TEXT,"
        "drive_type TEXT,"
        "process_name TEXT,"
        "pid INTEGER,"
        "ppid INTEGER,"
        "command_line TEXT,"
        "size_bytes INTEGER,"
        "sha256 TEXT,"
        "rule_id TEXT,"
        "rule_name TEXT,"
        "severity INTEGER,"
        "content_flags TEXT,"
        "device_context TEXT,"
        "decision TEXT,"
        "reason TEXT);"
        "CREATE TABLE IF NOT EXISTS device_events("
        "id INTEGER PRIMARY KEY,"
        "ts DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "drive TEXT,"
        "serial TEXT,"
        "allowed INTEGER,"
        "decision TEXT,"
        "reason TEXT);"
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
    if (rc == SQLITE_OK) {
        ensure_column(g_db, "events_v2", "user_sid", "TEXT");
        ensure_column(g_db, "events_v2", "process_name", "TEXT");
        ensure_column(g_db, "events_v2", "pid", "INTEGER");
        ensure_column(g_db, "events_v2", "ppid", "INTEGER");
        ensure_column(g_db, "events_v2", "command_line", "TEXT");
        ensure_column(g_db, "events_v2", "rule_id", "TEXT");
        ensure_column(g_db, "events_v2", "rule_name", "TEXT");
        ensure_column(g_db, "events_v2", "severity", "INTEGER");
        ensure_column(g_db, "events_v2", "content_flags", "TEXT");
        ensure_column(g_db, "events_v2", "device_context", "TEXT");
        ensure_column(g_db, "device_events", "decision", "TEXT");
        ensure_column(g_db, "device_events", "reason", "TEXT");
    }
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
        "INSERT INTO events_v2(event_type, action, path, user, user_sid, drive_type, process_name, pid, ppid, command_line, size_bytes, sha256, rule_id, rule_name, severity, content_flags, device_context, decision, reason) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        -1,
        &st,
        nullptr);
    if (!st) return;
    sqlite3_bind_text(st, 1, ev.event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ev.action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ev.path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, ev.user.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, ev.user_sid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, ev.drive_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, ev.process_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 8, static_cast<sqlite3_int64>(ev.pid));
    sqlite3_bind_int64(st, 9, static_cast<sqlite3_int64>(ev.ppid));
    sqlite3_bind_text(st, 10, ev.command_line.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 11, static_cast<sqlite3_int64>(ev.size_bytes));
    sqlite3_bind_text(st, 12, ev.sha256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 13, ev.rule_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 14, ev.rule_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 15, static_cast<sqlite3_int64>(ev.severity));
    sqlite3_bind_text(st, 16, ev.content_flags.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 17, ev.device_context.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 18, ev.decision.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 19, ev.reason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

void sqlite_insert_device_event(const DeviceEvent &ev) {
    std::lock_guard<std::mutex> lk(g_db_mtx);
    if (!g_db) return;
    sqlite3_stmt *st = nullptr;
    sqlite3_prepare_v2(
        g_db,
        "INSERT INTO device_events(drive, serial, allowed, decision, reason) VALUES(?, ?, ?, ?, ?);",
        -1,
        &st,
        nullptr);
    if (!st) return;
    sqlite3_bind_text(st, 1, ev.drive_letter.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ev.serial.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, ev.allowed ? 1 : 0);
    sqlite3_bind_text(st, 4, ev.decision.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, ev.reason.c_str(), -1, SQLITE_TRANSIENT);
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
