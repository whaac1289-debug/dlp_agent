#!/usr/bin/env python3
"""Simple SQLite inspection tool for dlp_agent.db

Usage examples:
  python load.py                # list tables and show recent rows
  python load.py --table events --limit 50
  python load.py --db other.db --csv out.csv --table logs
"""
import sqlite3
import argparse
import csv
import sys


def list_tables(conn):
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    return [r[0] for r in cur.fetchall()]


def count_rows(conn, table):
    try:
        cur = conn.execute(f"SELECT COUNT(*) FROM \"{table}\"")
        return cur.fetchone()[0]
    except Exception:
        return None


def tail_rows(conn, table, limit):
    cur = conn.execute(f"SELECT * FROM \"{table}\" ORDER BY rowid DESC LIMIT ?", (limit,))
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    return cols, rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="dlp_agent.db", help="path to sqlite database")
    p.add_argument("--list-tables", action="store_true", help="only list tables")
    p.add_argument("--table", help="table to show")
    p.add_argument("--limit", type=int, default=20, help="number of recent rows to show")
    p.add_argument("--csv", help="export selected table to CSV file")
    args = p.parse_args()

    try:
        conn = sqlite3.connect(args.db)
    except Exception as e:
        print(f"Failed to open database {args.db}: {e}")
        sys.exit(1)

    tables = list_tables(conn)
    if args.list_tables:
        for t in tables:
            cnt = count_rows(conn, t)
            print(f"{t}\t{cnt if cnt is not None else 'N/A'}")
        return

    if not args.table:
        print("Tables:")
        for t in tables:
            cnt = count_rows(conn, t)
            print(f" - {t}: {cnt if cnt is not None else 'N/A'} rows")
        print()
        # show quick previews for common tables
        for preview in ("events", "logs", "file_events", "device_events"):
            if preview in tables:
                print(f"Preview {preview} (last {args.limit} rows):")
                cols, rows = tail_rows(conn, preview, args.limit)
                print('\t'.join(cols))
                for r in rows:
                    print('\t'.join([str(x) if x is not None else '' for x in r]))
                print()
        return

    if args.table not in tables:
        print(f"Table '{args.table}' not found in {args.db}")
        sys.exit(1)

    cols, rows = tail_rows(conn, args.table, args.limit)
    if args.csv:
        with open(args.csv, "w", newline='', encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for r in reversed(rows):
                w.writerow(["" if x is None else x for x in r])
        print(f"Exported {len(rows)} rows to {args.csv}")
    else:
        print('\t'.join(cols))
        for r in rows:
            print('\t'.join([str(x) if x is not None else '' for x in r]))


if __name__ == '__main__':
    main()
