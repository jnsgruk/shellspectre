#!/usr/bin/env python3
"""Simple SQLite assertion helper for shspectr system tests.

Usage:
    assert_db.py count <table> [where clause]  -- print row count
    assert_db.py query <sql>                   -- print query result
    assert_db.py check-schema                  -- verify core schema exists
    assert_db.py check-no-orphans              -- verify no orphaned events
    assert_db.py check-exit-code <filename> <expected_code>
"""
import sqlite3
import sys
import os

DB_PATH = os.environ.get("DB_PATH", "/tmp/shspectr-test.db")

def main():
    conn = sqlite3.connect(DB_PATH)
    cmd = sys.argv[1]

    if cmd == "count":
        table = sys.argv[2]
        where = " WHERE " + " ".join(sys.argv[3:]) if len(sys.argv) > 3 else ""
        r = conn.execute(f"SELECT COUNT(*) FROM {table}{where}").fetchone()
        print(r[0])

    elif cmd == "query":
        sql = sys.argv[2]
        r = conn.execute(sql).fetchone()
        print(r[0] if r else "")

    elif cmd == "check-schema":
        for table in ["sessions", "events"]:
            r = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            assert r[0] >= 1, f"expected rows in {table}, got {r[0]}"
        r = conn.execute(
            "SELECT COUNT(*) FROM events "
            "WHERE event_type = 0 AND execution_id = 0"
        ).fetchone()
        assert r[0] == 0, f"found {r[0]} exec events with execution_id=0"
        r = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE ended_at IS NOT NULL"
        ).fetchone()
        assert r[0] >= 1, f"no completed sessions"
        print("schema OK")

    elif cmd == "check-no-orphans":
        r = conn.execute(
            "SELECT COUNT(*) FROM events e "
            "LEFT JOIN sessions s ON e.session_id = s.id "
            "WHERE s.id IS NULL"
        ).fetchone()
        assert r[0] == 0, f"found {r[0]} orphaned events"
        print("no orphans")

    elif cmd == "check-exit-code":
        filename, expected = sys.argv[2], int(sys.argv[3])
        r = conn.execute(
            "SELECT exit_code FROM events "
            "WHERE event_type = 0 AND filename = ? "
            "ORDER BY id DESC LIMIT 1",
            (filename,),
        ).fetchone()
        assert r is not None, f"no exec event for {filename}"
        assert r[0] == expected, \
            f"{filename}: expected exit_code={expected}, got {r[0]}"
        print(f"{filename} exit_code={r[0]} OK")

    conn.close()

if __name__ == "__main__":
    main()
