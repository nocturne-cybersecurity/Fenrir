"""Persistencia en SQLite: guarda el estado de cada run."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from fenrir.core.state import StateGraph


class Storage:
    def __init__(self, db_path: str | Path = "fenrir.db") -> None:
        self.db_path = str(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    finished_at REAL,
                    state_json TEXT
                )
                """
            )
            con.commit()

    def start_run(self, target: str) -> int:
        with sqlite3.connect(self.db_path) as con:
            cur = con.execute(
                "INSERT INTO runs (target, started_at) VALUES (?, ?)",
                (target, time.time()),
            )
            con.commit()
            return cur.lastrowid

    def finish_run(self, run_id: int, state: StateGraph) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "UPDATE runs SET finished_at = ?, state_json = ? WHERE id = ?",
                (time.time(), json.dumps(state.to_dict()), run_id),
            )
            con.commit()

    def list_runs(self) -> list[tuple[int, str, float]]:
        with sqlite3.connect(self.db_path) as con:
            cur = con.execute(
                "SELECT id, target, started_at FROM runs ORDER BY id DESC"
            )
            return cur.fetchall()