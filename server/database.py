"""
LAN Messenger - - - Database Layer (SQLite)
Handles storage of users and messages (store-and-forward).
"""


"""
sqlite3 ref sheet

    sqlite3.connect(database, timeout=5.0, detect_types=0, isolation_level='DEFERRED', 
            check_same_thread=True, factory=sqlite3.Connection, cached_statements=128, uri=False, *, 
            autocommit=sqlite3.LEGACY_TRANSACTION_CONTROL)

    execute(sql, [parameters]):     Executes a single SQL statement. 
    executescript(sql_script):      Executes multiple semicolon-separated SQL statements at once.

    conn.commit()

"""
import sqlite3
import threading

from pathlib import Path
from typing import List, Optional

from shared.authentication import hash_password, verify_password

DB_PATH = Path(__file__).parent / "lanmsg.db"


class Database:
    """
    Thread-safe SQLite wrapper for the LAN messenger server.
    """

    def __init__(self, path: Path = DB_PATH):
        self._path = path
        self._local = threading.local()  # Each thread gets its own connection
        self._init_schema()              # Creates table structure

    # Connection management (one connection per thread) -------------------------------------
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(str(self._path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL") # Enables Write-Ahead Logging
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return self._local.conn

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Runs a query and Automatically commits, Returns cursor to carry out tasks and retrieves data"""
        conn = self._conn()
        cur = conn.execute(sql, params)
        conn.commit()
        return cur

  
    # Schema --------------------------------------------------------------------------
    def _init_schema(self) -> None:
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                password_salt   TEXT    NOT NULL,
                password_hash   TEXT    NOT NULL,
                cert_subject    TEXT,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now','utc'))
            );

            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user   TEXT    NOT NULL,
                to_user     TEXT,           -- NULL means broadcast
                body        TEXT    NOT NULL,
                sent_at     TEXT    NOT NULL DEFAULT (datetime('now','utc')),
                delivered   INTEGER NOT NULL DEFAULT 0   -- 0=pending, 1=delivered
            );

            CREATE INDEX IF NOT EXISTS idx_messages_to_delivered
                ON messages (to_user, delivered);
        """)
        conn.commit()

   
    # User operations --------------------------------------------------------------------------
    def user_exists(self, username: str) -> bool: 
        row = self._conn().execute(
            "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone()
        return row is not None

    def register_user(self, username: str, password_salt: str, password_hash: str) -> bool:
        """Return True if created, False if username already exists."""
        if self.user_exists(username):
            return False
        self._execute("INSERT INTO users (username, password_salt, password_hash) VALUES (?, ?, ?)", 
                      (username, password_salt, password_hash)) # Parameterized statment works
        return True
    
    def verify_user(self, username: str, password: str) -> bool:
         """
         Return True if username exists and password is correct. 
         Uses constant-time comparison with hmac.compare_digest :D (inside authentication.py --> verify_password).
         TODO: Add explanation of constant-time comparison to README/features
         """
         row = self._conn().execute("SELECT password_salt, password_hash FROM users WHERE username = ? COLLATE NOCASE",
                                    (username,),).fetchone()
         if row is None:
            # User doesn't exist, run a dummy hash to avoid timing-based --> user enumeration (attacker should'nt be able to tell "wrong user" from "wrong password")
            hash_password("dummy-timing-guard") #TODO: check/test if this is sufficient 
            return False
         
         return verify_password(password, row["password_salt"], row["password_hash"])


    def list_users(self) -> List[str]:
        rows = self._conn().execute("SELECT username FROM users ORDER BY username COLLATE NOCASE").fetchall()
        return [r["username"] for r in rows]
    
    
    def update_password(self, username: str, salt_hex: str, hash_hex: str )-> None:
        self._execute(
            "UPDATE users SET password_salt = ?, password_hash = ? WHERE username = ? COLLATE NOCASE",
            (salt_hex, hash_hex, username)
        )

    def update_cert_subject(self, username: str, cert_subject: str) -> None:
        self._execute(
            "UPDATE users SET cert_subject = ? WHERE username = ? COLLATE NOCASE",
            (cert_subject, username),
    )

    # Message operations --------------------------------------------------------------------------
    def store_message(self, from_user: str, to_user: Optional[str], body: str) -> int:
        """Store a message and return its ID."""
        cur = self._execute(
            "INSERT INTO messages (from_user, to_user, body) VALUES (?, ?, ?)",
            (from_user, to_user, body),
        )
        return cur.lastrowid

    def fetch_pending(self, username: str) -> List[sqlite3.Row]:
        """Return all undelivered direct messages for  username + all broadcasts."""
        rows = self._conn().execute(
            """
            SELECT id, from_user, to_user, body, sent_at
            FROM   messages
            WHERE  delivered = 0
              AND  (to_user = ? COLLATE NOCASE OR to_user IS NULL)
              AND  from_user != ? COLLATE NOCASE
            ORDER  BY sent_at, id
            """,
            (username, username),
        ).fetchall()
        return rows

    def mark_delivered(self, message_ids: List[int]) -> None:
        if not message_ids:
            return
        placeholders = ",".join("?" * len(message_ids))     # ex (?, ?, ?,...)
        self._execute(
            f"UPDATE messages SET delivered = 1 WHERE id IN ({placeholders})",
            tuple(message_ids),
        )

    # Stats (for server info display) -------------------------------------
    def stats(self) -> dict:
        conn = self._conn()
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_msgs  = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        pending     = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE delivered = 0"
        ).fetchone()[0]
        return {
            "total_users": total_users,
            "total_messages": total_msgs,
            "pending_messages": pending,
        }