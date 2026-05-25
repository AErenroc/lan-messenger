"""
LAN Messenger – - - Server setup
Listens for TCP connections, authenticates users, stores and forwards messages.

Usage:
    python server.py [--host 0.0.0.0] [--port 54321]
"""

import argparse
import logging
import socket
import struct
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
import sys

import ssl

# Allow running from project root or server/ directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))



from shared.protocol import (
    DEFAULT_PORT, MAX_PACKET, HEADER_SIZE, decode_header, decode_body, encode,
    MSG_REGISTER, MSG_LOGIN, MSG_LOGOUT, MSG_SEND, MSG_BROADCAST,
    MSG_FETCH, MSG_LIST_USERS,
    MSG_OK, MSG_ERROR, MSG_DELIVER, MSG_USER_LIST, MSG_NOTIFY,
)
from shared.tls import server_ssl_context, cert_fingerprint, CERT_PATH
from server.database import Database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("lanmsg.server")



# Client session ------------------------------------------------------------------------------------------------------------
class ClientSession(threading.Thread):
    """One thread per connected client."""

    def __init__(self, sock: socket.socket, addr, server: "Server"):
        super().__init__(daemon=True)
        self.sock = sock
        self.addr = addr
        self.server = server
        self.db: Database = server.db
        self.username: Optional[str] = None
        self._lock = threading.Lock()
        self._alive = True  # cleared when recv loop ends



    # Thread entry point ------------------------------------------------------------------------
    def run(self):
        log.info("Connection from %s:%d", *self.addr)
        try:
            while True:
                packet = self._recv_packet()
                if packet is None:
                    break
                self._handle(packet)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            self._disconnect()

  
    # Network helpers ------------------------------------------------------------------------
    def _recv_packet(self) -> Optional[dict]:
        """Block until a full length-prefixed packet arrives, or return None on EOF."""
        try:
            raw_header = self._recvall(HEADER_SIZE)
            if raw_header is None:
                return None
            length = decode_header(raw_header)
            raw_body = self._recvall(length)
            if raw_body is None:
                return None
            return decode_body(raw_body)
        except (struct.error, UnicodeDecodeError, ValueError):
            return None

    def _recvall(self, n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def send(self, payload: dict) -> bool:
        """Send a packet to this client. Thread-safe. Returns False if disconnected."""
        with self._lock:
            if self.sock is None:
                return False
            try:
                self.sock.sendall(encode(payload))
                return True
            except OSError:
                return False

    def is_connected(self) -> bool:
        """True if the recv thread is still running (session is alive)."""
        return self._alive and self.sock is not None

    def _ok(self, info: str = ""):
        self.send({"type": MSG_OK, "info": info})

    def _error(self, info: str):
        self.send({"type": MSG_ERROR, "info": info})


    # Dispatch -----------------------------------------------------------------
    def _handle(self, pkt: dict):
        t = pkt.get("type")
        if t == MSG_REGISTER:
            self._handle_register(pkt)
        elif t == MSG_LOGIN:
            self._handle_login(pkt)
        elif t == MSG_LOGOUT:
            self._handle_logout()
        elif t == MSG_SEND:
            self._handle_send(pkt)
        elif t == MSG_BROADCAST:
            self._handle_broadcast(pkt)
        elif t == MSG_FETCH:
            self._handle_fetch()
        elif t == MSG_LIST_USERS:
            self._handle_list_users()
        else:
            self._error(f"Unknown message type: {t!r}")

  

    # Handlers ---------------------------------------------------------------
    def _handle_register(self, pkt: dict):
        username = (pkt.get("username") or "").strip()
        if not username or len(username) > 32:
            return self._error("Username must be 1-32 characters.")
        if not username.replace("_", "").replace("-", "").isalnum():
            return self._error("Username may only contain letters, digits, - and _.")
        if self.db.register_user(username):
            log.info("Registered new user: %s", username)
            self._ok(f"User '{username}' registered successfully.")
        else:
            self._error(f"Username '{username}' is already taken.")

    def _handle_login(self, pkt: dict):
        username = (pkt.get("username") or "").strip()
        if not username:
            return self._error("Username required.")
        if not self.db.user_exists(username):
            return self._error(f"Unknown user '{username}'. Register first.")
        if self.server.is_online(username):
            return self._error(f"'{username}' is already logged in from another client.")
        self.username = username
        self.server.add_session(username, self)
        log.info("%s logged in from %s:%d", username, *self.addr)
        self._ok(f"Welcome, {username}!")
        self.server.broadcast_notify("joined", username, exclude=username)
        # Deliver any stored messages immediately
        self._deliver_pending()

    def _handle_logout(self):
        if self.username:
            self.server.remove_session(self.username)
            log.info("%s logged out", self.username)
            self.server.broadcast_notify("left", self.username, exclude=self.username)
            self.username = None
        self._ok("Logged out.")

    def _handle_send(self, pkt: dict):
        if not self.username:
            return self._error("Not logged in.")
        to = (pkt.get("to") or "").strip()
        body = (pkt.get("body") or "").strip()
        if not to:
            return self._error("'to' field required.")
        if not body:
            return self._error("Message body cannot be empty.")
        if not self.db.user_exists(to):
            return self._error(f"Unknown user '{to}'.")
        if to.lower() == self.username.lower():
            return self._error("Cannot send a message to yourself.")

        msg_id = self.db.store_message(self.username, to, body)
        log.info("MSG %d: %s → %s", msg_id, self.username, to)

        # Attempt live delivery
        target = self.server.get_session(to)
        if target and target.is_connected():
            delivered = target.send({
                "type": MSG_DELIVER,
                "id": msg_id,
                "from": self.username,
                "body": body,
                "sent_at": datetime.utcnow().isoformat(timespec="seconds"),
                "broadcast": False,
            })
            if delivered:
                self.db.mark_delivered([msg_id])
                self._ok(f"Message delivered to {to} (online).")
                return
            else:
                # Stale session — clean it up
                self.server.remove_session(to)
        self._ok(f"Message stored. Will be delivered when {to} comes online.")

    def _handle_broadcast(self, pkt: dict):
        if not self.username:
            return self._error("Not logged in.")
        body = (pkt.get("body") or "").strip()
        if not body:
            return self._error("Message body cannot be empty.")

        msg_id = self.db.store_message(self.username, None, body)
        log.info("BROADCAST %d from %s", msg_id, self.username)

        delivered_ids = []
        for uname, session in self.server.online_sessions():
            if uname.lower() == self.username.lower():
                continue
            ok = session.send({
                "type": MSG_DELIVER,
                "id": msg_id,
                "from": self.username,
                "body": body,
                "sent_at": datetime.utcnow().isoformat(timespec="seconds"),
                "broadcast": True,
            })
            if ok:
                delivered_ids.append(msg_id)

        if delivered_ids:
            self.db.mark_delivered(list(set(delivered_ids)))

        self._ok("Broadcast sent.")

    def _handle_fetch(self):
        if not self.username:
            return self._error("Not logged in.")
        self._deliver_pending()

    def _handle_list_users(self):
        all_users = self.db.list_users()
        online_set = {u.lower() for u in self.server.online_usernames()}
        users = [
            {"username": u, "online": u.lower() in online_set}
            for u in all_users
        ]
        self.send({"type": MSG_USER_LIST, "users": users})

    # Internal helpers ------------------------------------------------------------
    def _deliver_pending(self):
        if not self.username:
            return
        rows = self.db.fetch_pending(self.username)
        if not rows:
            self._ok("No pending messages.")
            return
        ids = []
        for row in rows:
            self.send({
                "type": MSG_DELIVER,
                "id": row["id"],
                "from": row["from_user"],
                "body": row["body"],
                "sent_at": row["sent_at"],
                "broadcast": row["to_user"] is None,
            })
            ids.append(row["id"])
        self.db.mark_delivered(ids)
        self._ok(f"Fetched {len(ids)} message(s).")

    def _disconnect(self):
        self._alive = False  # mark dead before anything else
        if self.username:
            self.server.remove_session(self.username)
            self.server.broadcast_notify("left", self.username, exclude=self.username)
            log.info("%s disconnected", self.username)
        else:
            log.info("Anonymous client %s:%d disconnected", *self.addr)
        try:
            self.sock.close()
        except OSError:
            pass
        self.sock = None  # signal to send() that we're gone



# Server ---------------------------------------------------------------------------------------------------------------------
class Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.db = Database()
        self._sessions: Dict[str, ClientSession] = {}  # username (lower) → session
        self._sessions_lock = threading.Lock()


    # Session registry --------------------------------------------------------
    def add_session(self, username: str, session: ClientSession):
        with self._sessions_lock:
            self._sessions[username.lower()] = session

    def remove_session(self, username: str):
        with self._sessions_lock:
            self._sessions.pop(username.lower(), None)

    def get_session(self, username: str) -> Optional[ClientSession]:
        with self._sessions_lock:
            return self._sessions.get(username.lower())

    def is_online(self, username: str) -> bool:
        with self._sessions_lock:
            return username.lower() in self._sessions

    def online_sessions(self):
        with self._sessions_lock:
            return list(self._sessions.items())

    def online_usernames(self):
        with self._sessions_lock:
            return list(self._sessions.keys())

    def broadcast_notify(self, event: str, username: str, exclude: Optional[str] = None):
        pkt = {"type": MSG_NOTIFY, "event": event, "username": username}
        for uname, session in self.online_sessions():
            if exclude and uname.lower() == exclude.lower():
                continue
            session.send(pkt)


    # Main loop ----------------------------------------------------------------
    def run(self):
        stats = self.db.stats()
        log.info("Database: %d users, %d messages (%d pending)",
                 stats["total_users"], stats["total_messages"], stats["pending_messages"])
        
        # Set up TLS
        print("\n\t Set up TLS CALLING --> ssl_ctx = server_ssl_context(self.host)\n")
        ssl_ctx = server_ssl_context(self.host)
        log.info("TLS enabled  (%s)", ssl_ctx.protocol.name if hasattr(ssl_ctx.protocol, 'name') else 'TLS')
        log.info("Cert fingerprint (SHA-256): %s", cert_fingerprint(CERT_PATH))
        log.info("Share server/server.crt with clients for certificate pinning.")



        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((self.host, self.port))
        raw_sock.listen(64)
        log.info("LAN Messenger server listening on %s:%d (TLS)", self.host, self.port)

        try:
            while True:
                client_raw, addr = raw_sock.accept()
                # Perform TLS handshake before spawning the session thread
                try:
                    client_tls = ssl_ctx.wrap_socket(client_raw, server_side=True)
                except ssl.SSLError as exc:
                    log.warning("TLS handshake failed from %s:%d — %s", *addr, exc)
                    client_raw.close()
                    continue
                session = ClientSession(client_tls, addr, self)
                session.start()
        except KeyboardInterrupt:
            log.info("Server shutting down.")
        finally:
            raw_sock.close()

# Entry point --------------------------------------------------------------------------------------------------------------------------------------
def main():
    
    parser = argparse.ArgumentParser(description="LAN Messenger Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    args = parser.parse_args()
    Server(args.host, args.port).run()


if __name__ == "__main__":
    main()