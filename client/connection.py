"""
LAN Messenger - - -  Client Network Layer
Manages the TCP connection to the server, sends commands, and
dispatches incoming packets to registered callbacks.

Manages 
    - Connecting to the server 
    - Sending messages safely (thread-safe) 
    - Receiving messages in the background 
    - Dispatching messages to registered callbacks
"""
import ssl
import socket
import threading
from pathlib import Path
from typing import Callable, Dict, Optional
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.protocol import (
    DEFAULT_PORT, HEADER_SIZE, decode_header, decode_body, encode,
    MSG_REGISTER, MSG_LOGIN, MSG_LOGOUT, MSG_SEND, MSG_BROADCAST,
    MSG_FETCH, MSG_LIST_USERS,
)
from shared.tls import client_ssl_context


class Connection:
    """
    Thread connection to the LAN Messenger server.

    Register callbacks via --> on(self, msg_type: str, callback: Callable[[dict], None]):
    Callbacks are called from the receiver thread, so they should be
    short or hand off work to the UI thread.

    Parameters
    ----------
    host : str
        Server IP or hostname.
    port : int
        Server port.
    cert_path : Path or None
        Path to the server's PEM certificate for pinned verification.
        Pass None to use the system CA bundle.
    verify : bool
        Set False to skip certificate verification (testing / fully-trusted
        LAN only).  Default is True.
    """

    def __init__(self, host: str, port: int = DEFAULT_PORT, cert_path: Optional[Path] = None, verify: bool = True):
        self.host = host
        self.port = port
        self._cert_path = cert_path
        self._verify = verify

        self._sock: Optional[socket.socket] = None
        self._send_lock = threading.Lock()                   # ensure thread-safe sending TODO: check if plan works
        self._callbacks: Dict[str, list[Callable]] = {}      
        self._disconnect_cb: Optional[Callable] = None       # special callback when connection drops
        self._recv_thread: Optional[threading.Thread] = None # background recive thread
        self.connected = False

    
    # Callback registration ------------------------------------------------------
    def on(self, msg_type: str, callback: Callable[[dict], None]):
        """Register a callback for a specific message type."""
        self._callbacks.setdefault(msg_type, []).append(callback)
        return self  # fluent

    def on_disconnect(self, callback: Callable[[], None]):
        self._disconnect_cb = callback
        return self
    
  
    # Connection Lifecycle ------------------------------------------------------------
    def connect(self, timeout: float = 5.0):
        """Connect to the server and complete the TLS handshake. Raises OSError on failure."""
        ssl_ctx = client_ssl_context(cert_path=self._cert_path, verify=self._verify)
        raw_sock = socket.create_connection((self.host, self.port), timeout=timeout)
        # Wrap with TLS - - server_hostname=None because we use cert pinning,
        # not hostname verification (self-signed cert on a LAN).
        self._sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=self.host)
        self._sock.settimeout(None)  # blocking after connect to wait for revc
        self.connected = True
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

    def disconnect(self):
        self.connected = False
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

   
    # Sending helpers ----------------------------------------------------------
    def _send(self, payload: dict):
        with self._send_lock:
            if not self._sock:
                raise OSError("Not connected")
            self._sock.sendall(encode(payload))     # continues to transmit data to server until entire buffer sent or error occures

    def register(self, username: str):
        self._send({"type": MSG_REGISTER, "username": username})

    def login(self, username: str):
        self._send({"type": MSG_LOGIN, "username": username})

    def logout(self):
        self._send({"type": MSG_LOGOUT})

    def send_message(self, to: str, body: str):
        self._send({"type": MSG_SEND, "to": to, "body": body})

    def broadcast(self, body: str):
        self._send({"type": MSG_BROADCAST, "body": body})

    def fetch(self):
        self._send({"type": MSG_FETCH})

    def list_users(self):
        self._send({"type": MSG_LIST_USERS})


    # Receiver loop (background thread) --------------------------------------------------------
    def _recv_loop(self):
        try:
            while self.connected:
                raw_header = self._recvall(HEADER_SIZE)
                if raw_header is None:
                    break
                length = decode_header(raw_header)
                raw_body = self._recvall(length)
                if raw_body is None:
                    break
                pkt = decode_body(raw_body)
                self._dispatch(pkt)
        except OSError:
            pass
        finally:
            self.connected = False
            if self._disconnect_cb:
                self._disconnect_cb()

    def _recvall(self, n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            sock = self._sock
            if sock is None:
                return None
            try:
                chunk = sock.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _dispatch(self, pkt: dict):
        msg_type = pkt.get("type")
        for cb in self._callbacks.get(msg_type, []):
            try:
                cb(pkt)
            except Exception as exc:
                print(f"[client] callback error for {msg_type}: {exc}")

