"""
LAN Messenger Protocol Definitions
All message types and packet structures shared between server and client.
"""

import json
import struct

# --- Packet framing ---
# Each packet: [4-byte little-endian length][JSON payload]
HEADER_FMT = "<I"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# Max packet size
MAX_PACKET = 65536  # 64KB 

# Server default port
DEFAULT_PORT = 54321

# --- Message Types (client --> server) ---
MSG_REGISTER    = "REGISTER"    # {"type": "REGISTER",   "username": str}
MSG_LOGIN       = "LOGIN"       # {"type": "LOGIN",      "username": str}
MSG_LOGOUT      = "LOGOUT"      # {"type": "LOGOUT"}
MSG_SEND        = "SEND"        # {"type": "SEND",       "to": str, "body": str}
MSG_BROADCAST   = "BROADCAST"   # {"type": "BROADCAST",  "body": str}
MSG_FETCH       = "FETCH"       # {"type": "FETCH"}       – request pending messages from database
MSG_LIST_USERS  = "LIST_USERS"  # {"type": "LIST_USERS"}
MSG_PASSWD      = "PASSWD"      # {"type": "PASSWD", "old": str, "new" : str}

# --- Message Types (server --> client) ---
MSG_OK          = "OK"          # {"type": "OK",         "info": str} #TODO: update based on changes to _on_ok, mabye create more message types

MSG_ERROR       = "ERROR"       # {"type": "ERROR",      "info": str}
MSG_DELIVER     = "DELIVER"     # {"type": "DELIVER",    "id": int, "from": str, "body": str, "sent_at": str, "broadcast": bool}
MSG_USER_LIST   = "USER_LIST"   # {"type": "USER_LIST",  "users": [{"username": str, "online": bool}]}
MSG_NOTIFY      = "NOTIFY"      # {"type": "NOTIFY",     "event": str, "username": str}  – user joined/left


def encode(payload: dict) -> bytes:
    """Encode a dict as a length-prefixed JSON packet."""
    body = json.dumps(payload).encode("utf-8")
    header = struct.pack(HEADER_FMT, len(body)) # struct.pack(...) converts that number into binary format and len(body) = number of bytes in the message.
    return header + body


def decode_header(raw: bytes) -> int:
    """Parse the 4-byte length header."""
    (length,) = struct.unpack(HEADER_FMT, raw)
    return length


def decode_body(raw: bytes) -> dict:
    """Parse JSON body into a dict."""
    return json.loads(raw.decode("utf-8"))