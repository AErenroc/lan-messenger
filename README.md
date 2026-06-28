# lan-messenger

A terminal LAN messaging application written in Python. Supports direct messages, broadcasts and store-and-forward delivery for offline users. Connections are secured with mutual TLS. Both the server and every client must present a certificate signed by the server's CA before any data can be exchanged.

## Table of Contents
- [General Information](#general-information)
  - [Requirements](#requirements)
  - [Project Structure](#project-structure)
  - [Features](#features)
  - [-- Setup --](#setup)
  - [Application Commands](#application-commands)
- [Innerworkings](#innerworkings)
    - [On Server Startup](#on-server-startup)
    - [How users are added](#how-users-are-added)
      - [What the server stores per user](#what-the-server-stores-per-user)
    - [Connecting as a client](#connecting-as-a-client)
      - [Password storage](#password-storage)
      - [Message delivery](#message-delivery)
    - [Mutual TLS](#mutual-tls)
      - [Certificate verification at login](#certificate-verification-at-login)
  
# General Information
---


## Requirements

- Python 3.8 or later
- OpenSSL
- `cryptography` library
```bash
pip install cryptography
```
- **Optional:** pip install `rich` for colorfull terminal output *(recommended but not required )*
```bash
pip install rich
```
## Project Structure

```
lan-messenger/
│
├── run_server.py           # Entry point to start the server
├── run_client.py           # Entry point to start the client
├── tests.py                # tests
│
├── server/
│   ├── server.py           # TCP server, session management, message routing
│   ├── database.py         # SQLite layer managment (users + store-and-forward messages)
│   ├──  lanmsg.db          # Created automatically on first run
│   └── provision_user.py   # Admin tool: register users and generate cert bundles
│
├── client/
│   ├── connection.py       # TCP connection, background receive thread, callbacks
│   └── client.py           # Terminal UI, command parser stuff
│
└── shared/
    ├── protocol.py         # Message types & packet framing (shared by both sides client-server)
    ├── authentication.py   # Password salting and hashing, verification
    └── tls.py              # SSL context, cert generation

```


## Features
[***Back to Table of Contents***](#table-of-contents)

**Security**
- **Mutual TLS (mTLS)** - both server and client authenticate with certificates; unauthenticated connections are rejected at the handshake

- **Admin-controlled user provisioning** - new users are added by an admin via `provision_user.py`
- **Certificate fingerprint pinning** - each login is verified against the SHA-256 fingerprint of the cert issued at provisioning time
- **Cert expiry checking** - expired certificates are explicitly rejected at login (in addition to the TLS handshake)
- **Secure password storage** - PBKDF2-HMAC-SHA256 with random salt and 200,000 iterations (TODO: look into higher iterations)
- **Timing-safe authentication** - constant-time password comparison and dummy hashing for unknown usernames avoid timing-based attacks
---
**Misc**
- **Store-and-forward** - messages sent to offline users are stored in the database and delivered automatically when they reconnect

- **Password login** - verifys a user's identity using a chosen password, stored as a salted hash
- **Real-time delivery** - messages to online users are pushed instantly over open TCP sockets
- **Broadcast messages** - send to all online users at once or message is stored for anyone currently offline
- **User registry** - persistent user accounts in SQLite
- **On/Offline notifications** - join/leave notifications and a `/users` command showing who is online
- **Rich terminal UI** - coloured output and formatted tables if `rich` is installed, plain text fallback if not

---
---


## Setup
[***Back to Table of Contents***](#table-of-contents)
### 1. Start the server

```bash
python run_server.py [--host HOST] [--port PORT]
  
  --host HOST    Address to listen on. Default: 0.0.0.0
  --port PORT    Port number. Default: 54321
```

On first run, the server generates a self-signed CA and a signed server certificate automatically. These are only created once and reused on subsequent starts.

### 2. Provision a user

Run this on the server machine for each user:

```bash
python server/provision_user.py <username> [--host <SERVER_LAN_IP>] [--port PORT]
```

You will be prompted for a temporary password. This creates a ready-to-distribute bundle at `provision_out/<username>/`:

```
provision_out/<username>/
├── ca.crt          # Server CA certificate
├── <username>.crt  # User's client certificate
├── <username>.key  # User's private key -- keep this secret
├── connect.sh      # Quick-connect script (Linux/macOS)
└── README.txt      # Instructions for the user
```

Copy this folder to the user's machine via USB or another trusted channel.

### 3. Connect as a client

```bash
# Using the provided script
cd provision_out/<username>/
./connect.sh

# Or manually
python run_client.py \
  --host <SERVER_LAN_IP> \
  --port 54321 \
  --ca   .../ca.crt \
  --cert .../<username>.crt \
  --key  .../<username>.key
```

### 4. First login

```
/login <username>
```

Then immediately change the temporary password:

```
/passwd
```

---

## Application Commands
[***Back to Table of Contents***](#table-of-contents)

Once connected to the server you can use the commands below.
| Command | Alias |  Description |
| -------- | -------- | -------- |
| `/login <name>` | | Log in (fetches pending messages automatically) |
| `/logout` | | Log out without disconnecting |
| `/msg <user> <text>` | `@<user> <text>` | Send a direct message |
| `/broadcast <text>` | `/bc`, `/all` | Send to all online users |
| `/fetch` | `/inbox` | Manually pull pending messages |
| `/users` | `/who`, `/list` | Show all users + online status |
| `/help` | | Show help |
| `/passwd` | | Change password |
| `/quit` | `/exit`, `/q` | Disconnect and exit |














# Innerworkings 
---
[***Back to Table of Contents***](#table-of-contents)

More thorough information on how the application works. 

## On Server Startup 

```bash
python run_server.py [--host 0.0.0.0] [--port 54321]
```

On first run the server will:

- Generate a self-signed CA (`server/CA/ca.crt` and `ca.key`) if one does not exist.
- Generate a server certificate signed by that CA (`server/server.crt` and `server.key`).
- Create the SQLite database (`server/lanmsg.db`).

The CA and server cert are only generated once. Subsequent starts reuse the existing files.

The server logs its certificate fingerprint on startup:

```
[INFO] Cert fingerprint (SHA-256): AA:BB:CC:...
```

## How users are added 
All users must be provisioned by an administrator directly on the server machine using `provision_user.py` ensuring only explicitly authorised identities can connect.

`provision_user.py` does the following in one step:

1. Registers the user in the database with a hashed temporary password.
2. Generates a client certificate signed by the server's CA.
3. Computes and stores the users certificate's SHA-256 fingerprint in the database.
4. Writes a distributable bundle to `provision_out/<username>/` containing everything the user needs to connect.

### What the server stores per user

| Field | Description |
|---|---|
| `username` | Case-insensitive, unique |
| `password_salt` | 32-byte random salt (hex) |
| `password_hash` | PBKDF2 digest (hex) |
| `cert_fingerprint` | SHA-256 fingerprint of the issued client cert (hex) |
| `created_at` | UTC timestamp |

## Connecting as a client

Use the connection script from your bundle:

```bash
# Linux / macOS
cd provision_out/<username>/
./connect.sh
```

Or connect manually:

```bash
python run_client.py \
  --host <SERVER_LAN_IP> \
  --port 54321 \
  --ca  .../ca.crt \
  --cert .../<username>.crt \
  --key  .../<username>.key
```
### Password storage

Passwords are hashed with PBKDF2-HMAC-SHA256 using a 32-byte random salt and 200,000 iterations. Verification uses `hmac.compare_digest` for constant-time comparison. Unknown usernames trigger a dummy hash computation to prevent timing-based user enumeration.

### Message delivery

Messages are stored in SQLite immediately on receipt. If the recipient is online, the server attempts live delivery and marks the message as delivered. If the recipient is offline, the message remains pending and is delivered automatically when they next log in, or can be retrieved manually with `/fetch`.


## Mutual TLS

Every connection requires both sides to present a valid certificate:

- The **server** presents `server.crt`, signed by the CA, with SANs covering its LAN IP and hostname.
- The **client** presents `<username>.crt`, signed by the same CA.
- The TLS handshake rejects any connection where either side cannot present a CA-signed certificate - unauthenticated clients cannot connect at all.

TLS 1.2 is the minimum version enforced.

### Certificate verification at login

The mTLS handshake authenticates the certificate. On top of that, `_handle_login` performs three additional checks using the `cryptography` library on the raw DER-encoded certificate:

1. **Expiry** - the certificate's `notAfter` field is checked against the current UTC time. The TLS handshake also enforces this, but it is checked explicitly (defence-in-depth).
2. **CN match** - the Common Name in the certificate Subject must match the username supplied in the login packet.

3. **Fingerprint match** - the SHA-256 fingerprint of the presented certificate is compared against the fingerprint stored in the database at provisioning time. *This binds each login to the exact certificate that was issued, so a different CA-signed certificate for the same CN is rejected*.




