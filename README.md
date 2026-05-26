# lan-messenger

A store-and-forward messaging system for local networks, written in Python with SQLite persistence and password authentication. Traffic is encrypted with TLS. The server generates a self-signed certificate on first run, clients verify it by fingerprint or by pinning the certificate file directly.

## Requirements
- Python 3.8 or later
- OpenSSL
- Optional: pip install rich for colored terminal output


## Features
- **Store-and-forward** — messages sent to offline users are stored in the database and delivered automatically when they reconnect
- **Password login** -- verifys a user's identity using a chosen password, stored as a salted hash
- **Real-time delivery** — messages to online users are pushed instantly over open TCP sockets
- **Broadcast messages** — send to all online users at once or message is stored for anyone currently offline
- **User registry** — persistent user accounts in SQLite
- **On/Offline notifications** — clients are notified when users join or leave the network
- **User list** — see who's registered and who's currently online

## Command-line flags

### Server

```
python run_server.py [--host HOST] [--port PORT]

  --host HOST    Address to listen on. Default: 127.0.0.1
  --port PORT    Port number. Default: 54321
```

### Client

```
python run_client.py [--host HOST] [--port PORT] [--cert PATH] [--no-verify]

  --host HOST    Server IP address. Default: 127.0.0.1
  --port PORT    Server port. Default: 54321
  --cert PATH    Path to server.crt for certificate pinning
  --no-verify    Skip TLS certificate verification (insecure, testing only)
```

## Commands
| Command | Alias |  Description |
| -------- | -------- | -------- |
| `/register <name>` | | Create a new account |
| `/login <name>` | | Log in (fetches pending messages automatically) |
| `/logout` | | Log out without disconnecting |
| `/msg <user> <text>` | `@<user> <text>` | Send a direct message |
| `/broadcast <text>` | `/bc`, `/all` | Send to all online users |
| `/fetch` | `/inbox` | Manually pull pending messages |
| `/users` | `/who`, `/list` | Show all users + online status |
| `/help` | | Show help |
| `/quit` | `/exit`, `/q` | Disconnect and exit |


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
│   └── lanmsg.db           # Created automatically on first run
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

## Optional: Prettier Output with `rich`

```bash
pip install rich
```

The client auto-detects `rich` and uses coloured output, tables, and panels if available. Falls back to plain text otherwise. Not a requirement.