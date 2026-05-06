# lan-messenger


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
    └── protocol.py         # Message types & packet framing (shared by both sides client-server)

```