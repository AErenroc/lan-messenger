"""
LAN Messenger – - - Terminal Client (TUI)
A polished terminal interface built with only the stdlib + optional 'rich'.

Usage:
    python client.py [--host SERVER_IP] [--port 54321]

If 'rich' is not installed, falls back to plain text.
"""

import argparse
import queue
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import getpass # for masking user input as it is typed

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client.connection import Connection
from shared.protocol import (
    DEFAULT_PORT, MAX_PACKET,
    MSG_OK, MSG_ERROR, MSG_DELIVER, MSG_USER_LIST, MSG_NOTIFY,
)


# Try to use 'rich' for nicer output but fall back if not inst --------------------------------------
try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich.table import Table #for db stuff
    from rich import print as rprint
    HAVE_RICH = True
    console = Console()
except ImportError:
    HAVE_RICH = False
    console = None  # type: ignore


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _print_info(msg: str):
    if HAVE_RICH:
        console.print(f"[dim]{_ts()}[/dim] [cyan](i) {msg}[/cyan]")
    else:
        print(f"[{_ts()}] INFO: {msg}")


def _print_ok(msg: str):
    if HAVE_RICH:
        console.print(f"[dim]{_ts()}[/dim] [green](o) {msg}[/green]")
    else:
        print(f"[{_ts()}] OK: {msg}")


def _print_error(msg: str):
    if HAVE_RICH:
        console.print(f"[dim]{_ts()}[/dim] [bold red](x) {msg}[/bold red]")
    else:
        print(f"[{_ts()}] ERROR: {msg}")


def _print_msg(from_user: str, body: str, sent_at: str, broadcast: bool = False):
    tag = " [BROADCAST]" if broadcast else ""
    if HAVE_RICH:
        label = f"[bold magenta]{from_user}[/bold magenta][yellow]{tag}[/yellow]"
        console.print(
            f"[dim]{sent_at}[/dim] {label}[white]: {body}[/white]"
        )
    else:
        print(f"[{sent_at}] <{from_user}{tag}>: {body}")


def _print_notify(event: str, username: str):
    icon = "-->" if event == "joined" else "<--"
    verb = "joined" if event == "joined" else "left"
    if HAVE_RICH:
        console.print(f"[dim]{_ts()}[/dim] [bold yellow]{icon} {username} {verb} the network[/bold yellow]")
    else:
        print(f"[{_ts()}] *** {username} {verb} the network ***")




# Main client class ------------------------------------------------
class MessengerClient:
    def __init__(self, host: str, port: int, cert_path=None, verify: bool = True):
        self.host = host
        self.port = port
        self.conn = Connection(host, port, cert_path=cert_path, verify=verify)
        self.username: Optional[str] = None
        self._running = True
        self._input_q: queue.Queue[str] = queue.Queue()

        # Wire callbacks
        self.conn.on(MSG_OK,        self._on_ok)
        self.conn.on(MSG_ERROR,     self._on_error)
        self.conn.on(MSG_DELIVER,   self._on_deliver)
        self.conn.on(MSG_USER_LIST, self._on_user_list)
        self.conn.on(MSG_NOTIFY,    self._on_notify)
        self.conn.on_disconnect(self._on_disconnect)


    # Server callbacks -----------------------------------------------------
    def _on_ok(self, pkt: dict):
        if pkt.get("info"):
            _print_ok(pkt["info"])

    def _on_error(self, pkt: dict):
        _print_error(pkt.get("info", "Unknown error"))

    def _on_deliver(self, pkt: dict):
        _print_msg(
            from_user=pkt.get("from", "?"),
            body=pkt.get("body", ""),
            sent_at=pkt.get("sent_at", _ts()),
            broadcast=pkt.get("broadcast", False),
        )

    def _on_user_list(self, pkt: dict):
        users = pkt.get("users", [])
        if HAVE_RICH:
            table = Table(title="Registered Users", show_header=True, header_style="bold cyan")
            table.add_column("Username", style="white")
            table.add_column("Status", justify="center")
            for u in users:
                status = "[green]● online[/green]" if u["online"] else "[dim]○ offline[/dim]"
                table.add_row(u["username"], status)
            console.print(table)
        else:
            print("\n--- Registered Users ---")
            for u in users:
                status = "ONLINE" if u["online"] else "offline"
                print(f"  {u['username']:20s} [{status}]")
            print("------------------------\n")

    def _on_notify(self, pkt: dict):
        _print_notify(pkt.get("event", ""), pkt.get("username", "?"))

    def _on_disconnect(self):
        if self._running:
            _print_error("Connection to server lost.")
            self._running = False

  
    # Help display banner ------------------------------------------------------------------
    def _print_banner(self):
        if HAVE_RICH:
            console.print(Panel.fit(
                "[bold cyan]LAN Messenger[/bold cyan]\n"
                f"[dim]Connected to [white]{self.host}:{self.port}[/white][/dim]",
                border_style="cyan",
            ))
        else:
            print("=" * 40)
            print("  LAN Messenger")
            print(f"  Server: {self.host}:{self.port}")
            print("=" * 40)

    def _print_help(self):
        help_text = """
Commands:
  /register <name>        Register a new username
  /login <name>           Log in as an existing user
  /logout                 Log out (stay connected)
  /msg <user> <text>      Send a direct message
  /broadcast <text>       Send to all online users
  /fetch                  Retrieve pending messages
  /users                  List all registered users
  /help                   Show this help
  /quit                   Disconnect and exit

Shorthand while logged in:
  @<user> <text>          Same as /msg <user> <text>
  /<anything else>        Falls through to /msg if ambiguous
"""
        if HAVE_RICH:
            console.print(Panel(help_text.strip(), title="Help", border_style="dim"))
        else:
            print(help_text)

  
    # Input loop ----------------------------------------------------------
    def run(self):
        # Connect
        try:
            _print_info(f"Connecting to {self.host}:{self.port} …")
            self.conn.connect(timeout=5.0)
            _print_ok(f"Connected! Type /help for commands.")
        except OSError as exc:
            _print_error(f"Cannot connect: {exc}")
            sys.exit(1)

        self._print_banner()

        while self._running:
            try:
                line = input(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            self._handle_input(line)

        self.conn.disconnect()
        print("\nGoodbye.")

    def _prompt(self) -> str:
        u = self.username or "guest"
        if HAVE_RICH:
            # Note - Rich renders markup in prompts unreliably keep, it plain
            return f"[{u}]> "
        return f"[{u}]> "

    def _handle_input(self, line: str):
        # @user shorthand
        if line.startswith("@") and " " in line:
            parts = line[1:].split(" ", 1)
            self._cmd_msg(parts[0], parts[1])
            return

        if not line.startswith("/"):
            _print_info("Use /help for commands, or @<user> <text> to send a message.")
            return

        parts = line[1:].split(" ", 2)
        cmd = parts[0].lower()

        if cmd == "help":                                   # HELP 
            self._print_help()
        elif cmd == "register":                             # REGISTER - - - - - - - - - - - - 
            if len(parts) < 2:
                _print_error("Usage: /register <username>")
            else:
                password = getpass.getpass("Choose a password: ")
                confirm  = getpass.getpass("Confirm password:  ")
                if password != confirm:
                    _print_error("Passwords do not match!")
                elif len(password) < 8:
                    _print_error("Password must be at least 8 characters")
                else:
                    self.conn.register(parts[1], password)
        elif cmd == "login":                                # LOGIN - - - - - - - - - - - - - -
            if len(parts) < 2:
                _print_error("Usage: /login <username>")
            else:
                password = getpass.getpass("Password: ")
                self.username = parts[1]
                self.conn.login(parts[1], password)
        elif cmd == "logout":                               # LOGOUT
            self.conn.logout()
            self.username = None
        elif cmd in ("msg", "message", "send"):             # MSG/MESSAGE/SEND
            if len(parts) < 3:
                _print_error("Usage: /msg <user> <message>")
            else:
                self._cmd_msg(parts[1], parts[2])
        elif cmd in ("broadcast", "bc", "all"):             # BROADCAST / BC / ALL
            if len(parts) < 2:
                _print_error("Usage: /broadcast <message>")
            else:
                self.conn.broadcast(" ".join(parts[1:]))
        elif cmd in ("fetch", "inbox"):                     # FETCH / INBOX
            self.conn.fetch()
        elif cmd in ("users", "list", "who"):               # USERS / LIST / WHO
            self.conn.list_users()
        elif cmd in ("quit", "exit", "q"):                  # QUIT / EXIT / Q
            self._running = False
        else:
            _print_error(f"Unknown command '/{cmd}'. Type /help.")

    def _cmd_msg(self, to: str, body: str):
        if not self.username:
            _print_error("You must /login first.")
            return
        if not body.strip():
            _print_error("Message cannot be empty.")
            return
        self.conn.send_message(to, body)



# Entry point --------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="LAN Messenger Client")
    parser.add_argument("--host", default="127.0.0.1", help="Server IP address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Server port (default: {DEFAULT_PORT})")

    tls_group = parser.add_argument_group("TLS / encryption")
    tls_group.add_argument(
        "--cert", default=None, metavar="PATH",
        help="Path to server's PEM certificate for pinned verification "
             "(e.g. server/server.crt). Recommended for security.",
    )

    tls_group.add_argument(
        "--no-verify", action="store_true",
        help="Skip TLS certificate verification (NOT recommended; for testing only).",
    )

    args = parser.parse_args()

    cert_path = Path(args.cert) if args.cert else None
    verify    = not args.no_verify

    client = MessengerClient(args.host, args.port, cert_path=cert_path, verify=verify)
    client.run()


if __name__ == "__main__":
    main()