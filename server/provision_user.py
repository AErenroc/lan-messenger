"""
User Provisioning:
    Run this on the server machine to create a new user account and generate
    their mTLS certificate bundle, which can then be copied to a USB drive or shared via other means.

Use:
    python provision_user.py <username> [--out ./provision_out]

Produces in --out/<username>/:
    ca.crt          -->  CA cert (for clients to verify server)
    <username>.crt  -->  Client cert signed by the CA
    <username>.key  -->  Client private key
    connect.sh      -->  Quick connection script that works for Linux/macOS (TODO: add windows script for quick connect)
    README.txt      -->  Instructions for the user
"""

import argparse
import getpass
import shutil
import sys
import os
from pathlib import Path
from datetime import datetime

# Allow running from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


from server.database import Database
from shared.authentication import hash_password
from shared.tls import (generate_ca, generate_client_cert, CA_CERT_PATH, CA_KEY_PATH, CLIENT_CERT_DIR)


def provision_user(
    username:   str,
    password:   str,
    out_dir:    Path,
    server_host: str = "0.0.0.0",
    server_port: int = 54321,
) -> Path:
    """
    Register the requested user in the DB, generate their cert bundle and write
    everything to [out_dir]/<username>/ ready for sharing using USB or other means.
    Returns the bundle directory path.
    """
    db = Database()

    # Register user in database --------------------------
    salt_hex, hash_hex = hash_password(password)
    if not db.register_user(username, salt_hex, hash_hex):
        print(f"\t[!] Username '{username}' is already registered.")
        sys.exit(1)
    print(f"\t[+] Registered '{username}' in database.")

    # Ensure CA already exists -----------------------------
    generate_ca(CA_CERT_PATH, CA_KEY_PATH)

    # Generate signed client cert --------------------------
    cert_path, key_path = generate_client_cert(
        username     = username,
        cert_dir     = CLIENT_CERT_DIR,
        ca_cert_path = CA_CERT_PATH,
        ca_key_path  = CA_KEY_PATH,
    )
    print(f"\t[+] Client cert generated: {cert_path}")

    # Build the bundle to distribute --------------------------
    bundle_dir = out_dir / username
    bundle_dir.mkdir(parents=True, exist_ok=True)

    # Copy the three files the client needs
    shutil.copy2(CA_CERT_PATH, bundle_dir / "ca.crt")
    shutil.copy2(cert_path,    bundle_dir / f"{username}.crt")
    shutil.copy2(key_path,     bundle_dir / f"{username}.key")

    # Protect the private key in the bundle too
    os.chmod(bundle_dir / f"{username}.key", 0o600)

    # Add quick connect helper script + README --------------------------
    _write_connect_sh(bundle_dir, username, server_host, server_port)
    _write_readme(bundle_dir, username, server_host, server_port)

    print(f"\t[+] Bundle ready at: {bundle_dir.resolve()}")
    return bundle_dir


# Script / README generators ------------------------------------------------------------------------------
def _write_connect_sh(
    bundle_dir:  Path,
    username:    str,
    server_host: str,
    server_port: int,
) -> None:
    
    script = bundle_dir / "connect.sh"
    script.write_text(f"""\
#!/usr/bin/env bash
# LAN Messenger - connect as {username}
# Copy this entire folder to your machine, then run this script from inside it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"

python3 "$SCRIPT_DIR/../../../../run_client.py" \\
    --host {server_host} \\
    --port {server_port} \\
    --ca   "$SCRIPT_DIR/ca.crt" \\
    --cert "$SCRIPT_DIR/{username}.crt" \\
    --key  "$SCRIPT_DIR/{username}.key"
""")
    os.chmod(script, 0o755)


def _write_connect_bat(
    bundle_dir:  Path,
    username:    str,
    server_host: str,
    server_port: int,
) -> None:
    (bundle_dir / "connect.bat").write_text(f"""\
@echo off
REM LAN Messenger — connect as {username}
REM Copy this entire folder to your machine, then double-click this file.
set SCRIPT_DIR=%~dp0
python run_client.py ^
    --host {server_host} ^
    --port {server_port} ^
    --ca   "%SCRIPT_DIR%ca.crt" ^
    --cert "%SCRIPT_DIR%{username}.crt" ^
    --key  "%SCRIPT_DIR%{username}.key"
pause
""")


def _write_readme(
    bundle_dir:  Path,
    username:    str,
    server_host: str,
    server_port: int,
) -> None:
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    (bundle_dir / "README.txt").write_text(f"""\
LAN Messenger - Connection Bundle for '{username}'
Generated: {generated_at}

FILES IN THIS BUNDLE
--------------------------
  ca.crt          Server's CA certificate (proves you're talking to the right server)
  {username}.crt  Your personal client certificate
  {username}.key  Your private key — DO NOT share this with anyone

QUICK START
-----------
  Linux / macOS : run  ./connect.sh
  Windows       : run  connect.bat

MANUAL CONNECTION
-----------
  python run_client.py \\
      --host {server_host} \\
      --port {server_port} \\
      --ca   ca.crt \\
      --cert {username}.crt \\
      --key  {username}.key

FIRST LOGIN
--------------------------
  Once connected, type:
      /login {username}
  You will be prompted for your password.

  Then immediately change your temporary password:
      /passwd <new-password>

SECURITY NOTES
--------------------------
  - Keep {username}.key secret as it proves your identity to the server.

""")




def main():
    parser = argparse.ArgumentParser(
        description="Provision a new user and generate their cert bundle."
    )
    parser.add_argument("username",      help="Username to register")
    parser.add_argument("--out",         default="./provision_out", metavar="DIR",
                        help="Output directory for bundles (default: ./provision_out)")
    parser.add_argument("--host",        default="0.0.0.0",
                        help="Server LAN IP written into connect scripts")
    parser.add_argument("--port",        type=int, default=54321,
                        help="Server port written into connect scripts")
    parser.add_argument("--set-password", action="store_true",
                        help="Set a real password interactively instead of prompting twice")
    args = parser.parse_args()

    username = args.username.strip()

    # Validate username using the same rules as the server
    if not username or len(username) > 32:
        print("[!] Username must be 1–32 characters.")
        sys.exit(1)
    if not username.replace("_", "").replace("-", "").isalnum():
        print("[!] Username may only contain letters, digits, - and _.")
        sys.exit(1)

    # Get temporary password
    print(f"Setting temporary password for '{username}'.")
    print("The user should change this immediately after first login.\n")
    while True:
        pw  = getpass.getpass("Temporary password (min 8 chars): ")
        pw2 = getpass.getpass("Confirm password               : ")
        if pw != pw2:
            print("[!] Passwords do not match, try again.\n")
            continue
        if len(pw) < 8:
            print("[!] Password must be at least 8 characters.\n")
            continue
        break

    bundle = provision_user(
        username    = username,
        password    = pw,
        out_dir     = Path(args.out),
        server_host = args.host,
        server_port = args.port,
    )

    print(f"\n{'─'*50}")
    print(f"  Copy  {bundle}  to a USB drive")
    print(f"  and hand it to {username}.")
    print(f"{'─'*50}\n")


if __name__ == "__main__":
    main()