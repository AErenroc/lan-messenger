"""
LAN Messenger - - - TLS Stuff

"""

import hashlib
import logging
import os
import socket
import ssl
import subprocess
import tempfile
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger("lan-messanger.tls")

# Paths (relative to the server/ package directory)
_SERVER_DIR = Path(__file__).resolve().parent.parent / "server"
CERT_PATH = _SERVER_DIR / "server.crt"
KEY_PATH  = _SERVER_DIR / "server.key"

# TLS minimum version
_MIN_TLS = ssl.TLSVersion.TLSv1_2 # 771 --> 0x0303: "TLS_1_2"



# Certificate generation, server-side/ one-time ----------------------------------------------------------------------------
def _openssl_available() -> bool:
    try:
        subprocess.run(
            ["openssl", "version"],
            check=True, capture_output=True, timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False



def _gen_cert_openssl(host_addr: str, cert_path: Path, key_path: Path, days: int, cn: str) -> None:
    """
    Uses the system openssl binary to generate a self-signed cert.
    """
    # Build a SAN extension that includes the machine's LAN IP so clients connecting by IP don't cause hostname mismatch.
    try:
        hostname = socket.gethostbyaddr(host_addr)[0] #FOR LOOK UP LATER
    except Exception:
        log.info("No reverse DNS record for %s", host_addr)
        hostname = "lanmsg-server"
     

    # check stuff, remove later
    print(f"\n\t\thostname ->> {hostname}, HOSTADDR ->>{host_addr}\n")
    print(f"\n\t IN _gen_cert_openssl() --> host_addr= {host_addr}, hostname = {hostname}\n")
    san = f"IP:{host_addr},IP:127.0.0.1,DNS:localhost,DNS:lanmsg-server"
    print(f"\n\n_gen_cert_ openssl() -->  {san}\n\n")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".cnf", delete=False) as f:
        f.write(
            f"""
[req]
distinguished_name=req_dn
x509_extensions=v3_req
prompt=no

[req_dn]
CN={cn}

[v3_req]
subjectAltName=@alt_names
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth

[alt_names]
IP.1=127.0.0.1
IP.2={host_addr}
DNS.1=localhost
DNS.2={hostname}
"""
        )
        cnf_path = f.name


    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path),
                "-out",    str(cert_path),
                "-days",   str(days),
                "-nodes",                  # no passphrase on the key
                "-config", cnf_path,
            ],
            check=True,
            capture_output=True,
        )
    finally:
        os.unlink(cnf_path)



def generate_self_signed_cert(host_addr: str, cert_path: Path = CERT_PATH, key_path: Path  = KEY_PATH, days: int = 365, cn: str = "lanmsg-server") -> None:
    """
    Generate a self-signed RSA-2048 / SHA-256 certificate using openssl.
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    if _openssl_available():
        _gen_cert_openssl(host_addr, cert_path, key_path, days, cn)
    else:
        print("\n[!] ~~~~~~~~~ Openssl not available, could not generate self signed cert ~~~~~~~~~\n Closing...\n") #TODO: add to logs, add rich response to cli
        sys.exit() # TODO: add another other cert gen before giving up


    log.info("TLS certificate written to %s", cert_path)
    log.info("TLS private key  written to %s", key_path)
    log.info("Certificate fingerprint (SHA-256): %s", cert_fingerprint(cert_path))



# Certificate fingerprint ---------------------------------
def cert_fingerprint(cert_path: Path = CERT_PATH) -> str:
    """
    Return the SHA-256 fingerprint of a PEM certificate (colon-separated hex).
    """
    pem = cert_path.read_bytes()
    # Strip PEM armour to get DER bytes
    der = ssl.PEM_cert_to_DER_cert(pem.decode())
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2))



# SSL context factories ------------------------------------------------------------------------------------------------------------------
# used in server/server.py
def server_ssl_context(host_addr: str = "127.0.0.1", cert_path: Path = CERT_PATH, key_path: Path  = KEY_PATH,) -> ssl.SSLContext:
    """
    Build an SSLContext for the server side.
    Auto-generates the certificate if it does not exist yet.
    """
    if not cert_path.exists() or not key_path.exists():
        log.info("No TLS certificate found — generating self-signed cert for [%s] ...", host_addr)
        generate_self_signed_cert(host_addr, cert_path, key_path)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _MIN_TLS
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    # Disable insecure cipher suites bc of paranoia
    ctx.set_ciphers("HIGH:!aNULL:!eNULL:!MD5:!RC4:!3DES")
    return ctx



# used in client/connection.py
def client_ssl_context( cert_path: Optional[Path] = None, verify: bool = True) -> ssl.SSLContext:
    """
    Build an SSLContext for the client side.

    Parameters
    cert_path : Path or None
        Path to the server's PEM certificate to use as the trusted CA.
    verify : bool
        If False, skip certificate verification entirely (INSECURE — for
        testing or fully-trusted networks only).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = _MIN_TLS
    ctx.set_ciphers("HIGH:!aNULL:!eNULL:!MD5:!RC4:!3DES")

    # TODO: remove verify check and always use cert after testing
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # If path the CERTIFICATE exists, use it
    if cert_path and cert_path.exists():
        # Pin to the server's specific self-signed cert
        ctx.load_verify_locations(cafile=str(cert_path))
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True              
    else:
       print("\n[!] ~~~~~~~~~~~~~ cert_path not found ~~~~~~~~~~~~~\n Closing...\n")
       sys.exit()

    return ctx

