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

# Paths ---------------------------------------------------------
_ROOT_DIR = Path(__file__).resolve().parent.parent
_SERVER_DIR =  _ROOT_DIR / "server"
_CLIENT_DIR =  _ROOT_DIR / "client"

# CA and Certificate paths 
CA_CERT_PATH =  _SERVER_DIR / "ca.crt"
CA_KEY_PATH = _SERVER_DIR / "ca.key"

CERT_PATH = _SERVER_DIR / "server.crt"
KEY_PATH  = _SERVER_DIR / "server.key"

CLIENT_CERT_DIR = _CLIENT_DIR / 'certs'     # Contains <username>.crt/.key 
# ----------------------------------------------------------------

# TLS minimum version ----------------------------------------------
_MIN_TLS = ssl.TLSVersion.TLSv1_2 # 771 --> 0x0303: "TLS_1_2"
_CIPHERS = "HIGH:!aNULL:!eNULL:!MD5:!RC4:!3DES"
_CERT_DAYS = 365


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


def _run_openssl(*args: str) -> None:
    """
    Runs a openssl subcommand, raise RunTimeError on failure.
    example. 
    _run_openssl(    "req", "-x509", "-newkey", "rsa:4096",
                    "-keyout", str(ca_key_path),
                    "-out",    str(ca_cert_path), ...
                )
    """
    result = subprocess.run(
        ["openssl", *args],
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError( f"openssl {args[0]} failed:\n{result.stderr.decode()}" )



# Build CA (to run once on server) ----------------------------------------------------------------------------
def generate_ca(ca_cert_path: Path = CA_CERT_PATH, 
                ca_key_path: Path = CA_KEY_PATH, 
                days: int = _CERT_DAYS * 2,        # (x2) to make CA live longer than leaf certs
                cn: str = "lanmsg-CA",) -> None:
    """
    Generate a self signed CA cert and private key. 
    Called automatically by server_ssl_context() if the CA doesn't exist yet. 
    Shouldn't overwrite an existing CA.
    """
    if ca_cert_path.exists() and ca_key_path.exists():
        log.info("CA already exists at %s - Skipping CA generation", ca_cert_path)
        return
    
    if not _openssl_available():
        print("\n[!] openssl not found — cannot generate CA. \tExiting...\n")
        sys.exit(1)

    ca_cert_path.parent.mkdir(parents=True, exist_ok=True)
    log.info("Generating a private CA [ %s ]...", cn)

    _run_openssl(
        "req", 
        "-x509", # create a self-signed cert
        "-newkey", "rsa:4096",
        "-keyout", str(ca_key_path),
        "-out",    str(ca_cert_path),
        "-days",   str(days),
        "-nodes",   # creates an unencrypted private key (no prompt for password) TODO: mabye change later
        "-subj",   f"/CN={cn}/O=LAN-Messenger-CA",
        "-extensions", "v3_ca",
    )
    # Extra security restricting key permissions
    os.chmod(ca_key_path, 0o600)    # r,w for owner only
    log.info("CA certificate: [%s]", ca_cert_path)
    log.info("CA private key : [%s] (keep this secret!!!)", ca_key_path)


# Certificate signing functions for leaf certs ----------------------------------------------------------------------------
def _build_san_config(host_addr: str, cn: str) -> str:
    """
    Returns an openssl config string with SAN for a server cert.
    """
    # Build a SAN extension that includes the machine's LAN IP so clients connecting by IP don't cause hostname mismatch.
    try:
        hostname = socket.gethostbyaddr(host_addr)[0] 
    except Exception:
        log.info("No reverse DNS record for %s, setting default as 'lanmsg-server", host_addr)
        hostname = "lanmsg-server"

    return f"""
    [req]
    distinguished_name = req_dn
    x509_extensions    = v3_req
    prompt             = no
    [req_dn]
    CN = {cn}
    
    [v3_req]
    subjectAltName     = @alt_names
    basicConstraints   = CA:FALSE
    keyUsage           = digitalSignature, keyEncipherment
    extendedKeyUsage   = serverAuth
    
    [alt_names]
    IP.1  = 127.0.0.1
    IP.2  = {host_addr}
    DNS.1 = localhost
    DNS.2 = {hostname}"""


def _sign_cert(
    csr_path:      Path,
    cert_path:     Path,
    ca_cert_path:  Path ,
    ca_key_path:   Path ,
    days:          int = _CERT_DAYS,
    extra_openssl_args: list[str] | None = None,
) -> None:
    """
    Signs a CSR with the CA and writes the resulting cert.
    """
    cmd = [
        "x509", "-req", # Take a CSR and produce a certificate.
        "-in",      str(csr_path),
        "-CA",      str(ca_cert_path),
        "-CAkey",   str(ca_key_path),
        "-CAcreateserial",
        "-out",     str(cert_path),
        "-days",    str(days),
        "-sha256",
    ]
    if extra_openssl_args:  # for SANs
        cmd.extend(extra_openssl_args)
    _run_openssl(*cmd)


def generate_server_cert(
    host_addr:    str  = "127.0.0.1",
    cert_path:    Path = CERT_PATH, #_SERVER_DIR / "server.crt"
    key_path:     Path = KEY_PATH,
    ca_cert_path: Path = CA_CERT_PATH,
    ca_key_path:  Path = CA_KEY_PATH,
    days:         int  = _CERT_DAYS,
    cn:           str  = "lanmsg-server",
) -> None:
    """
    Generate the server's key+CSR, then sign it with the CA.
    Called by server_ssl_context() automatically when needed. 
    """
    if not _openssl_available():
        print("\n[!] openssl not found — cannot generate server cert. \tExiting...\n")
        sys.exit(1)
    
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:   # For CSR, deletes after cert is signed.
        csr_path = Path(tmpdir) / "server.csr"
        cnf_path = Path(tmpdir) / "server.cnf"
        cnf_path.write_text(_build_san_config(host_addr, cn))       # Def. (CNF) file is OpenSSL ConfFile that automates the gen of your CSR by defining your server's identifying details and security parameters
        ext_path = Path(tmpdir) / "server_ext.cnf"
        ext_path.write_text(
            "[v3_req]\n"
            "subjectAltName=IP:127.0.0.1,IP:{},DNS:localhost\n"
            "basicConstraints=CA:FALSE\n"
            "keyUsage=digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n".format(host_addr)
        )


def generate_client_cert(
    username:     str,
    cert_dir:     Path = CLIENT_CERT_DIR,
    ca_cert_path: Path = CA_CERT_PATH,
    ca_key_path:  Path = CA_KEY_PATH,
    days:         int  = _CERT_DAYS,
) -> tuple[Path, Path]:
    """
    Generate a client key+cert signed by the CA for <username>.
    Returns (cert_path, key_path).

    Called by the server during the /register so the server is the authority that issues client certs.
    """
    if not _openssl_available():
        print("\n[!] openssl not found — cannot generate client cert. \tExiting...\n")
        sys.exit(1)

    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / f"{username}.crt"
    key_path  = cert_dir / f"{username}.key"

    with tempfile.TemporaryDirectory() as tmpdir:
        csr_path = Path(tmpdir) / f"{username}.csr"
        ext_path = Path(tmpdir) / "client_ext.cnf"
        ext_path.write_text(
            "[v3_client]\n"
            "basicConstraints = CA:FALSE\n"
            "keyUsage         = digitalSignature\n"
            "extendedKeyUsage = clientAuth\n"       # <-- clientAuth, not serverAuth
            f"subjectAltName  = email:{username}@lanmsg.local\n"
        )

        # Key + CSR — CN is the username so it's visible in server logs
        _run_openssl(
            "req", "-newkey", "rsa:2048",
            "-keyout", str(key_path),
            "-out",    str(csr_path),
            "-nodes",
            "-subj",   f"/CN={username}/O=LAN-Messenger",
        )
        _sign_cert(
            csr_path, cert_path,
            ca_cert_path, ca_key_path,
            days,
            extra_openssl_args=["-extfile", str(ext_path), "-extensions", "v3_client"],
        )

    os.chmod(key_path, 0o600)
    log.info("Client cert issued for '%s': %s", username, cert_path)
    return cert_path, key_path

















# ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~

# ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~



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



def generate_self_signed_cert(host_addr: str, cert_path: Path = CERT_PATH, key_path: Path  = KEY_PATH, days: int = _CERT_DAYS, cn: str = "lanmsg-server") -> None:
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
    ctx.set_ciphers(_CIPHERS)
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
    ctx.set_ciphers(_CIPHERS)

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

