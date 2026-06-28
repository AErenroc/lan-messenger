TODO:

- [ADDED] authentication, password hashing etc DONE
        -- NEED TO CREATE TESTS FOR
- [ADDED] password changing


- add mutual TLS, temp CA
        - add Extended Key Usage for mutualTLS , restrict what certs can be used for
        - need to figure out how to distribute certs, (make on server dist manually?)
- add setup.py instead of using 'sys.path.insert(0, str(Path(__file__).resolve().parent.parent))'
        --> from setuptools import setup, find_packages


- Let admin/user replace old cert with new cert

## Things you need to fix!

- **No rate limiting on login attempts.** A client can make unlimited failed login attempts. A per-IP attempt counter with lockout or exponential backoff should be added.
- **Packet size not enforced on receive.** The 4-byte length header is read and used directly to allocate the receive buffer without checking against `MAX_PACKET` (64 KB). A malicious client could advertise an oversized body. A bounds check before `_recvall` should be added.
- **CA private key lives on the server at runtime.** `provision_user.py` reads `ca.key` to sign new certificates. If the server is compromised, the CA key is at risk. For higher-security deployments, consider offline CA key storage and a separate signing step.
- **Windows quick-connect script not included.** `connect.bat` is stubbed in the code but not written by `provision_user.py`. A Windows user must connect manually.
- **Password hashing.** PBKDF2-SHA256 is used. Consider migrating to `argon2-cffi` (Argon2id), which is memory-hard and more resistant to GPU-based attacks.
- **CN used for cert identity.** Cert identity checks use the Subject CN field. Migrating to Subject Alternative Names (SANs) for client certs would be more robust and forward-compatible.