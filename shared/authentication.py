import hashlib #also review security , mabye use bcrypt
import hmac
import secrets
from typing import Tuple

ITERATIONS = 200_000
SALT_SIZE = 32 #


def hash_password(password: str) -> Tuple[str, str]:
    """
    Returns:    Tuple[salt_hex, hash_hex]
    """
    salt = secrets.token_bytes(SALT_SIZE)
    digest = hashlib.pbkdf2_hmac( "sha256", password.encode(), salt, ITERATIONS,)
    # salt_hex, hash_hex
    return salt.hex(), digest.hex()

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac( "sha256", password.encode(), salt, ITERATIONS,)
    return hmac.compare_digest(digest.hex(), hash_hex) 