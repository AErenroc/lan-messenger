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


"""def main():
    # TESTING
    pw1 = "MR_COOLGUY"
    pw2 = "THE_WRONG_PASSWORD"

    #Salt and hex for right pw
    salt_hex1, hash_hex1 = hash_password(pw1)

    #Salt and hex for wrong password
    salt_hex2, hash_hex2 = hash_password(pw2)

    result1 = verify_password(pw1, salt_hex1, hash_hex1)
    result2 = verify_password(pw2, salt_hex1, hash_hex1)

    result3 = verify_password(pw2, salt_hex2, hash_hex1)

    print(F"\n pw1 compared its own salt+hash --> {result1}\n")
    print(f"\n pw2 compared to p1's salt+hash --> {result2}")
    print(f"\n pw2 compared to pw2 salt , p1's hash --> {result3}")
    

if __name__ == "__main__":
    main()"""