import hashlib, hmac, os, secrets
from Crypto.Cipher import AES

def store_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 600_000)
    return f"{salt.hex()}:{dk.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    salt_hex, dk_hex = stored.split(":")
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt_hex), 600_000)
    return hmac.compare_digest(dk, bytes.fromhex(dk_hex))

def get_encryption_key() -> bytes:
    key_hex = os.environ.get("APP_ENCRYPTION_KEY")
    if not key_hex:
        raise RuntimeError("APP_ENCRYPTION_KEY is not set.")
    return bytes.fromhex(key_hex)

def encrypt_data(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ct

def decrypt_data(blob: bytes, key: bytes) -> bytes:
    nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)

def reset_token() -> str:
    return secrets.token_urlsafe(32)

if __name__ == "__main__":
    key = get_encryption_key()
    h = store_password("password123")
    print("valid:", verify_password("password123", h))
    enc = encrypt_data(b"A" * 16 + b"A" * 16, key)
    print("decrypted:", decrypt_data(enc, key))
    print("token:", reset_token())