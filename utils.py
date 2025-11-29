import os
import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

# ---------------- USERS -----------------

def load_users():
    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            return json.load(f)
    return {}


def save_users(users: dict):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)


def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)

    pw_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200000,
    )

    return (
        base64.b64encode(salt).decode(),
        base64.b64encode(pw_hash).decode()
    )


def verify_password(password: str, salt_b64: str, stored_hash_b64: str) -> bool:
    salt = base64.b64decode(salt_b64)
    stored_hash = base64.b64decode(stored_hash_b64)

    test_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200000,
    )

    return test_hash == stored_hash


def generate_rsa_keypair():
    key = RSA.generate(2048)
    public_key = key.publickey().export_key().decode()
    private_key_bytes = key.export_key()
    return public_key, private_key_bytes


def encrypt_private_key(private_key_bytes: bytes, password: str):
    aes_key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_key_bytes)

    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(cipher.nonce).decode(),
        base64.b64encode(tag).decode()
    )


def decrypt_private_key(ciphertext_b64: str, nonce_b64: str, tag_b64: str, password: str):
    aes_key = hashlib.sha256(password.encode()).digest()

    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ---------------- CONTACTS -----------------

def derive_session_key(password: str):
    """
    Derive a 256-bit symmetric key from the user's password.
    Used for encrypting contacts (and could be reused for other session data).
    """
    return hashlib.sha256(password.encode()).digest()


def encrypt_json_with_key(data: dict, key: bytes):
    """
    Encrypt a JSON-serializable dict using AES-GCM with the given key.
    Returns a dict containing base64-encoded nonce, tag, ciphertext.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    plaintext = json.dumps(data).encode()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def decrypt_json_with_key(enc_obj: dict, key: bytes):
    """
    Decrypt a JSON-blob encrypted by encrypt_json_with_key.
    Raises ValueError if integrity check fails.
    """
    nonce = base64.b64decode(enc_obj["nonce"])
    tag = base64.b64decode(enc_obj["tag"])
    ciphertext = base64.b64decode(enc_obj["ciphertext"])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext.decode())
