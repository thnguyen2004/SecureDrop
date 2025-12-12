import os
import json
import base64
import hashlib
import hmac
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# ***** users.py *****

# Load users.json or return empty dictionary
def load_users():
    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            return json.load(f)
    return {}

# Write updated users to users.json
def save_users(users: dict):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

# Hash a password using PBKDF2-HMAC-SHA256 (salt generated if not provided)
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

# Verify a given password against stored salt + PBKDF2 hash
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

# Generate an RSA-2048 keypair (public key string + private key bytes)
def generate_rsa_keypair():
    key = RSA.generate(2048)
    public_key = key.publickey().export_key().decode()
    private_key_bytes = key.export_key()
    return public_key, private_key_bytes

# Encrypt RSA private key using AES-GCM with a password-derived key
def encrypt_private_key(private_key_bytes: bytes, password: str):
    aes_key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_key_bytes)

    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(cipher.nonce).decode(),
        base64.b64encode(tag).decode()
    )

# Decrypt AES-GCM encrypted RSA private key
def decrypt_private_key(ciphertext_b64: str, nonce_b64: str, tag_b64: str, password: str):
    aes_key = hashlib.sha256(password.encode()).digest()

    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ***** discovery.py *****

# Encrypt using a public key (RSA OAEP)
def rsa_encrypt_with_public_key(public_key_bytes, data: bytes) -> bytes:
    key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(data)

# Decrypt using our private key
def rsa_decrypt_with_private_key(private_key_bytes, encrypted: bytes) -> bytes:
    key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(encrypted)

def derive_hmac_key(private_key_bytes: bytes) -> bytes:
    """
    Derive a stable HMAC key from the user's private key.
    """
    return hashlib.sha256(private_key_bytes).digest()


def compute_hmac(data: bytes, key: bytes) -> str:
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(mac).decode()


def verify_hmac(data: bytes, key: bytes, expected_b64: str) -> bool:
    expected = base64.b64decode(expected_b64)
    actual = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(actual, expected)