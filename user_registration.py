# This module handles user registration for SecureDrop
# It allows new users to register by providing their name, email, and password.
# User details are stored in a JSON file named users.json.
# Passwords are currently stored in plaintext (to be improved in future milestones).
# Future improvements will include password hashing and salting.

import json, os, base64, hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from getpass import getpass


# Load users from JSON file
def _load_users():

    # Load existing users from json file
    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            users = json.load(f)
    else:
        users = {}

    return users

# Check if any users are registered
def any_users_registered() -> bool:

    # Return True if users.json contains at least one user.
    users = _load_users()

    return len(users) > 0

# User Registration
def register_user():

    users = _load_users()

    name = input("Enter Full Name: ").strip()

    email = input("Enter Email Address: ").strip()
    if email in users:
        print("\nEmail already registered.")
        return

    # Hidden password input
    password = getpass("Enter Password: ")
    confirm = getpass("Re-enter Password: ")

    if password != confirm:
        print("\nPasswords do not match.")
        return

    print("\nPasswords Match.")

    # Hash + salt the password using PBKDF2
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200000
    )

    salt_b64 = base64.b64encode(salt).decode()
    hash_b64 = base64.b64encode(password_hash).decode()

    # Generate RSA keypair
    key = RSA.generate(2048)
    public_key = key.publickey().export_key().decode()
    private_key_bytes = key.export_key()

    # Encrypt the private key with AES-GCM using password-derived key
    aes_key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_key_bytes)

    private_key_encrypted_b64 = base64.b64encode(ciphertext).decode()
    nonce_b64 = base64.b64encode(cipher.nonce).decode()
    tag_b64 = base64.b64encode(tag).decode()

    # Save new user to json file
    users[email] = {
        "name": name,
        "salt": salt_b64,
        "password_hash": hash_b64,
        "public_key": public_key,
        "private_key_encrypted": private_key_encrypted_b64,
        "nonce": nonce_b64,
        "tag": tag_b64
    }

    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

    print("User Registered.")
    print("Exiting SecureDrop.")