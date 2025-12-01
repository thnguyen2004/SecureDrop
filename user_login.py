from getpass import getpass
from utils import (
    load_users,
    verify_password,
    decrypt_private_key,
    derive_session_key,
)

def login_user():
    users = load_users()

    while True:
        email = input("Enter Email Address: ").strip()

        if email not in users:
            print("Email and Password Combination Invalid.\n")
            continue

        password = getpass("Enter Password: ")

        user = users[email]

        # Password check
        if not verify_password(password, user["salt"], user["password_hash"]):
            print("Email and Password Combination Invalid.\n")
            continue

        # Decrypt RSA private key (kept in memory only)
        private_key = decrypt_private_key(
            user["private_key_encrypted"],
            user["nonce"],
            user["tag"],
            password
        )

        # Derive a session key for encrypting contacts, etc.
        session_key = derive_session_key(password)

        # Clear raw password from memory reference
        password = None

        print("Welcome to SecureDrop.")
        print("Type \"help\" For Commands.\n")

        # Session object stored in RAM only
        return {
            "email": email,
            "name": user["name"],
            "public_key": user["public_key"],
            "private_key_bytes": private_key,
            "session_key": session_key,   # <-- NEW
        }