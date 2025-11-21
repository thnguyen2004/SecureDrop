from getpass import getpass
from utils import (
    load_users,
    verify_password,
    decrypt_private_key
)

def login_user():
    users = load_users()

    email = input("Enter Email Address: ").strip()

    if email not in users:
        print("Email and Password Combination Invalid.\n")
        return None

    password = getpass("Enter Password: ")

    user = users[email]

    # Password check
    if not verify_password(password, user["salt"], user["password_hash"]):
        print("Email and Password Combination Invalid.\n")
        return None

    # Decrypt RSA private key (kept in memory only)
    private_key = decrypt_private_key(
        user["private_key_encrypted"],
        user["nonce"],
        user["tag"],
        password
    )

    print("Welcome to SecureDrop.")
    print("Type \"help\" For Commands.\n")

    # Session object stored in ram only
    return {
        "email": email,
        "name": user["name"],
        "public_key": user["public_key"],
        "private_key_bytes": private_key
    }
