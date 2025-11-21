from getpass import getpass
from utils import (
    load_users,
    save_users,
    hash_password,
    generate_rsa_keypair,
    encrypt_private_key
)

def register_user():
    users = load_users()

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

    # Hash + salt
    salt_b64, hash_b64 = hash_password(password)

    # RSA keys
    public_key, private_key_bytes = generate_rsa_keypair()

    # Encrypt private key
    encrypted_b64, nonce_b64, tag_b64 = encrypt_private_key(private_key_bytes, password)

    # Store user in memory
    users[email] = {
        "name": name,
        "salt": salt_b64,
        "password_hash": hash_b64,
        "public_key": public_key,
        "private_key_encrypted": encrypted_b64,
        "nonce": nonce_b64,
        "tag": tag_b64
    }

    # Save to users.json
    save_users(users)

    print("User Registered.")
    print("Exiting SecureDrop.\n")