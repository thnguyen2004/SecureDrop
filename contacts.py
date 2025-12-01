# contacts.py

import json
import os
from utils import encrypt_json_with_key, decrypt_json_with_key

CONTACTS_FILE = "contacts.json"


def _load_contacts_file() -> dict:
    """Load the raw (encrypted) contacts file: owner_email -> encrypted blob."""
    if os.path.exists(CONTACTS_FILE):
        try:
            if os.path.getsize(CONTACTS_FILE) == 0:
                return {}
            with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}


def _save_contacts_file(all_contacts: dict) -> None:
    """Save the raw (encrypted) contacts file."""
    with open(CONTACTS_FILE, "w", encoding="utf-8") as f:
        json.dump(all_contacts, f, indent=4)


def load_contacts_for_session(session: dict) -> dict:
    """
    Decrypt and return the logged-in user's contact dict.
    Returns {} if none exist yet.
    """
    owner_email = session["email"]
    key = session["session_key"]

    all_contacts = _load_contacts_file()
    enc_blob = all_contacts.get(owner_email)

    if not enc_blob:
        return {}

    try:
        return decrypt_json_with_key(enc_blob, key)
    except Exception:
        # Tampering or wrong key
        print("Warning: Failed to decrypt contacts (possible tampering or key mismatch).")
        return {}  # Safe fallback; you could also choose to abort.


def save_contacts_for_session(session: dict, contacts_dict: dict) -> None:
    """
    Encrypt and save the logged-in user's contact dict.
    """
    owner_email = session["email"]
    key = session["session_key"]

    all_contacts = _load_contacts_file()
    enc_blob = encrypt_json_with_key(contacts_dict, key)

    all_contacts[owner_email] = enc_blob
    _save_contacts_file(all_contacts)


def add_contact_cli(owner_session: dict) -> None:
    """
    CLI helper bound to the logged-in user session.
    """
    contact_name = input("Enter Full Name: ").strip()
    contact_email = input("Enter Email Address: ").strip()

    if not contact_name or not contact_email:
        print("Name and email are required.\n")
        return

    contacts = load_contacts_for_session(owner_session)
    contacts[contact_email] = {
        "name": contact_name,
        "email": contact_email,
    }

    save_contacts_for_session(owner_session, contacts)
    print("Contact Added.")


def list_contacts_cli(owner_session: dict) -> None:
    """
    Decrypt and print contacts for the logged-in user.
    """
    contacts = load_contacts_for_session(owner_session)

    if not contacts:
        print("No contacts found.\n")
        return

    print("The following contacts are online:")
    for email, info in contacts.items():
        print(f" * {info['name']} <{email}>")
    print()
