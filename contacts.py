# contacts.py

import json
import os

from utils import derive_hmac_key, compute_hmac, verify_hmac

CONTACTS_FILE = "contacts.json"
HMAC_FILE = "contacts.json.hmac"

# Load entire contacts.json or return empty structure
def _load_all_contacts(session: dict):
    if not os.path.exists(CONTACTS_FILE):
        return {}

    with open(CONTACTS_FILE, "rb") as f:
        data = f.read()

    if not os.path.exists(HMAC_FILE):
        raise RuntimeError("Contacts integrity file missing.")

    with open(HMAC_FILE, "r", encoding="utf-8") as f:
        stored_hmac = f.read().strip()

    key = derive_hmac_key(session["private_key_bytes"])

    if not verify_hmac(data, key, stored_hmac):
        raise RuntimeError("Contacts file has been tampered with.")

    return json.loads(data.decode("utf-8"))


# Save entire contacts.json
def _save_all_contacts(all_data: dict, session: dict):
    data = json.dumps(all_data, indent=4).encode("utf-8")

    with open(CONTACTS_FILE, "wb") as f:
        f.write(data)

    key = derive_hmac_key(session["private_key_bytes"])
    mac = compute_hmac(data, key)

    with open(HMAC_FILE, "w", encoding="utf-8") as f:
        f.write(mac)


# Get the logged-in user's contact list, or empty if none exist
def load_contacts_for_user(session: dict) -> dict:
    all_data = _load_all_contacts(session)
    return all_data.get(session["email"], {}).get("contacts", {})


def save_contacts_for_user(session: dict, contacts: dict):
    all_data = _load_all_contacts(session)

    all_data[session["email"]] = {
        "name": session["name"],
        "contacts": contacts
    }

    _save_all_contacts(all_data, session)


# Add a contact (user A adds user B)
def add_contact_cli(session: dict):
    owner_email = session["email"]

    contact_name = input("Enter Full Name: ").strip()
    contact_email = input("Enter Email Address: ").strip()

    contacts_owner = load_contacts_for_user(session)
    contacts_other = {}

    try:
        contacts_other = _load_all_contacts(session).get(contact_email, {}).get("contacts", {})
    except RuntimeError:
        pass

    contacts_owner[contact_email] = {
        "name": contact_name,
        "confirmed": False
    }

    if owner_email in contacts_other:
        contacts_owner[contact_email]["confirmed"] = True
        contacts_other[owner_email]["confirmed"] = True

        save_contacts_for_user(
            {"email": contact_email, "name": contact_name, "private_key_bytes": session["private_key_bytes"]},
            contacts_other
        )

    save_contacts_for_user(session, contacts_owner)

    print("Contact Added.")
