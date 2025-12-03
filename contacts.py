# contacts.py

import json
import os

CONTACTS_FILE = "contacts.json"


# Load entire contacts.json or return empty structure
def _load_all_contacts():
    if os.path.exists(CONTACTS_FILE) and os.path.getsize(CONTACTS_FILE) > 0:
        try:
            with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}


# Save entire contacts.json
def _save_all_contacts(all_data):
    with open(CONTACTS_FILE, "w", encoding="utf-8") as f:
        json.dump(all_data, f, indent=4)


# Get the logged-in user's contact list, or empty if none exist
def load_contacts_for_user(email: str) -> dict:
    all_data = _load_all_contacts()
    user_entry = all_data.get(email, {})
    return user_entry.get("contacts", {})


# Save the logged-in user's contacts
def save_contacts_for_user(email: str, name: str, contacts: dict):
    all_data = _load_all_contacts()

    all_data[email] = {
        "name": name,
        "contacts": contacts
    }

    _save_all_contacts(all_data)


# Add a contact (user A adds user B)
def add_contact_cli(session: dict):
    owner_email = session["email"]
    owner_name = session["name"]

    contact_name = input("Enter Full Name: ").strip()
    contact_email = input("Enter Email Address: ").strip()

    if not contact_name or not contact_email:
        print("Name and email are required.\n")
        return

    # Load all existing contacts
    contacts_owner = load_contacts_for_user(owner_email)
    contacts_other = load_contacts_for_user(contact_email)

    # Add pending contact for owner
    contacts_owner[contact_email] = {
        "name": contact_name,
        "confirmed": False
    }

    # If the other user also added this user -> confirm both sides
    if owner_email in contacts_other:
        contacts_owner[contact_email]["confirmed"] = True
        contacts_other[owner_email]["confirmed"] = True

        # Save the other user's updated entry
        save_contacts_for_user(
            contact_email,
            contacts_other.get("name", ""),
            contacts_other
        )

    # Save owner's updated contacts
    save_contacts_for_user(owner_email, owner_name, contacts_owner)

    print("Contact Added.")
