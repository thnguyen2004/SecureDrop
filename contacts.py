# contacts.py

import json
import os

CONTACTS_FILE = "contacts.json"


def load_all_contacts() -> dict:
    """Load the entire contacts database (dict of dicts)."""
    if os.path.exists(CONTACTS_FILE):
        try:
            if os.path.getsize(CONTACTS_FILE) == 0:
                return {}
            with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}


def save_all_contacts(all_contacts: dict) -> None:
    """Save the entire contacts database."""
    with open(CONTACTS_FILE, "w", encoding="utf-8") as f:
        json.dump(all_contacts, f, indent=4)


def add_contact(owner_email: str, contact_name: str, contact_email: str) -> None:
    """
    Add or overwrite a contact for the given owner.
    """
    all_contacts = load_all_contacts()

    # Get this user's contact list or create a new one
    owner_book = all_contacts.get(owner_email, {})

    owner_book[contact_email] = {
        "name": contact_name,
        "email": contact_email
    }

    all_contacts[owner_email] = owner_book
    save_all_contacts(all_contacts)


def list_contacts_for_owner(owner_email: str) -> dict:
    """Return a dict of contacts for a given owner email."""
    all_contacts = load_all_contacts()
    return all_contacts.get(owner_email, {})


def add_contact_cli(owner_email: str) -> None:
    """
    CLI helper:
      - prompts for Full Name and Email Address of the contact
      - adds/overwrites contact for the logged-in user
    """
    print("\nAdd new contact")
    contact_name = input("Enter Full Name: ").strip()
    contact_email = input("Enter Email Address: ").strip()

    if not contact_name or not contact_email:
        print("Name and email are required.\n")
        return

    add_contact(owner_email, contact_name, contact_email)
    print("Contact Added.\n")
