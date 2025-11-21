from user_registration import register_user
from user_login import login_user
from utils import load_users
from contacts import add_contact_cli, list_contacts_for_owner

def secure_drop_shell(session):
    while True:
        cmd = input("secure_drop> ").strip().lower()

        if cmd == "help":
            print("\nAvailable Commands:")
            print(" add   – Add a new contact (Milestone 3)")
            print(" list  – List available contacts (Milestone 3/4)")
            print(" send  – Send a file (Milestone 4/5)")
            print(" exit  – Exit SecureDrop\n")

        elif cmd == "add":
            # Milestone 3: Add contact for the logged-in user
            owner_email = session["email"]
            add_contact_cli(owner_email)

        elif cmd == "list":
            # Milestone 3: List this user's contacts (local view)
            owner_email = session["email"]
            contacts = list_contacts_for_owner(owner_email)

            if not contacts:
                print("\nNo contacts found for this user.\n")
            else:
                print("\nYour contacts:")
                for email, info in contacts.items():
                    print(f" * {info['name']} <{email}>")
                print()

        elif cmd == "exit":
            print("Exiting SecureDrop.\n")
            break

        else:
            print("Unknown Command. Type 'help' for options.\n")

def main():
    users = load_users()

    if len(users) == 0:
        print("No users are registered with this client.\n")
        choice = input("Do you want to register a new user (y/n)? ").strip().lower()
        if choice == "y":
            register_user()
        else:
            print("Exiting SecureDrop.")
        return

    # Login flow
    session = login_user()

    if session is not None:
        secure_drop_shell(session)


if __name__ == "__main__":
    main()