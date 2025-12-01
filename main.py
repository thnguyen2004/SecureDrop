from user_registration import register_user
from user_login import login_user
from utils import load_users
from contacts import add_contact_cli, list_contacts_cli


def secure_drop_shell(session):
    while True:
        cmd = input("secure_drop> ").strip().lower()

        if cmd == "help":
            print(' "add"   -> Add a new contact')
            print(' "list"  -> List all online contacts')
            print(' "send"  -> Transfer file to contact')
            print(' "exit"  -> Exit SecureDrop')

        elif cmd == "add":
            # Milestone 3: Add contact for the logged-in user
            add_contact_cli(session)

        elif cmd == "list":
            # Milestone 3: List this user's contacts (local view)
            list_contacts_cli(session)

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