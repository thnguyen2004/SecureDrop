from user_registration import register_user
from user_login import login_user
from utils import load_users
from contacts import add_contact_cli, load_contacts_for_user
from discovery import start_discovery, get_online_peers


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
            # Milestone 4 (partial): show online peers that are also confirmed contacts
            peers = get_online_peers()
            contacts = load_contacts_for_user(session["email"])  # <-- use email, not session

            online_confirmed = {}

            for email, peer_info in peers.items():
                # Only show if this email is in our contacts AND confirmed
                if email in contacts and contacts[email].get("confirmed"):
                    online_confirmed[email] = peer_info

            if not online_confirmed:
                print("No contacts online.\n")
            else:
                print("The following contacts are online:")
                for email, info in online_confirmed.items():
                    # Prefer our local contact name
                    name = contacts[email].get("name", info["name"])
                    print(f" * {name} <{email}> @ {info['ip']}")
                print()

        elif cmd == "exit":
            print("Exiting SecureDrop.\n")
            break

        else:
            print("Unknown Command. Type 'help' for options.\n")


def main():
    users = load_users()

    if len(users) == 0:
        print("No users are registered with this client.")
        choice = input("Do you want to register a new user (y/n)? ").strip().lower()
        if choice == "y":
            register_user()
        else:
            print("Exiting SecureDrop.")
        return

    # Login flow
    session = login_user()

    if session:
        # Start UDP discovery in the background (listener + broadcaster)
        start_discovery(session)
        # Enter interactive shell
        secure_drop_shell(session)


if __name__ == "__main__":
    main()
