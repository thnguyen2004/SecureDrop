from user_registration import register_user
from user_login import login_user
from utils import load_users
from contacts import add_contact_cli, load_contacts_for_user
from discovery import start_discovery, get_online_peers
from file_transfer import start_file_transfer_server, FileTransferProtocol
from pathlib import Path


def secure_drop_shell(session):
    # Start file transfer server
    file_protocol = start_file_transfer_server(session)
    
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
            peers = get_online_peers()
            contacts = load_contacts_for_user(session["email"])

            # Only show contacts where BOTH:
            # - Contact is confirmed
            # - Contact is currently online
            online_confirmed = {}

            for email, info in peers.items():
                if email in contacts and contacts[email].get("confirmed"):
                    online_confirmed[email] = info

            if not online_confirmed:
                print("No contacts online.\n")
            else:
                print("The following contacts are online:")
                for email, info in online_confirmed.items():
                    print(f" * {info['name']} <{email}> @ {info['ip']}")
                print()

        elif cmd == "send":
            # Milestone 5: Secure File Transfer
            peers = get_online_peers()
            contacts = load_contacts_for_user(session["email"])
            
            # Get online confirmed contacts
            online_confirmed = {}
            for email, info in peers.items():
                if email in contacts and contacts[email].get("confirmed"):
                    online_confirmed[email] = info
            
            if not online_confirmed:
                print("No contacts online to send to.\n")
                continue
            
            # Show available contacts
            print("\nOnline contacts:")
            contact_list = list(online_confirmed.items())
            for i, (email, info) in enumerate(contact_list, 1):
                print(f"{i}. {info['name']} <{email}> @ {info['ip']}")
            
            # Select contact
            try:
                choice = input("\nSelect contact number: ").strip()
                index = int(choice) - 1
                
                if index < 0 or index >= len(contact_list):
                    print("Invalid selection.\n")
                    continue
                
                peer_email, peer_info = contact_list[index]
            except ValueError:
                print("Invalid input.\n")
                continue
            
            # Get file path
            filepath_str = input("Enter file path to send: ").strip()
            filepath = Path(filepath_str)
            
            if not filepath.exists():
                print(f"File not found: {filepath}\n")
                continue
            
            # Send file
            print(f"\n Starting secure file transfer...")
            success = file_protocol.send_file(filepath, peer_email, peer_info['ip'])
            
            if success:
                print(f"\n File transfer completed successfully!\n")
            else:
                print(f"\n File transfer failed.\n")

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
        start_discovery(session)
        secure_drop_shell(session)


if __name__ == "__main__":
    main()