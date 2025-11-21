# Main application file for SecureDrop
# It manages user registration and login flow.
# It uses the user_registration module for handling registrations.
# Future milestones will include user login functionality.

from user_registration import any_users_registered, register_user


def main():

    print()  # clean starting line

    # If no users exist, trigger registration flow
    if not any_users_registered():
        print("No users are registered with this client.")
        choice = input("Do you want to register a new user (y/n)? ").strip().lower()
        if choice == "y":
            register_user()
        else:
            print("Exiting SecureDrop.")
            return
    else:
        # Milestone 2 will go here (login flow)
        print("Existing users detected.")
        print("Next step (Milestone 2): activate login flow here.")
        # from user_login import login_user
        # login_user()

if __name__ == "__main__":
    main()