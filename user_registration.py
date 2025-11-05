import json, os

# Load users from JSON file
def _load_users():

    # Load existing users from json file
    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            users = json.load(f)
    else:
        users = {}

    return users

# Check if any users are registered
def any_users_registered() -> bool:

    # Return True if users.json contains at least one user.
    users = _load_users()

    return len(users) > 0

# User Registration
def register_user():

    users = _load_users()

    name = input("Enter your Full Name: ").strip()

    # Get user inputs (email and password)
    email = input("Enter your email: ").strip() # Trim whitespace
    if email in users:
        print("Email already registered!")
        return
    
    password = input("Enter your password: ").strip()
    confirm_password = input("Confirm your password: ").strip()  
    if password != confirm_password:
        print("Passwords do not match!")
        return
    
    # Save new user to json file
    users[email] = {"name": name, "password": password} # Store user details
    with open("users.json", "w") as f: # Open file for writing
        json.dump(users, f, indent=4) # write with indentation for readability

    print("Registration successful!")