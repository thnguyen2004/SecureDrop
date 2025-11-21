# SecureDrop
SecureDrop is a command-line tool that simulates a secure file-transfer system similar to Apple AirDrop.
The project is being developed in phases (milestones) to demonstrate practical cybersecurity and cryptography concepts including:

- Symmetric & asymmetric cryptography
- Digital certificates and mutual authentication
- Password security and non-repudiation
- Confidentiality and integrity protection

This implementation currently completes Milestone 1 — User Registration, providing a secure way to register new users while storing their credentials safely using salted password hashes.

🧩 Current Features (Milestone 1)

CLI-based registration flow (python main.py)
Automatic detection of existing users
JSON-based local storage (users.json)

Directory Structure:

SecureDrop/
│
├── main.py                # Entry-point for the CLI
├── user_registration.py   # Handles registration & secure password hashing
├── users.json             # Local user database (auto-created)
└── README.md              # Project documentation

🧱 Dependencies

Python ≥ 3.8:
Required for standard library features and type hints.	Pre-installed on most systems

🧰 Installation & Setup

1. Clone the repository:
- git clone https://github.com/<your-username>/SecureDrop.git
- cd SecureDrop

2. Install Python and virtual environment tools:
- sudo apt update
- sudo apt install python3 python3-pip python3-venv

3. Create and activate a virtual environment:
- python3 -m venv venv
- source venv/bin/activate

4. Install project dependencies:
- pip install -r requirements.txt
