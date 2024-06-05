# Token-Based Authentication Example

This is a simple Python project demonstrating token-based authentication using JWT (JSON Web Tokens). The project includes user registration, token generation, and token verification functionalities.

## Features

- **User Registration:** Register a new user with a username and password.
- **Token Generation:** Generate a JWT token for a registered user.
- **Token Verification:** Verify the validity of a JWT token.

## Technologies Used

- Python
- SQLite
- Bcrypt
- PyJWT

## Setup and Usage

### Prerequisites

- Python 3.x

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/dmtno/token-auth-example.git
    cd token-auth-example
    ```

2. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

### Running the Project

1. Execute the main script:

    ```bash
    python main.py
    ```

2. Follow the prompts to register users, generate tokens, and verify tokens.

### User Actions

- **Register User (`ru`):**
  - Enter `ru` when prompted.
  - Provide a username and password to register a new user.

- **Get Token (`gt`):**
  - Enter `gt` when prompted.
  - Provide the registered username and password to receive a JWT token.

- **Verify Token (`vt`):**
  - Enter `vt` when prompted.
  - Provide the JWT token to verify its validity.

## Code Overview

- `main.py`:
  - The main script that handles user input and performs actions like user registration, token generation, and token verification.
  - Utilizes SQLite for storing user information and bcrypt for hashing passwords.
  - Uses PyJWT for encoding and decoding JWT tokens.

### Example Usage

```bash
Enter 'ru' to register user, 'gt' to get token, 'vt' to verify token: ru
Username: exampleuser
Password: examplepassword
User registered successfully!

Enter 'ru' to register user, 'gt' to get token, 'vt' to verify token: gt
Username: exampleuser
Password: examplepassword
Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

Enter 'ru' to register user, 'gt' to get token, 'vt' to verify token: vt
Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Token is valid: {'sub': 1, 'iat': 1659876543, 'exp': 1659876573}

