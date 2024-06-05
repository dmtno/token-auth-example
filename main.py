import datetime
import sqlite3
import bcrypt
import jwt

# Constants for JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect("users.db")
c = conn.cursor()


def main():
    """
    Main function to handle user registration, token generation, and token verification.
    """
    try:
        # Create users table if it doesn't exist
        c.execute(
            """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
        )
        conn.commit()

        # Infinite loop to handle user actions
        while True:
            action = input(
                "Enter 'ru' to register user, 'gt' to get token, 'vt' to verify token, 'exit' to exit: "
            )
            if action == "ru":
                username = input("Username: ")
                password = input("Password: ")
                register_user(username, password)
            elif action == "gt":
                username = input("Username: ")
                password = input("Password: ")
                token = get_token(username, password)
                print("Token: ", token)
            elif action == "vt":
                token = input("Token: ")
                verify_token(token)
            elif action == "exit":
                break
            else:
                print("Invalid action! Please try again.")
    finally:
        # Close the connection when done
        conn.close()


def register_user(username, password):
    """
    Registers a new user with the given username and password.

    Args:
        username (str): The username for the new user.
        password (str): The password for the new user.
    """
    try:
        # Hash the password
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        )
        # Insert the new user into the users table
        c.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
    except Exception as e:
        print("Error:", e)


def get_token(username, password):
    """
    Generates a JWT token for the user if the username and password are correct.

    Args:
        username (str): The username of the user.
        password (str): The password of the user.

    Returns:
        str: The generated JWT token if authentication is successful, None otherwise.
    """
    # Fetch user from the database
    c.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    )
    user = c.fetchone()

    if user:
        password_hash = user[1]
        # Check if the provided password matches the stored password hash
        if bcrypt.checkpw(password.encode("utf-8"), password_hash):
            payload = {
                "sub": user[0],  # User ID
                "iat": datetime.datetime.utcnow(),  # Issued at time
                "exp": datetime.datetime.utcnow()
                + datetime.timedelta(seconds=30),  # Expiration time
            }
            # Encode and return the JWT token
            return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return None


def verify_token(token):
    """
    Verifies the given JWT token.

    Args:
        token (str): The JWT token to verify.
    """
    try:
        # Decode and print the token payload
        print(jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]))
    except Exception as e:
        print("Invalid token:", e)


if __name__ == "__main__":
    main()
