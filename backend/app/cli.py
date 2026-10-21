import argparse
import secrets

from backend.app.main import connect_db, hash_api_key


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a one-time API key")
    parser.add_argument("owner")
    parser.add_argument("email", nargs="?")
    args = parser.parse_args()
    secret = f"sk_live_{secrets.token_urlsafe(32)}"
    with connect_db() as connection:
        connection.execute("INSERT INTO api_keys (owner, email, key_hash, key_prefix) VALUES (?, ?, ?, ?)",
                           (args.owner, args.email, hash_api_key(secret), secret[:15]))
    print("API key created. Copy it now; it cannot be retrieved later:")
    print(secret)


if __name__ == "__main__":
    main()
