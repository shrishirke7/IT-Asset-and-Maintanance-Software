import getpass
import json
import os

import psycopg
from werkzeug.security import generate_password_hash


def main():
    username = getpass.getpass("Administrator username: ").strip()
    password = getpass.getpass("New password (hidden): ")
    confirmation = getpass.getpass("Confirm new password (hidden): ")
    if len(password) < 10 or len(password) > 1024:
        raise SystemExit("Password must be between 10 and 1024 characters.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    with psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=8) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE")
            row = cur.fetchone()
            users = row[0] if row else []
            account = next(
                (user for user in users
                 if str(user.get("username", "")).casefold() == username.casefold()
                 and user.get("role") == "Administrator"
                 and user.get("enabled", True)),
                None,
            )
            if not account:
                raise SystemExit("Enabled administrator account not found.")
            account["password_hash"] = generate_password_hash(password)
            account["auth_version"] = int(account.get("auth_version", 0) or 0) + 1
            cur.execute(
                "UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'",
                (json.dumps(users),),
            )
    print("Administrator password reset complete.")


if __name__ == "__main__":
    main()
