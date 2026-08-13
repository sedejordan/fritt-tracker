#!/usr/bin/env python3
"""make_admin.py — run once to grant yourself admin access."""
import os
import sys
import psycopg2

DATABASE_URL = os.environ.get("DATABASE_URL")

def make_admin(email):
    conn = psycopg2.connect(DATABASE_URL)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        row = cursor.fetchone()
        if not row:
            print(f"❌ No user found with email {email}")
            return
        user_id = row[0]
        cursor.execute(
            "INSERT INTO admin_users (user_id) VALUES (%s) ON CONFLICT (user_id) DO NOTHING",
            (user_id,)
        )
        conn.commit()
        print(f"✅ {email} (id {user_id}) is now an admin")
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py you@example.com")
        sys.exit(1)
    make_admin(sys.argv[1])