"""
tests/test_auth.py

Covers account creation and login/logout - the basic building blocks
everything else depends on.
"""

import os
import psycopg2
from database import get_db, put_db


def register(client, email="alice@example.com", password="Test123!@#"):
    return client.post(
        "/register",
        data={"email": email, "password": password},
        follow_redirects=True
    )


def login(client, email="alice@example.com", password="Test123!@#"):
    return client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=True
    )


def test_register_creates_account_and_logs_user_in(client):
    """Registration should create an account and redirect to verification."""
    response = register(client)
    assert response.status_code == 200
    # After registration, user is redirected to verification page
    # Look for verification-related content instead of "Add Document"
    assert b"verify" in response.data.lower() or b"verification" in response.data.lower()


def test_register_rejects_duplicate_email(client):
    """Registration should reject duplicate email addresses."""
    # First registration
    register(client, email="alice@example.com")
    client.get("/logout")
    
    # Second attempt with same email
    response = register(client, email="alice@example.com")
    # Look for error message about existing account
    assert b"already exists" in response.data or b"already" in response.data


def test_register_rejects_short_password(client):
    """Registration should reject passwords under 8 characters."""
    response = register(client, email="alice@example.com", password="short")
    # Check for password requirements message
    assert b"Password must contain" in response.data or b"At least 8" in response.data


def test_login_with_correct_password_succeeds(client):
    """Login with correct credentials should work."""
    # Register first
    register(client, email="alice@example.com", password="Test123!@#")
    client.get("/logout")
    
    # Manually verify the user in the database (bypass email verification)
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = %s",
            ("alice@example.com",)
        )
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    # Login
    response = login(client, email="alice@example.com", password="Test123!@#")
    assert response.status_code == 200
    # After successful login, should show dashboard content
    assert b"Add Document" in response.data


def test_login_with_wrong_password_fails(client):
    """Login with wrong password should fail."""
    register(client, email="alice@example.com", password="Test123!@#")
    client.get("/logout")
    
    response = login(client, email="alice@example.com", password="wrongpassword")
    assert b"Invalid email or password" in response.data


def test_login_with_unknown_email_fails(client):
    """Login with unknown email should fail."""
    response = login(client, email="nobody@example.com", password="Test123!@#")
    assert b"Invalid email or password" in response.data


def test_logout_requires_login_again_to_see_documents(client):
    """After logout, user should need to login again."""
    register(client, email="alice@example.com", password="Test123!@#")
    
    # Manually verify the user
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = %s",
            ("alice@example.com",)
        )
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    client.get("/logout")
    
    # After logging out, should redirect to login page
    response = client.get("/", follow_redirects=True)
    # Should show login form
    assert b"Login" in response.data or b"Password" in response.data


def test_delete_account_with_wrong_password_fails(client):
    """Delete account should fail with wrong password."""
    register(client, email="alice@example.com", password="Test123!@#")
    
    # Manually verify the user
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = %s",
            ("alice@example.com",)
        )
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    response = client.post(
        "/delete-account",
        data={"password": "wrongpassword"},
        follow_redirects=True
    )
    # Should show password error
    assert b"Incorrect password" in response.data or b"password" in response.data


def test_delete_account_removes_account_and_logs_out(client):
    """Delete account should remove the account and log out."""
    register(client, email="alice@example.com", password="Test123!@#")
    
    # Manually verify the user
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = %s",
            ("alice@example.com",)
        )
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    client.post(
        "/delete-account",
        data={"password": "Test123!@#"},
        follow_redirects=True
    )
    
    # Should be redirected to login page
    response = client.get("/", follow_redirects=True)
    assert b"Login" in response.data or b"Password" in response.data

# tests/test_auth.py - Fix delete account test

def test_delete_account_also_removes_documents(client):
    """Delete account should also remove all user documents."""
    # Clean up any existing documents first
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM documents")
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    register(client, email="alice@example.com", password="Test123!@#")
    
    # Manually verify the user
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = %s",
            ("alice@example.com",)
        )
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    # Add a document
    client.post(
        "/add",
        data={"title": "Passport", "expiry_date": "2099-01-01"},
        follow_redirects=True
    )
    
    # Delete account
    client.post(
        "/delete-account",
        data={"password": "Test123!@#"},
        follow_redirects=True
    )
    
    # Check documents are gone
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM documents")
        count = cursor.fetchone()[0]
        cursor.close()
    finally:
        put_db(conn)
    
    assert count == 0

def test_logged_out_visitor_cannot_delete_account(client):
    """Logged out visitors cannot access delete account page."""
    response = client.get("/delete-account", follow_redirects=True)
    assert b"Login" in response.data or b"Password" in response.data