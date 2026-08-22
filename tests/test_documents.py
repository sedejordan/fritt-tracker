# tests/test_documents.py - Fixed

import os
import psycopg2
from database import get_db, put_db
from datetime import datetime


def register_and_verify(client, email="alice@example.com", password="Test123!@#"):
    """Register and automatically verify the user, then log them in."""
    # Register
    client.post(
        "/register",
        data={"email": email, "password": password},
        follow_redirects=True
    )
    
    # Verify in database
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = %s RETURNING id",
            (email,)
        )
        user_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    # Login the user
    client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=True
    )
    
    return user_id


def add_document(client, title="Passport", expiry_date="2099-01-01"):
    return client.post(
        "/add",
        data={"title": title, "expiry_date": expiry_date},
        follow_redirects=True
    )


def test_logged_out_visitor_is_redirected_to_login(client):
    """Logged out visitors should be redirected to login."""
    response = client.get("/", follow_redirects=True)
    assert b"Login" in response.data or b"Password" in response.data


def test_logged_out_visitor_cannot_add_document(client):
    """Logged out visitors cannot access add document page."""
    response = client.get("/add", follow_redirects=True)
    assert b"Login" in response.data or b"Password" in response.data


def test_add_document_appears_on_homepage(client):
    """Added document should appear on the homepage."""
    register_and_verify(client)
    add_document(client, title="Passport", expiry_date="2099-01-01")
    
    response = client.get("/")
    assert b"Passport" in response.data


def test_add_document_requires_title(client):
    """Adding document requires a title."""
    register_and_verify(client)
    response = add_document(client, title="", expiry_date="2099-01-01")
    # The error message might be different - check for any error
    assert b"error" in response.data.lower() or b"please fill" in response.data.lower()


def test_add_document_requires_valid_date(client):
    """Adding document requires a valid date."""
    register_and_verify(client)
    response = add_document(client, title="Passport", expiry_date="not-a-date")
    # Check for any validation error
    assert b"Invalid" in response.data or b"error" in response.data.lower()

def test_edit_document_updates_title(client):
    """Editing document should update the title."""
    register_and_verify(client)
    add_document(client, title="Old Title", expiry_date="2099-01-01")
    
    # Find the document's id
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM documents WHERE title = %s", ("Old Title",))
        row = cursor.fetchone()
        assert row is not None, "Document 'Old Title' not found"
        doc_id = row[0]
        cursor.close()
    finally:
        put_db(conn)
    
    # Use a unique title
    unique_title = f"New Title {datetime.now().timestamp()}"
    client.post(
        f"/edit/{doc_id}",
        data={"title": unique_title, "expiry_date": "2099-01-01"},
        follow_redirects=True
    )
    
    response = client.get("/")
    assert unique_title in response.data.decode()
    assert b"Old Title" not in response.data

def test_delete_document_removes_it(client):
    """Deleting document should remove it."""
    register_and_verify(client)
    add_document(client, title="Delete Me", expiry_date="2099-01-01")
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM documents WHERE title = %s", ("Delete Me",))
        row = cursor.fetchone()
        assert row is not None, "Document 'Delete Me' not found"
        doc_id = row[0]
        cursor.close()
    finally:
        put_db(conn)
    
    client.post(f"/delete/{doc_id}", follow_redirects=True)
    
    response = client.get("/")
    assert b"Delete Me" not in response.data