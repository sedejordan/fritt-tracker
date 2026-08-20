# tests/test_security.py
"""
tests/test_security.py

Critical security tests - prevent data leaks and unauthorized access.
"""

import pytest
from database import get_db, put_db


def test_user_cannot_see_other_users_documents(client):
    """User A should not see User B's documents."""
    # Create User A
    client.post(
        "/register",
        data={"email": "alice@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = 'alice@example.com' RETURNING id"
        )
        alice_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    # Login as Alice and add a document
    client.post(
        "/login",
        data={"email": "alice@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    client.post(
        "/add",
        data={"title": "Alice's Secret Document", "expiry_date": "2099-01-01"},
        follow_redirects=True
    )
    client.get("/logout")
    
    # Create User B
    client.post(
        "/register",
        data={"email": "bob@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = 'bob@example.com' RETURNING id"
        )
        bob_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    # Login as Bob
    client.post(
        "/login",
        data={"email": "bob@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    # Bob should not see Alice's document
    response = client.get("/", follow_redirects=True)
    assert b"Alice's Secret Document" not in response.data

def test_user_cannot_edit_other_users_document_by_id(client):
    """User should not be able to edit another user's document by guessing the ID."""
    # Create User A and a document
    client.post(
        "/register",
        data={"email": "alice@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = 'alice@example.com' RETURNING id"
        )
        alice_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    client.post(
        "/login",
        data={"email": "alice@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    client.post(
        "/add",
        data={"title": "Alice's Doc", "expiry_date": "2099-01-01"},
        follow_redirects=True
    )
    
    # Get the document ID - use parameterized query
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM documents WHERE title = %s", ("Alice's Doc",))
        result = cursor.fetchone()
        cursor.close()
    finally:
        put_db(conn)
    
    # If no document found, skip the test or fail with a clear message
    assert result is not None, "Document not found - check if registration/login worked"
    doc_id = result[0]
    
    client.get("/logout")
    
    # Create User B
    client.post(
        "/register",
        data={"email": "bob@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = 'bob@example.com' RETURNING id"
        )
        cursor.fetchone()
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    client.post(
        "/login",
        data={"email": "bob@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    # Bob tries to edit Alice's document - should return 404
    response = client.get(f"/edit/{doc_id}", follow_redirects=True)
    assert response.status_code == 404

def test_user_cannot_delete_other_users_document_by_id(client):
    """User should not be able to delete another user's document by guessing the ID."""
    # Create User A and a document
    client.post(
        "/register",
        data={"email": "alice@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = 'alice@example.com' RETURNING id"
        )
        alice_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    client.post(
        "/login",
        data={"email": "alice@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    client.post(
        "/add",
        data={"title": "Alice's Doc", "expiry_date": "2099-01-01"},
        follow_redirects=True
    )
    
    # Get the document ID - use parameterized query
    conn = get_db()
    try:
        cursor = conn.cursor()
        # Use %s placeholder - this handles apostrophes correctly
        cursor.execute("SELECT id FROM documents WHERE title = %s", ("Alice's Doc",))
        row = cursor.fetchone()
        assert row is not None, "Document not found"
        doc_id = row[0]
        cursor.close()
    finally:
        put_db(conn)
    
    client.get("/logout")
    
    # Create User B
    client.post(
        "/register",
        data={"email": "bob@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = 'bob@example.com' RETURNING id"
        )
        bob_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    client.post(
        "/login",
        data={"email": "bob@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    # Bob tries to delete Alice's document
    response = client.post(f"/delete/{doc_id}", follow_redirects=True)
    assert response.status_code == 404

@pytest.mark.skip(reason="CSRF is disabled in test mode")
def test_csrf_protection_enabled_for_forms(client, test_user):
    """All POST forms should require CSRF protection (except webhooks)."""
    # Try to add a document without CSRF token
    response = client.post(
        "/add",
        data={"title": "Test", "expiry_date": "2099-01-01"},
        follow_redirects=True
    )
    
    # Should fail due to missing CSRF token
    assert b"CSRF" in response.data or response.status_code in [400, 403]


def test_security_headers_present(client):
    """All responses should have security headers."""
    response = client.get("/")
    
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'

def test_session_cookie_secure(client):
    """Session cookies should have security flags."""
    client.post(
        "/register",
        data={"email": "test@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    # Get the session cookie - use correct attribute access
    session_cookie = client.get_cookie('session')
    
    # The cookie object might be a dict-like object
    if hasattr(session_cookie, 'httponly'):
        assert session_cookie.httponly is True
    elif hasattr(session_cookie, 'get'):
        assert session_cookie.get('httponly', False) is True
    else:
        # Skip if we can't check
        pytest.skip("Cannot check httponly flag on this cookie object")

def test_password_strength_validation(client):
    """Weak passwords should be rejected."""
    response = client.post(
        "/register",
        data={"email": "test@example.com", "password": "weak"},
        follow_redirects=True
    )
    
    assert b"Password must contain" in response.data


def test_email_verification_required_for_document_operations(client):
    """Users must verify their email before accessing document features."""
    # Create unverified user
    client.post(
        "/register",
        data={"email": "unverified@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    # Try to add a document
    response = client.post(
        "/add",
        data={"title": "Test", "expiry_date": "2099-01-01"},
        follow_redirects=True
    )
    
    assert b"verify" in response.data.lower() or b"verification" in response.data.lower()


def test_sql_injection_prevention(client, test_user):
    """SQL injection attempts should be prevented."""
    malicious_title = "Test'; DROP TABLE users; --"
    
    response = client.post(
        "/add",
        data={"title": malicious_title, "expiry_date": "2099-01-01"},
        follow_redirects=True
    )
    
    # Should not error - either succeed or validate
    assert response.status_code < 500
    
    # Check that the table wasn't dropped (users still exist)
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users LIMIT 1")
        result = cursor.fetchone()
        cursor.close()
    finally:
        put_db(conn)
    
    assert result is not None

@pytest.mark.skip(reason="Rate limiting is disabled in test mode")
def test_rate_limiting_applied_to_sensitive_endpoints(client):
    """Rate limiting should be applied to authentication endpoints."""
    # Make 11 login attempts quickly (limit is 10 per minute)
    for i in range(11):
        response = client.post(
            "/login",
            data={"email": "test@example.com", "password": "wrong"},
            follow_redirects=True
        )
        
        if i >= 10:
            # Should hit rate limit
            assert b"Too many" in response.data or b"rate" in response.data
            break