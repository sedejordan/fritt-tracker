# tests/conftest.py
"""
conftest.py - Updated with complete test fixtures.
"""

import os
import sys
from pathlib import Path
import pytest
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch
import psycopg2

# Make sure the project root is on Python's import search path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Set test environment variables BEFORE importing app
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-not-used-in-production")
os.environ["DISABLE_RATE_LIMITING"] = "true"
os.environ["FLW_TEST_MODE"] = "true"
os.environ["RESEND_API_KEY"] = "test_resend_key"  # Mock email sending
os.environ["FLW_WEBHOOK_SECRET"] = "test_webhook_secret"
os.environ["TRIGGER_SECRET"] = "test_trigger_secret"
os.environ["ADMIN_EMAIL"] = "admin@test.com"

# Database setup
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
if not TEST_DATABASE_URL:
    raise RuntimeError(
        "TEST_DATABASE_URL is not set. Tests must run against a database "
        "that is NOT your production database."
    )
os.environ["DATABASE_URL"] = TEST_DATABASE_URL

# Import after env vars are set
import app as app_module
from database import init_db, get_db, put_db

# Initialize the test database
init_db()


@pytest.fixture
def app():
    """The Flask app, configured for testing."""
    app_module.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,  # Disable CSRF for tests
    )
    yield app_module.app


@pytest.fixture
def client(app):
    """A Flask test client."""
    return app.test_client()

@pytest.fixture(scope="function", autouse=False)  # Remove autouse
def clean_database():
    """Runs before every test. Empties all tables."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SET lock_timeout = '5s';")
        cursor.execute("""
            TRUNCATE TABLE documents, users, admin_users, flagged_users, 
            audit_log, user_activity_logs, contact_inquiries, business_inquiries,
            newsletter_subscribers RESTART IDENTITY CASCADE;
        """)
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    yield

@pytest.fixture
def test_user(client):
    """Create and return a test user (automatically verified)."""
    client.post(
        "/register",
        data={"email": "test@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = %s RETURNING id, email",
            ("test@example.com",)
        )
        user = cursor.fetchone()
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    return {"id": user[0], "email": user[1]}

@pytest.fixture
def test_admin_user(client):
    """Create and return a test admin user."""
    # Register
    client.post(
        "/register",
        data={"email": "admin@example.com", "password": "Admin123!@#"},
        follow_redirects=True
    )
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        # Verify the user
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = %s RETURNING id",
            ("admin@example.com",)
        )
        user_id = cursor.fetchone()[0]
        
        # Check if already an admin before inserting
        cursor.execute(
            "SELECT 1 FROM admin_users WHERE user_id = %s",
            (user_id,)
        )
        if not cursor.fetchone():
            # Make them an admin
            cursor.execute(
                "INSERT INTO admin_users (user_id) VALUES (%s)",
                (user_id,)
            )
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    return {"id": user_id, "email": "admin@example.com"}

@pytest.fixture
def logged_in_user(client, test_user):
    """Return a logged-in test user."""
    client.post(
        "/login",
        data={"email": "test@example.com", "password": "Test123!@#"},
        follow_redirects=True
    )
    return test_user

@pytest.fixture
def fresh_user(client):
    """Create a fresh user with a unique email."""
    import time
    unique_email = f"test_{int(time.time())}@example.com"
    
    client.post(
        "/register",
        data={"email": unique_email, "password": "Test123!@#"},
        follow_redirects=True
    )
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE email = %s RETURNING id, email",
            (unique_email,)
        )
        user = cursor.fetchone()
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    client.post(
        "/login",
        data={"email": unique_email, "password": "Test123!@#"},
        follow_redirects=True
    )
    
    return {"id": user[0], "email": user[1]}

# Add this debug test to conftest.py temporarily
@pytest.fixture
def logged_in_admin(client, test_admin_user):
    """Return a logged-in admin user."""
    response = client.post(
        "/login",
        data={"email": "admin@example.com", "password": "Admin123!@#"},
        follow_redirects=True
    )
    # Print the response to debug
    print(f"Login response status: {response.status_code}")
    print(f"Login response contains admin check: {b'Add Document' in response.data}")
    
    # Check if admin_users table has the user
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM admin_users WHERE user_id = %s",
            (test_admin_user["id"],)
        )
        admin_record = cursor.fetchone()
        print(f"Admin record in DB: {admin_record}")
        cursor.close()
    finally:
        put_db(conn)
    
    return test_admin_user

@pytest.fixture
def test_document(logged_in_user, client):
    """Create a test document and return its ID."""
    response = client.post(
        "/add",
        data={"title": "Test Document", "expiry_date": "2099-01-01"},
        follow_redirects=True
    )
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM documents WHERE user_id = %s AND title = 'Test Document'",
            (logged_in_user["id"],)
        )
        doc_id = cursor.fetchone()[0]
        cursor.close()
    finally:
        put_db(conn)
    
    return doc_id


@pytest.fixture
def mock_email():
    """Mock email sending so tests don't actually send emails."""
    with patch('app.requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        yield mock_post