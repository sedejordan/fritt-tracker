"""
database.py

Sets up the database tables for Fritt Tracker.

This project used to use SQLite (a database stored in a single file on
disk). We've switched to PostgreSQL because SQLite's file gets wiped
every time Render redeploys or restarts the app - PostgreSQL runs as
its own persistent service, so the data survives deploys.

Connection details come from the DATABASE_URL environment variable,
which Render provides automatically once you create a PostgreSQL
database and link it to this web service. Locally, you'd set this
yourself (see the README for how to point it at a local Postgres
install, or just develop against the same Render database).
"""

# =============================================================================
# IMPORTS
# =============================================================================
import os
import secrets
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import time

import psycopg2
from psycopg2 import pool
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from psycopg2 import OperationalError, InterfaceError

# =============================================================================
# DATABASE CONNECTION POOL
# =============================================================================
# Connection pool manages database connections efficiently.
# Instead of opening/closing a connection for every request, we reuse
# connections from the pool. This is faster and prevents connection exhaustion.
#
# SimpleConnectionPool: min 1, max 5 connections.
# - min=1: Always keep at least one connection ready
# - max=5: Maximum 5 concurrent connections
# 
# If you have more than 5 concurrent users, they'll wait for a connection
# to become available. The free tier of Render typically runs 1-2 workers,
# so 5 connections is usually enough.

db_pool = None

# =============================================================================
# DATABASE CONNECTION POOL
# =============================================================================
# NeonDB Free Tier connection limits:
# - Max connections: 20
# - Idle timeout: ~30-60 seconds
# - Connection pooler available on port 5432
#
# We use min=1, max=5 to stay well within the 20-connection limit
# while still handling multiple concurrent requests.
#
# If you enable NeonDB's connection pooler (port 5432 with ?pool_mode=transaction),
# you can safely increase max connections to 10-15.

db_pool = None

def init_pool():
    """Initialize the database connection pool."""
    global db_pool
    if db_pool is None:
        # NeonDB free tier: 20 max connections, so 5 is conservative
        db_pool = psycopg2.pool.SimpleConnectionPool(
            1, 5,  # min 1, max 5 for NeonDB free tier
            dsn=os.environ.get("DATABASE_URL")
        )
        print(f"✅ Database connection pool initialized (max 5 connections) - Optimized for NeonDB")
        
# =============================================================================
# CONNECTION HEALTH CHECK
# =============================================================================

def _is_connection_alive(conn):
    """
    Check if a database connection is still alive.
    
    Returns True if the connection is valid, False if it's dead.
    This prevents handing out stale connections that have been closed
    by the database server (e.g., after Render PostgreSQL hibernates).
    """
    if conn is None:
        return False
    try:
        # Try a simple query to test the connection
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        return True
    except Exception as e:
        # Any exception means the connection is dead
        print(f"⚠️ Connection health check failed: {e}")
        try:
            conn.close()
        except:
            pass
        return False

def _get_valid_connection(max_attempts=3, delay=0.5):
    """
    Get a valid connection from the pool with retry logic.
    
    Args:
        max_attempts: Maximum number of connection attempts
        delay: Seconds to wait between attempts (exponential backoff)
    
    Returns:
        A valid database connection
    
    Raises:
        Exception: If unable to get a valid connection after max_attempts
    """
    if db_pool is None:
        init_pool()
    
    last_error = None
    
    for attempt in range(max_attempts):
        try:
            # Get a connection from the pool
            conn = db_pool.getconn()
            
            # Reset any aborted transaction
            try:
                conn.rollback()
            except:
                pass
            
            # Health check - ensure connection is alive
            if _is_connection_alive(conn):
                return conn
            else:
                # Connection is dead - discard it
                print(f"⚠️ Got dead connection from pool, attempt {attempt + 1}/{max_attempts}")
                try:
                    db_pool.putconn(conn, close=True)  # Close it permanently
                except:
                    pass
                
                # If the pool is exhausted, reset it
                if attempt < max_attempts - 1:
                    time.sleep(delay * (attempt + 1))  # Exponential backoff
                    if attempt == max_attempts - 2:
                        # On last retry, try resetting the pool
                        try:
                            db_pool.closeall()
                            init_pool()
                            print("🔄 Reset connection pool")
                        except:
                            pass
                continue
                
        except Exception as e:
            last_error = e
            print(f"⚠️ Error getting DB connection (attempt {attempt + 1}/{max_attempts}): {e}")
            
            if attempt < max_attempts - 1:
                time.sleep(delay * (attempt + 1))
                # Try to reset the pool if we're getting errors
                try:
                    db_pool.closeall()
                    init_pool()
                    print("🔄 Reset connection pool")
                except:
                    pass
            continue
    
    # If we get here, all attempts failed
    error_msg = f"Failed to get a valid database connection after {max_attempts} attempts"
    if last_error:
        error_msg += f": {last_error}"
    raise Exception(error_msg)

# =============================================================================
# CONNECTION MANAGEMENT
# =============================================================================

def get_db():
    """
    Get a validated connection from the pool.
    
    Usage:
        conn = get_db()
        try:
            cursor = conn.cursor()
            # ... do database work ...
        finally:
            put_db(conn)  # ALWAYS return the connection!
    
    This function automatically:
    - Checks if the connection is alive
    - Retries with exponential backoff if the pool is exhausted
    - Replaces dead connections with fresh ones
    - Handles Render PostgreSQL hibernation gracefully
    """
    return _get_valid_connection()


def put_db(conn):
    """
    Return a connection to the pool.
    
    IMPORTANT: Always call this in a finally block to prevent
    connection leaks. A connection leak happens when you get a
    connection but never return it - eventually the pool runs out
    of connections and the app freezes.
    
    Example:
        conn = get_db()
        try:
            cursor = conn.cursor()
            # ... do work ...
        finally:
            put_db(conn)  # <-- ALWAYS do this
    """
    if db_pool is not None and conn is not None:
        # Reset any pending transaction before returning to pool
        try:
            conn.rollback()
        except:
            pass
        db_pool.putconn(conn)


@contextmanager
def get_connection():
    """
    Get a validated connection from the pool with context manager.
    
    Usage:
        with get_connection() as conn:
            cursor = conn.cursor()
            # ... do database work ...
        # Connection automatically returned when context exits
    
    This is the recommended way to use connections - it guarantees
    the connection is always returned, even if an exception occurs.
    """
    conn = get_db()  # Now uses the retry logic
    try:
        yield conn
    finally:
        try:
            conn.rollback()
        except:
            pass
        put_db(conn)


@contextmanager
def get_db_cursor():
    """
    Context manager for database connections with cursor.
    
    Usage:
        with get_db_cursor() as cursor:
            cursor.execute("SELECT * FROM users")
            results = cursor.fetchall()
        # Connection is committed (or rolled back on error)
        # and returned to the pool automatically
    
    This is the most convenient way to use the database.
    It handles:
    - Getting a connection with retry logic
    - Creating a cursor
    - Committing on success
    - Rolling back on error
    - Closing the cursor
    - Returning the connection
    """
    conn = get_db()  # Now uses the retry logic
    try:
        cursor = conn.cursor()
        yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        put_db(conn)


@contextmanager
def get_db_cursor_manual():
    """
    Context manager that returns BOTH connection and cursor.
    
    Usage:
        with get_db_cursor_manual() as (conn, cursor):
            cursor.execute("SELECT * FROM users")
            # You have access to conn for special operations
        # Connection automatically committed/rolled back and returned
    
    Use this when you need direct access to the connection object
    (e.g., for transactions that need to be committed at a specific time).
    """
    conn = get_db()  # Now uses the retry logic
    try:
        cursor = conn.cursor()
        yield conn, cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        put_db(conn)

# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

@contextmanager
def get_connection_autocommit():
    """
    Get a connection with autocommit enabled.
    
    Use this for schema migrations and other operations that need
    autocommit mode (e.g., CREATE/DROP/ALTER statements).
    """
    global db_pool
    if db_pool is None:
        init_pool()
    
    conn = db_pool.getconn()
    try:
        conn.autocommit = True
        yield conn
    finally:
        try:
            conn.autocommit = False
        except:
            pass
        db_pool.putconn(conn)

def init_db():
    """
    Creates the database tables and indexes if they don't already exist.
    """
    try:
        # Use the autocommit connection directly - this is the ONLY connection
        with get_connection_autocommit() as conn:
            cursor = conn.cursor()
            
            # ---------------------------------------------------------------------
            # USERS TABLE
            # ---------------------------------------------------------------------
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email_verified BOOLEAN DEFAULT FALSE
                );
            """)
            print("✅ Created/verified users table")

            # Add columns individually with their own checks
            columns_to_add = [
                ("reset_token", "TEXT"),
                ("reset_token_expiry", "TIMESTAMP"),
                ("verification_token", "VARCHAR(255)"),
                ("verification_token_expiry", "TIMESTAMP"),
                ("email_verification_sent_at", "TIMESTAMP"),
                ("subscription_tier", "VARCHAR(50) DEFAULT 'free'"),
                ("subscription_status", "VARCHAR(50) DEFAULT 'active'"),
                ("subscription_expiry", "TIMESTAMP"),
            ]
            
            for col_name, col_type in columns_to_add:
                try:
                    cursor.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col_name} {col_type};")
                    print(f"✅ Added column {col_name} to users")
                except Exception as e:
                    if "already exists" in str(e).lower():
                        print(f"ℹ️ Column {col_name} already exists in users")
                    else:
                        print(f"ℹ️ Could not add column {col_name}: {e}")

            # ---------------------------------------------------------------------
            # DOCUMENTS TABLE
            # ---------------------------------------------------------------------
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id SERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    expiry_date TEXT NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id)
                );
            """)
            print("✅ Created/verified documents table")

            # Add reminder columns individually
            reminder_columns = [
                ("last_reminder_sent", "DATE"),
                ("reminder_state", "TEXT"),
                ("snoozed_until", "DATE"),
            ]
            
            for col_name, col_type in reminder_columns:
                try:
                    cursor.execute(f"ALTER TABLE documents ADD COLUMN IF NOT EXISTS {col_name} {col_type};")
                    print(f"✅ Added column {col_name} to documents")
                except Exception as e:
                    if "already exists" in str(e).lower():
                        print(f"ℹ️ Column {col_name} already exists in documents")
                    else:
                        print(f"ℹ️ Could not add column {col_name}: {e}")

            print("✅ Added/verified reminder columns to documents table")

            # ---------------------------------------------------------------------
            # UNIQUE CONSTRAINT - Prevent duplicate documents
            # ---------------------------------------------------------------------
            cursor.execute("""
                SELECT 1 FROM information_schema.constraint_column_usage 
                WHERE constraint_name = 'unique_document_for_user' 
                AND table_name = 'documents';
            """)
            constraint_exists = cursor.fetchone() is not None
            
            if not constraint_exists:
                try:
                    # Check for duplicates
                    cursor.execute("""
                        SELECT COUNT(*) FROM (
                            SELECT user_id, title, expiry_date, COUNT(*) 
                            FROM documents 
                            GROUP BY user_id, title, expiry_date 
                            HAVING COUNT(*) > 1
                        ) AS duplicates;
                    """)
                    duplicate_count = cursor.fetchone()[0]
                    
                    if duplicate_count > 0:
                        print(f"⚠️ Found {duplicate_count} duplicate document groups. Removing duplicates...")
                        
                        cursor.execute("""
                            WITH duplicates AS (
                                SELECT id,
                                    ROW_NUMBER() OVER (
                                        PARTITION BY user_id, title, expiry_date 
                                        ORDER BY id
                                    ) as rn
                                FROM documents
                            )
                            DELETE FROM documents
                            WHERE id IN (
                                SELECT id FROM duplicates WHERE rn > 1
                            );
                        """)
                        print(f"✅ Removed {cursor.rowcount} duplicate documents.")
                    
                    cursor.execute("""
                        ALTER TABLE documents ADD CONSTRAINT unique_document_for_user 
                        UNIQUE (user_id, title, expiry_date);
                    """)
                    print("✅ Added unique constraint for documents")
                except Exception as e:
                    print(f"⚠️ Could not add unique constraint: {e}")
            else:
                print("ℹ️ Unique constraint already exists, skipping")

            # ---------------------------------------------------------------------
            # NEWSLETTER SUBSCRIBERS TABLE
            # ---------------------------------------------------------------------
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS newsletter_subscribers (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    unsubscribed_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE
                );
            """)
            print("✅ Created/verified newsletter_subscribers table")

            # ---------------------------------------------------------------------
            # INDEXES - Speed up common queries
            # ---------------------------------------------------------------------
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(verification_token);",
                "CREATE INDEX IF NOT EXISTS idx_users_email_verified ON users(email_verified);",
                "CREATE INDEX IF NOT EXISTS idx_newsletter_email ON newsletter_subscribers(email);",
            ]
            
            for index_sql in indexes:
                try:
                    cursor.execute(index_sql)
                    print(f"✅ Created index: {index_sql.split('ON')[0].strip()}")
                except Exception as e:
                    print(f"ℹ️ Could not create index: {e}")

            cursor.close()
            print("✅ Database tables initialized successfully")
        
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        # Don't re-raise - we want the app to continue even if DB init fails

# =============================================================================
# USER VERIFICATION FUNCTIONS
# =============================================================================

def create_verification_token(user_id):
    """
    Create and store a verification token for a user.
    
    Args:
        user_id: The user's ID
        
    Returns:
        The generated verification token (URL-safe string)
    
    The token is used in the email verification link:
    https://tracker.fritt.org/verify-email/{token}
    
    Tokens expire after 24 hours.
    """
    token = secrets.token_urlsafe(32)
    expiry = datetime.now(timezone.utc) + timedelta(hours=24)
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE users 
               SET verification_token = %s, 
                   verification_token_expiry = %s, 
                   email_verification_sent_at = %s 
               WHERE id = %s""",
            (token, expiry, datetime.now(timezone.utc), user_id)
        )
        conn.commit()
        cursor.close()
        return token
    finally:
        put_db(conn)


def verify_email_token(token):
    """
    Verify a user's email using their verification token.
    
    Args:
        token: The verification token from the email link
        
    Returns:
        (user_id, email) if token is valid and not expired, else None
    
    This function:
    1. Finds the user with the matching token
    2. Checks that the token hasn't expired
    3. Marks the user as verified
    4. Clears the token so it can't be reused
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, email 
               FROM users 
               WHERE verification_token = %s 
                 AND verification_token_expiry > %s 
                 AND email_verified = FALSE""",
            (token, datetime.now(timezone.utc))
        )
        user = cursor.fetchone()
        
        if user:
            cursor.execute(
                """UPDATE users 
                   SET email_verified = TRUE, 
                       verification_token = NULL, 
                       verification_token_expiry = NULL 
                   WHERE id = %s""",
                (user[0],)
            )
            conn.commit()
            cursor.close()
            return user
        
        cursor.close()
        return None
    finally:
        put_db(conn)


def is_email_verified(user_id):
    """
    Check if a user's email is verified.
    
    Args:
        user_id: The user's ID
        
    Returns:
        True if verified, False otherwise
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT email_verified FROM users WHERE id = %s",
            (user_id,)
        )
        result = cursor.fetchone()
        cursor.close()
        return result[0] if result else False
    finally:
        put_db(conn)

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    """
    Running "python database.py" directly sets up the tables.
    Do this once, right after connecting the Postgres database on Render.
    
    In production, init_db() is also called on app startup in app.py,
    so you don't need to run this manually unless you're setting up a
    new environment.
    """
    print("🚀 Initializing database tables...")
    init_db()
    print("✅ Database tables are ready.")

"""
# Later in the life if more traffic comes
# db_pool = psycopg2.pool.SimpleConnectionPool(
    1, 10,  # Increase to 10 if needed
    dsn=os.environ.get("DATABASE_URL")
)
"""