"""
app.py

Main Flask application for Fritt Tracker.

Each user has their own account (see the users table). Every document
is tied to the user who created it via a user_id column, and every
database query that touches documents filters by
"WHERE user_id = <the logged-in user>" - that filter is what keeps
one user's documents private from everyone else.

Passwords are never stored as plain text - werkzeug.security scrambles
("hashes") them before saving, and checks a login attempt by hashing
the attempt and comparing hashes, not the raw passwords.

The file upload feature (letting someone attach the actual document,
not just a title) is temporarily disabled - see the comments below
marked "FILE UPLOAD FEATURE: DISABLED FOR MVP". It's commented out,
not deleted, so it can be switched back on once there's persistent
file storage in place (e.g. S3, Supabase Storage, or a Render disk).
"""

# =============================================================================
# IMPORTS
# =============================================================================
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import re
import sys
from email_validator import validate_email, EmailNotValidError

import requests
from flask import (
    Flask, abort, flash, redirect, render_template, request,
    session, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

# Database utilities
from database import get_db, init_db, put_db

# =============================================================================
# CONFIGURATION & ENVIRONMENT VARIABLES
# =============================================================================

# Secret token for cron job authentication
TRIGGER_SECRET = os.environ.get("TRIGGER_SECRET")

# Sentry error monitoring (optional)
SENTRY_DSN = os.environ.get("SENTRY_DSN")
if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration
    
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.1,
        environment=os.environ.get("FLASK_ENV", "production"),
    )
    print("✅ Sentry error monitoring enabled")
else:
    print("ℹ️ Sentry not configured - set SENTRY_DSN to enable error monitoring")

# Email configuration
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "auth@fritt.org")
RESET_TOKEN_LIFETIME = timedelta(hours=1)

# Admin email
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")

# Log a warning if email is not configured
if not RESEND_API_KEY:
    print("⚠️ WARNING: RESEND_API_KEY not set - email features will be disabled")

# Subscription tiers
SUBSCRIPTION_TIERS = {
    'free': {
        'name': 'Free',
        'doc_limit': 20,
        'price_monthly': 0,
        'price_yearly': 0
    },
    'pro': {
        'name': 'Pro',
        'doc_limit': 100,
        'price_monthly': 8.99,
        'price_yearly': 89.99
    },
    'vip': {
        'name': 'VIP',
        'doc_limit': 0,  # Unlimited
        'price_monthly': 19.99,
        'price_yearly': 199.99
    }
}

# Webhook configuration
FLW_WEBHOOK_SECRET = os.environ.get("FLW_WEBHOOK_SECRET", "")
DATABASE_URL = os.environ.get("DATABASE_URL")

# =============================================================================
# FLASK APP INITIALIZATION
# =============================================================================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
app.config['SERVER_NAME'] = os.environ.get("APP_URL", "tracker.fritt.org")

# Make sure secret key exists
if not app.secret_key:
    print("❌ CRITICAL: SECRET_KEY environment variable not set.")
    sys.exit(1)

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# -----------------------------------------------------------------------------
# SECURE COOKIE SETTINGS
# -----------------------------------------------------------------------------
# SESSION_COOKIE_SECURE: only send the login cookie over HTTPS, never plain HTTP.
# SESSION_COOKIE_HTTPONLY: stops JavaScript from reading the cookie.
# SESSION_COOKIE_SAMESITE="Lax": stops the cookie being sent along with
# requests that originate from other websites.
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# -----------------------------------------------------------------------------
# CSRF PROTECTION
# -----------------------------------------------------------------------------
# Cross-Site Request Forgery: requires every POST form to include a
# secret, single-use token.
csrf = CSRFProtect(app)

# -----------------------------------------------------------------------------
# RATE LIMITING
# -----------------------------------------------------------------------------
limiter = Limiter(
    get_remote_address,
    app=app,
    # No default limits - we'll apply per-route instead
    enabled=os.environ.get("DISABLE_RATE_LIMITING", "false").lower() != "true"
)
# Custom error handler for rate limit exceeded
@app.errorhandler(429)
def ratelimit_handler(e):
    """Return a user-friendly message when rate limit is exceeded."""
    # e.description contains the custom error message
    error_message = e.description if e.description else "Too many requests. Please slow down."
    return render_template('errors/429.html', error_message=error_message), 429

# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

# Creates the users/documents tables if they don't exist yet.
try:
    init_db()
except Exception as e:
    print(f"Warning: could not initialize database tables on startup: {e}")

# Run migration for existing users
try:
    from migrate_subscriptions import run_subscription_migration
    run_subscription_migration()
except Exception as e:
    print(f"Note: Subscription migration not run: {e}")

# =============================================================================
# SUBSCRIPTION CACHE
# =============================================================================

_subscription_cache = {}
_cache_ttl = 60  # 60 seconds

# FIXED: Moved get_subscription_status definition BEFORE get_cached_subscription_status uses it
def get_subscription_status(user_id):
    """Get user's subscription status and expiry."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT subscription_tier, subscription_status, subscription_expiry FROM users WHERE id = %s",
            (user_id,)
        )
        result = cursor.fetchone()
        cursor.close()
        
        if result:
            tier, status, expiry = result
            # Make expiry timezone-aware if it's naive
            if expiry and expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)

            # Check if subscription is active
            is_active = True
            if tier != 'free' and expiry is not None:
                is_active = expiry > datetime.now(timezone.utc)
            elif tier == 'free':
                is_active = True
            else:
                is_active = status == 'active'
            
            return {
                'tier': tier,
                'status': status,
                'expiry': expiry,
                'is_active': is_active
            }
        return {'tier': 'free', 'status': 'active', 'expiry': None, 'is_active': True}
    finally:
        put_db(conn)

@app.before_request
def check_subscription_status():
    if 'user_id' in session:
        user_id = session['user_id']
        sub_status = get_subscription_status(user_id)
        if sub_status['tier'] not in ['free', 'suspended'] and not sub_status['is_active']:
            trim_documents_to_free_limit(user_id)
            # Update user to free tier...
            # Optionally flash a message
            flash("Your subscription has expired. You've been downgraded to the Free plan.", "warning")

def get_cached_subscription_status(user_id):
    """Get subscription status with simple caching."""
    cache_key = f"sub_{user_id}"
    now = datetime.now(timezone.utc)
    
    # Check if cached and not expired
    if cache_key in _subscription_cache:
        cached_data, cache_time = _subscription_cache[cache_key]
        if (now - cache_time).total_seconds() < _cache_ttl:
            return cached_data
    
    # Get fresh data
    result = get_subscription_status(user_id)
    _subscription_cache[cache_key] = (result, now)
    return result

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_utc_now():
    """Helper function to get timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def get_user_by_email(email):
    """
    Returns (id, email, password_hash, email_verified) for this email,
    or None if no account exists.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, password_hash, email_verified FROM users WHERE email = %s",
            (email,)
        )
        user = cursor.fetchone()
        cursor.close()
        return user
    finally:
        put_db(conn)


def get_user_by_reset_token(token):
    """
    Returns (id, email, reset_token_expiry) for a valid, unexpired reset token,
    or None if the token doesn't exist or has expired.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, reset_token_expiry FROM users WHERE reset_token = %s",
            (token,)
        )
        user = cursor.fetchone()
        cursor.close()
    finally:
        put_db(conn)

    if user is None:
        return None

    user_id, email, expiry = user
    
    if expiry is None:
        return None
    
    # Make expiry timezone-aware if it's naive
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    
    if get_utc_now() > expiry:
        return None

    return user


def is_email_verified(user_id):
    """Check if a user's email is verified."""
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


def get_user_subscription(user_id):
    """Get user's current subscription tier."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT subscription_tier FROM users WHERE id = %s",
            (user_id,)
        )
        result = cursor.fetchone()
        cursor.close()
        return result[0] if result else 'free'
    finally:
        put_db(conn)


def get_document_count(user_id):
    """Get the number of documents a user has."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM documents WHERE user_id = %s",
            (user_id,)
        )
        count = cursor.fetchone()[0]
        cursor.close()
        return count
    finally:
        put_db(conn)


def can_add_document(user_id):
    """Check if user can add more documents based on subscription."""
    # First check if suspended
    if is_user_suspended(user_id):
        return False
    
    sub_status = get_subscription_status(user_id)
    tier = sub_status['tier']
    
    # If Pro expired, trigger cleanup
    if tier == 'pro' and not sub_status['is_active']:
        # Trim documents and revert to free
        trim_documents_to_free_limit(user_id)
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users 
                SET subscription_tier = 'free', 
                    subscription_status = 'expired',
                    subscription_expiry = NULL
                WHERE id = %s
            """, (user_id,))
            conn.commit()
            cursor.close()
        finally:
            put_db(conn)
        tier = 'free'
    else:
        tier = sub_status['tier']
    
    # Suspended users can't add documents
    if tier == 'suspended':
        return False
    
    # VIP and Business have unlimited documents
    if tier in ['vip', 'business']:
        return True
    
    # Get the limit for this tier
    limit = SUBSCRIPTION_TIERS.get(tier, {}).get('doc_limit', 20)
    
    # Count current documents
    return get_document_count(user_id) < limit

def trim_documents_to_free_limit(user_id):
    """
    When a user's subscription expires, keep only the 20 documents
    with the closest expiry dates (most urgent) and delete the rest.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        # Get all document IDs ordered by expiry_date ASC (closest first)
        cursor.execute("""
            SELECT id 
            FROM documents 
            WHERE user_id = %s 
            ORDER BY expiry_date ASC
        """, (user_id,))
        all_docs = [row[0] for row in cursor.fetchall()]
        
        if len(all_docs) <= 20:
            return 0
        
        # Keep the first 20 (closest expiry), delete the rest
        docs_to_delete = all_docs[20:]
        
        if docs_to_delete:
            placeholders = ','.join(['%s'] * len(docs_to_delete))
            cursor.execute(
                f"DELETE FROM documents WHERE id IN ({placeholders}) AND user_id = %s",
                docs_to_delete + [user_id]
            )
            deleted_count = cursor.rowcount
            conn.commit()
            return deleted_count
        
        return 0
    finally:
        put_db(conn)

def get_owned_document(doc_id, user_id):
    """
    Fetches a single document, but ONLY if it belongs to user_id.
    Every route that edits/deletes/views a specific document by ID
    must go through this function.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, title, expiry_date, user_id FROM documents WHERE id = %s AND user_id = %s",
            (doc_id, user_id)
        )
        doc = cursor.fetchone()
        cursor.close()
    finally:
        put_db(conn)

    if doc is None:
        return None

    return {"id": doc[0], "title": doc[1], "expiry_date": doc[2], "user_id": doc[3]}


def get_documents(user_id, search_query=""):
    """
    Returns every document belonging to user_id, optionally filtered
    by a title search.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        if search_query:
            cursor.execute(
                "SELECT id, title, expiry_date FROM documents "
                "WHERE user_id = %s AND title ILIKE %s ORDER BY expiry_date ASC",
                (user_id, f"%{search_query}%")
            )
        else:
            cursor.execute(
                "SELECT id, title, expiry_date FROM documents "
                "WHERE user_id = %s ORDER BY expiry_date ASC",
                (user_id,)
            )
        docs = cursor.fetchall()
        cursor.close()
        return docs
    finally:
        put_db(conn)


def get_status(expiry_date_str):
    """Determine the status, color, and icon for a document based on days left."""
    expiry_date = datetime.strptime(expiry_date_str, "%Y-%m-%d").date()
    today = datetime.today().date()
    days_left = (expiry_date - today).days

    if days_left >= 120:
        return days_left, "Safe", "blue", "🟦"
    elif days_left >= 60:
        return days_left, "Good", "green", "🟢"
    elif days_left >= 15:
        return days_left, "Warning", "orange", "🟠"
    elif days_left >= 0:
        return days_left, "Urgent", "red", "🔴"
    else:
        return days_left, "Expired", "black", "⚫"


def get_user_region():
    """Detect user's region based on IP address."""
    try:
        # Get user's IP address
        if request.headers.get('X-Forwarded-For'):
            ip = request.headers.get('X-Forwarded-For').split(',')[0]
        else:
            ip = request.remote_addr
        
        # Skip for localhost (testing)
        if ip in ['127.0.0.1', 'localhost']:
            return 'us'
        
        # Use free API to get country
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        if response.status_code == 200:
            data = response.json()
            country_code = data.get('countryCode', '').upper()
            
            if country_code == 'NG':
                return 'ng'
            elif country_code == 'GB' or country_code == 'UK':
                return 'uk'
    except Exception as e:
        print(f"Warning: Could not detect region: {e}")
    
    return 'us'  # Default fallback


def get_pricing(region='us'):
    """Return pricing based on region."""
    pricing = {
        'ng': {
            'currency': '₦',
            'monthly': '5,000',
            'yearly': '50,000',
            'monthly_raw': 5000,
            'yearly_raw': 50000,
            'vip_monthly': '10,000',
            'vip_yearly': '100,000',
            'vip_monthly_raw': 10000,
            'vip_yearly_raw': 100000,
            'region_name': 'Nigeria',
            'currency_code': 'NGN'
        },
        'uk': {
            'currency': '£',
            'monthly': '8.00',
            'yearly': '80.00',
            'monthly_raw': 8.00,
            'yearly_raw':80.00,
            'vip_monthly': '16.00',
            'vip_yearly': '160.00',
            'vip_monthly_raw': 16.00,
            'vip_yearly_raw': 160.00,
            'region_name': 'United Kingdom',
            'currency_code': 'GBP'
        },
        'us': {
            'currency': '$',
            'monthly': '10.00',
            'yearly': '100.00',
            'monthly_raw': 10.00,
            'yearly_raw': 100.00,
            'vip_monthly': '20.00',
            'vip_yearly': '200.00',
            'vip_monthly_raw': 20.00,
            'vip_yearly_raw': 200.00,
            'region_name': 'Worldwide',
            'currency_code': 'USD'
        }
    }
    return pricing.get(region, pricing['us'])

def get_currency_for_region(region):
    """Map region to currency code."""
    currency_map = {
        'ng': 'NGN',
        'uk': 'GBP',
        'us': 'USD'
    }
    return currency_map.get(region, 'USD')


def get_plan_id(plan_type, currency):
    """Get the appropriate plan ID based on plan type and currency."""
    plan_map = {
        'pro_monthly': f"FLW_PRO_MONTHLY_{currency}_PLAN",
        'pro_yearly': f"FLW_PRO_YEARLY_{currency}_PLAN",
        'vip_monthly': f"FLW_VIP_MONTHLY_{currency}_PLAN",
        'vip_yearly': f"FLW_VIP_YEARLY_{currency}_PLAN",
    }
    var_name = plan_map.get(plan_type)
    return os.getenv(var_name) if var_name else None


def validate_password_strength(password):
    """Check if password meets complexity requirements."""
    errors = []
    
    if len(password) < 8:
        errors.append("At least 8 characters")
    if not any(c.isupper() for c in password):
        errors.append("An uppercase letter")
    if not any(c.islower() for c in password):
        errors.append("A lowercase letter")
    if not any(c.isdigit() for c in password):
        errors.append("A number")
    if not any(c in "!@#$%^&*()_+-=[]{}|;:',.<>?/~`" for c in password):
        errors.append("A symbol")
    
    return errors


def update_user_to_free(user_id):
    """
    Update a user's subscription to free tier.
    Called when subscription is cancelled or expires.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT subscription_tier, subscription_status FROM users WHERE id = %s",
            (user_id,)
        )
        result = cursor.fetchone()
        
        if not result:
            print(f"User {user_id} not found")
            return False
        
        current_tier, current_status = result
        
        if current_tier in ['pro', 'vip', 'business']:
            # Check if user has more than 20 documents
            cursor.execute(
                "SELECT COUNT(*) FROM documents WHERE user_id = %s",
                (user_id,)
            )
            doc_count = cursor.fetchone()[0]
            
            if doc_count > 20:
                trim_documents_to_free_limit(user_id)
                print(f"Trimmed documents for user {user_id} (had {doc_count} docs)")
            
            cursor.execute("""
                UPDATE users 
                SET subscription_tier = 'free',
                    subscription_status = 'expired',
                    subscription_expiry = NULL
                WHERE id = %s
            """, (user_id,))
            conn.commit()
            
            print(f"✅ User {user_id} downgraded to Free tier (was {current_tier})")
            return True
        else:
            print(f"User {user_id} is already on Free tier")
            return False
            
    except Exception as e:
        print(f"Error updating user {user_id} to free: {e}")
        conn.rollback()
        return False
    finally:
        put_db(conn)

def is_admin(user_id=None):
    """Check if a user has admin privileges."""
    if user_id is None:
        user_id = session.get("user_id")
    
    if not user_id:
        return False
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM admin_users WHERE user_id = %s",
            (user_id,)
        )
        result = cursor.fetchone()
        cursor.close()
        return result is not None
    finally:
        put_db(conn)

# Add this helper function at the top with other helper functions

def is_user_suspended(user_id):
    """Check if a user is suspended."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT subscription_tier FROM users WHERE id = %s",
            (user_id,)
        )
        result = cursor.fetchone()
        cursor.close()
        return result and result[0] == 'suspended'
    finally:
        put_db(conn)

def get_user_tier(user_id):
    """Get user's actual tier (not suspended)."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT subscription_tier FROM users WHERE id = %s",
            (user_id,)
        )
        result = cursor.fetchone()
        cursor.close()
        return result[0] if result else 'free'
    finally:
        put_db(conn)

# =============================================================================
# CONTEXT PROCESSOR
# =============================================================================

@app.context_processor
def utility_processor():
    """Make utility functions available to all templates."""
    return dict(is_admin=is_admin)

# =============================================================================
# DECORATORS & AUTHENTICATION HELPERS
# =============================================================================

def require_verified():
    """
    Check if user is logged in AND their email is verified AND not suspended.
    Returns a redirect if not, otherwise None.
    """
    if not session.get("user_id"):
        return redirect(url_for("login"))
    
    user_id = session["user_id"]
    
    # Check if suspended
    if is_user_suspended(user_id):
        session.clear()
        flash("❌ Your account has been suspended. Please contact support for assistance.", "error")
        return redirect(url_for("login"))
    
    if not is_email_verified(user_id):
        flash("⚠️ Please verify your email address to access all features.", "warning")
        return redirect(url_for("resend_verification"))
    
    return None

def verify_flutterwave_webhook(data, signature):
    """Verify webhook signature."""
    if not FLW_WEBHOOK_SECRET:
        print("⚠️ FLW_WEBHOOK_SECRET not set - webhook verification disabled")
        return True
    
    if not signature:
        print("❌ No signature provided")
        return False
    
    try:
        expected_signature = hmac.new(
            FLW_WEBHOOK_SECRET.encode('utf-8'),
            json.dumps(data).encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(expected_signature, signature)
    except Exception as e:
        print(f"❌ Signature verification error: {e}")
        return False

# =============================================================================
# EMAIL FUNCTIONS
# =============================================================================

# ***********
def send_verification_email(user_email, user_id):
    """Send email verification link to a new user."""
    # Check if email is configured
    if not RESEND_API_KEY:
        print(f"ℹ️ Email not sent: RESEND_API_KEY not configured. User {user_id} ({user_email}) needs verification.")
        # Still create the token so they can verify later via resend
        token = secrets.token_urlsafe(32)
        expiry = datetime.now(timezone.utc) + timedelta(hours=24)
        
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET verification_token = %s, verification_token_expiry = %s, email_verification_sent_at = %s WHERE id = %s",
                (token, expiry, datetime.now(timezone.utc), user_id)
            )
            conn.commit()
            cursor.close()
        finally:
            put_db(conn)
        
        flash("⚠️ Email service not configured. Please contact support to verify your email.", "warning")
        return False
    
    try:
        token = secrets.token_urlsafe(32)
        expiry = datetime.now(timezone.utc) + timedelta(hours=24)
        
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET verification_token = %s, verification_token_expiry = %s, email_verification_sent_at = %s WHERE id = %s",
                (token, expiry, datetime.now(timezone.utc), user_id)
            )
            conn.commit()
            cursor.close()
        finally:
            put_db(conn)
        
        base_url = os.environ.get("APP_URL", "tracker.fritt.org")
        verification_link = f"https://{base_url}{url_for('verify_email', token=token)}"
        
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": RESEND_FROM_EMAIL,
                "to": [user_email],
                "subject": "Verify your email address for Fritt Tracker",
                "html": f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <style>
                            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                            .header {{ background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
                            .content {{ padding: 30px; background: #f9fafb; }}
                            .button {{ background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; }}
                            .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 14px; }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h1>Welcome to Fritt Tracker! 🎉</h1>
                            </div>
                            <div class="content">
                                <p>Thanks for creating an account. Please verify your email address to get started.</p>
                                <p style="text-align: center; margin: 30px 0;">
                                    <a href="{verification_link}" class="button" style="background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Verify Email Address</a>
                                </p>
                                <p style="text-align: center; margin: 30px 0;">
                                    Or copy and paste this link into your browser:
                                    <br>
                                    <span style="word-break: break-all; color: #2563eb; font-size: 14px;">{verification_link}</span>
                                </p>
                                <p>This link expires in <strong>24 hours</strong>.</p>
                                <p style="color: #6b7280; font-size: 14px;">If you didn't create an account, you can safely ignore this email.</p>
                            </div>
                            <div class="footer">
                                <p>Fritt Tracker helps you keep track of your important documents and their expiry dates.</p>
                            </div>
                        </div>
                    </body>
                    </html>
                """,
                "text": f"""
                    Welcome to Fritt Tracker!
                    
                    Thanks for creating an account. Please verify your email address to get started.
                    
                    Verify your email by visiting this link:
                    {verification_link}
                    
                    This link expires in 24 hours.
                    
                    If you didn't create an account, you can safely ignore this email.
                    
                    ---
                    Fritt Tracker helps you keep track of your important documents and their expiry dates.
                    Visit us at: https://tracker.fritt.org
                """
            },
            timeout=10
        )
        
        if response.status_code >= 400:
            print(f"Warning: Resend error sending verification email: {response.text}")
            return False
        return True
    except Exception as e:
        print(f"Warning: failed to send verification email: {e}")
        return False


def send_password_reset_email(user_email, reset_link):
    """Send password reset email via Resend."""
    if not RESEND_API_KEY:
        print(f"ℹ️ Password reset email not sent: RESEND_API_KEY not configured for {user_email}")
        return
    
    try:
        if reset_link.startswith('http://'):
            reset_link = reset_link.replace('http://', 'https://')
        
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": RESEND_FROM_EMAIL,
                "to": [user_email],
                "subject": "Reset your Fritt Tracker password",
                "html": f"""
                    <p>We received a request to reset your Fritt Tracker password.</p>
                    <p><a href="{reset_link}">Click here to choose a new password</a></p>
                    <p>This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>
                    <p style="font-size: 14px; color: #6b7280;">Or copy this link: {reset_link}</p>
                """,
                "text": f"""
                    We received a request to reset your Fritt Tracker password.
                    
                    Click here to choose a new password: {reset_link}
                    
                    This link expires in 1 hour.
                    
                    If you didn't request this, you can safely ignore this email.
                """
            },
            timeout=10
        )
        if response.status_code >= 400:
            print(f"Warning: Resend returned an error sending password reset email: {response.text}")
    except Exception as e:
        print(f"Warning: failed to send password reset email: {e}")

def send_welcome_email(user_email, user_id):
    """Send a welcome email to a newly verified user."""
    if not RESEND_API_KEY:
        print(f"ℹ️ Welcome email not sent: RESEND_API_KEY not configured for {user_email}")
        return False
    
    try:
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
            result = cursor.fetchone()
            cursor.close()
            user_name = result[0].split('@')[0] if result else "there"
        finally:
            put_db(conn)
        
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": RESEND_FROM_EMAIL,
                "to": [user_email],
                "subject": "Welcome to Fritt Tracker! 🎉",
                "html": f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <style>
                            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                            .header {{ background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
                            .content {{ padding: 30px; background: #f9fafb; }}
                            .button {{ background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; }}
                            .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 14px; }}
                            .tip {{ background: white; padding: 15px; border-radius: 8px; margin: 10px 0; }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h1>Welcome to Fritt Tracker, {user_name}! 👋</h1>
                            </div>
                            <div class="content">
                                <p>Your email has been verified successfully! You're all set to start tracking your important documents.</p>
                                
                                <div class="tip">
                                    <h3>🚀 Quick Start Guide</h3>
                                    <ul>
                                        <li>📄 <strong>Add your documents</strong> - Click the "Add Document" button to start tracking</li>
                                        <li>🔔 <strong>Get reminders</strong> - We'll email you before documents expire</li>
                                        <li>📊 <strong>Track everything</strong> - See all your documents in one dashboard</li>
                                    </ul>
                                </div>
                                
                                <div class="tip">
                                    <h3>💡 Pro Tips</h3>
                                    <ul>
                                        <li>Import multiple documents at once using <strong>CSV import</strong></li>
                                        <li>Set <strong>realistic expiry dates</strong> to get timely reminders</li>
                                        <li>Renew documents with one click when they expire</li>
                                    </ul>
                                </div>
                                
                                <p style="text-align: center; margin: 30px 0;">
                                    <a href="https://tracker.fritt.org/" class="button">Go to Your Dashboard →</a>
                                </p>
                                
                                <p style="color: #6b7280; font-size: 14px;">You're on the <strong>Free plan</strong> which includes up to 20 documents. Upgrade anytime for unlimited tracking.</p>
                            </div>
                            <div class="footer">
                                <p>Need help? Reply to this email - we're here to help!</p>
                                <p style="font-size: 12px;">
                                    <a href="https://tracker.fritt.org/terms" style="color: #6b7280;">Terms</a> • 
                                    <a href="https://tracker.fritt.org/privacy" style="color: #6b7280;">Privacy</a>
                                </p>
                            </div>
                        </div>
                    </html>
                """,
                "text": f"""
                    Welcome to Fritt Tracker, {user_name}!
                    
                    Your email has been verified successfully! You're all set to start tracking your important documents.
                    
                    Quick Start Guide:
                    - Add your documents - Click "Add Document" to start tracking
                    - Get reminders - We'll email you before documents expire
                    - Track everything - See all your documents in one dashboard
                    
                    Pro Tips:
                    - Import multiple documents at once using CSV import
                    - Set realistic expiry dates to get timely reminders
                    - Renew documents with one click when they expire
                    
                    Go to Your Dashboard: https://tracker.fritt.org/
                    
                    You're on the Free plan which includes up to 20 documents. Upgrade anytime for unlimited tracking.
                    
                    Need help? Reply to this email - we're here to help!
                    
                    ---
                    Fritt Tracker - Keep track of your important documents
                    https://tracker.fritt.org
                """
            },
            timeout=10
        )
        
        if response.status_code >= 400:
            print(f"Warning: Resend error sending welcome email: {response.text}")
            return False
        return True
    except Exception as e:
        print(f"Error sending welcome email: {e}")
        return False

def send_subscription_expiry_email(user_email, user_name=None):
    """Send email notification when subscription expires."""
    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": RESEND_FROM_EMAIL,
                "to": [user_email],
                "subject": "Your Fritt Tracker Subscription Has Expired",
                "html": f"""
                    <h2>Your Subscription Has Expired</h2>
                    <p>Your Fritt Tracker subscription has expired.</p>
                    <p>You've been moved back to the Free plan with a 20-document limit.</p>
                    <p>If you have more than 20 documents, we've kept your 20 most important ones.</p>
                    <p><a href="https://tracker.fritt.org/pricing">Renew your subscription →</a></p>
                """,
                "text": f"""
                    Your Fritt Tracker subscription has expired.
                    
                    You've been moved back to the Free plan with a 20-document limit.
                    
                    If you have more than 20 documents, we've kept your 20 most important ones.
                    
                    Renew your subscription: https://tracker.fritt.org/pricing
                """
            },
            timeout=10
        )
        return response.status_code < 400
    except Exception as e:
        print(f"Error sending expiry email: {e}")
        return False

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def page_not_found(e):
    """Page not found - user followed a broken link or typed a wrong URL."""
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Internal server error - something unexpected broke in the app."""
    return render_template('errors/500.html'), 500


@app.errorhandler(403)
def forbidden(e):
    """Forbidden - user tried to access something they shouldn't."""
    return render_template('errors/403.html'), 403


@app.errorhandler(405)
def method_not_allowed(e):
    """Method not allowed - e.g., GET instead of POST."""
    return render_template('errors/405.html'), 405

# =============================================================================
# ROUTES - PUBLIC
# =============================================================================

@app.route("/")
@limiter.exempt
def home():
    """Show landing page for non-logged-in users, dashboard for logged-in users."""
    if not session.get("user_id"):
        region = get_user_region()
        pricing = get_pricing(region)
        return render_template("landing.html", pricing=pricing)

    user_id = session["user_id"]
    
    # Check if suspended FIRST
    if is_user_suspended(user_id):
        session.clear()
        flash("❌ Your account has been suspended. Please contact support.", "error")
        return redirect(url_for("login"))

    # Get subscription status
    sub_status = get_subscription_status(user_id)
    tier = sub_status['tier']
    is_active = sub_status['is_active']
    
    # If Pro/VIP expired, downgrade to free and trim documents
    if tier != 'free' and tier != 'suspended' and not is_active:
        deleted_count = trim_documents_to_free_limit(user_id)
        
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users 
                SET subscription_tier = 'free', 
                    subscription_status = 'expired',
                    subscription_expiry = NULL
                WHERE id = %s
            """, (user_id,))
            conn.commit()
            cursor.close()
        finally:
            put_db(conn)
        
        # Send expiry notification email
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
            user_email = cursor.fetchone()[0]
            cursor.close()
        finally:
            put_db(conn)
        
        send_subscription_expiry_email(user_email)
        
        if deleted_count > 0:
            flash(
                f"⚠️ Your {tier} subscription has expired. We've kept your 20 most important documents "
                f"(farthest from expiry) and removed {deleted_count} documents. "
                f"Upgrade to continue tracking more than 20 documents.",
                "warning"
            )
        else:
            flash(
                f"⚠️ Your {tier} subscription has expired. You're now on the Free plan with a 20-document limit. "
                "Upgrade to track more documents.",
                "warning"
            )
        
        # Update tier to free for the rest of the request
        tier = 'free'
        sub_status['tier'] = 'free'
    
    # Get document count
    doc_count = get_document_count(user_id)
    
    # If on free plan and over limit, trim immediately
    if tier == 'free' and doc_count > 20:
        deleted_count = trim_documents_to_free_limit(user_id)
        if deleted_count > 0:
            flash(
                f"⚠️ You have more than 20 documents on the Free plan. "
                f"We've kept your 20 most important documents (farthest from expiry) "
                f"and removed {deleted_count} documents. "
                f"Upgrade to Pro or VIP to track more than 20 documents.",
                "warning"
            )
            doc_count = get_document_count(user_id)  # Refresh count
    
    search_query = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "")

    docs = get_documents(user_id, search_query)
    documents = []

    for doc_id, title, expiry_date in docs:
        days_left, status, color, icon = get_status(expiry_date)

        if status_filter and status != status_filter:
            continue

        if days_left < 0:
            display_days = f"{abs(days_left)} days overdue"
        else:
            display_days = f"{days_left} days left"

        documents.append({
            "id": doc_id,
            "title": title,
            "expiry_date": expiry_date,
            "display_days": display_days,
            "status": status,
            "color": color,
            "icon": icon
        })

    return render_template(
        "index.html", 
        documents=documents, 
        doc_count=doc_count,  
        subscription_tier=tier,
        subscription_expiry=sub_status.get('expiry'),
        now=datetime.now(timezone.utc)
    )

@app.route("/health")
@limiter.exempt
def health_check():
    """Health check endpoint for UptimeRobot — no rate limit."""
    return "OK", 200

# =============================================================================
# ROUTES - CONTACT & SUPPORT
# =============================================================================

@app.route("/contact", methods=["GET", "POST"])
@limiter.limit("10 per hour", error_message="Too many contact form submissions. Please try again later.")
def contact():
    """Contact page for support and business inquiries."""
    error = None
    success = None
    
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        inquiry_type = request.form.get("inquiry_type", "support")
        
        # Validation
        if not name:
            error = "Please enter your name."
        elif not email:
            error = "Please enter your email address."
        elif not validate_email.email:
            error = "Please enter a valid email address."
        elif not subject:
            error = "Please enter a subject."
        elif not message or len(message) < 10:
            error = "Please enter a message (at least 10 characters)."
        
        if not error:
            try:
                # Store in database
                conn = get_db()
                try:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO contact_inquiries 
                        (name, email, subject, message, inquiry_type, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (name, email, subject, message, inquiry_type, datetime.now(timezone.utc)))
                    inquiry_id = cursor.fetchone()[0]
                    conn.commit()
                    cursor.close()
                finally:
                    put_db(conn)
                
                # Send notification to you (support@fritt.org or your personal email)
                send_inquiry_notification(name, email, subject, message, inquiry_type, inquiry_id)
                
                # Send auto-reply to user
                send_auto_reply(email, name, inquiry_type)
                
                success = "✅ Your message has been sent! We'll get back to you within 24 hours."
                
            except Exception as e:
                print(f"❌ Error saving inquiry: {e}")
                error = "Something went wrong. Please try again later."
    
    return render_template("contact.html", error=error, success=success)


@app.route("/business", methods=["GET", "POST"])
@limiter.limit("10 per hour", error_message="Too many business inquiries. Please try again later.")
def business():
    """Business inquiries page."""
    error = None
    success = None
    
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        company = request.form.get("company", "").strip()
        team_size = request.form.get("team_size", "")
        message = request.form.get("message", "").strip()
        
        # Validation
        if not name:
            error = "Please enter your name."
        elif not email:
            error = "Please enter your email address."
        elif not validate_email.email:
            error = "Please enter a valid email address."
        elif not company:
            error = "Please enter your company name."
        elif not message or len(message) < 10:
            error = "Please enter a message (at least 10 characters)."
        
        if not error:
            try:
                # Store in database
                conn = get_db()
                try:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO business_inquiries 
                        (name, email, company, team_size, message, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (name, email, company, team_size, message, datetime.now(timezone.utc)))
                    inquiry_id = cursor.fetchone()[0]
                    conn.commit()
                    cursor.close()
                finally:
                    put_db(conn)
                
                # Send notification to you
                send_business_inquiry_notification(name, email, company, team_size, message, inquiry_id)
                
                # Send auto-reply
                send_business_auto_reply(email, name)
                
                success = "✅ Thank you! A team member will contact you within 24 hours."
                
            except Exception as e:
                print(f"❌ Error saving business inquiry: {e}")
                error = "Something went wrong. Please try again later."
    
    return render_template("business.html", error=error, success=success)

def send_inquiry_notification(name, email, subject, message, inquiry_type, inquiry_id):
    """Send notification to you (the admin)."""
    if not RESEND_API_KEY:
        print(f"📧 New {inquiry_type} inquiry from {name} ({email}): {subject}")
        return
    
    try:
        # Send to your personal email (or support@fritt.org later)
        if not ADMIN_EMAIL:
            print(f"⚠️ WARNING: ADMIN_EMAIL not set. Inquiry from {email} was not sent.")
            return
        
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": RESEND_FROM_EMAIL,
                "to": [ADMIN_EMAIL],
                "reply_to": [email],
                "subject": f"[Fritt Tracker] New {inquiry_type} inquiry: {subject}",
                "html": f"""
                    <h2>New {inquiry_type.capitalize()} Inquiry</h2>
                    <p><strong>From:</strong> {name} ({email})</p>
                    <p><strong>Subject:</strong> {subject}</p>
                    <p><strong>Message:</strong></p>
                    <p>{message.replace(chr(10), '<br>')}</p>
                    <hr>
                    <p><strong>Inquiry ID:</strong> #{inquiry_id}</p>
                    <p><strong>Type:</strong> {inquiry_type}</p>
                    <p>Reply directly to this email to respond to {name}.</p>
                """,
                "text": f"""
                    New {inquiry_type} Inquiry
                    
                    From: {name} ({email})
                    Subject: {subject}
                    
                    Message:
                    {message}
                    
                    Inquiry ID: #{inquiry_id}
                    Type: {inquiry_type}
                """
            },
            timeout=10
        )
        if response.status_code >= 400:
            print(f"⚠️ Failed to send inquiry notification: {response.text}")
    except Exception as e:
        print(f"⚠️ Error sending inquiry notification: {e}")


def send_auto_reply(user_email, user_name, inquiry_type="support"):
    """Send auto-reply to user."""
    if not RESEND_API_KEY:
        print(f"ℹ️ Auto-reply not sent (no API key): {user_email}")
        return
    
    try:
        if inquiry_type == "business":
            subject = "Thank you for your business inquiry"
            body = f"""
                <h2>Thank you for reaching out, {user_name}!</h2>
                <p>We've received your business inquiry and a team member will get back to you within <strong>24 hours</strong>.</p>
                <p>In the meantime, you can:</p>
                <ul>
                    <li>📝 <a href="https://tracker.fritt.org/register">Create your free account</a></li>
                    <li>📖 <a href="https://tracker.fritt.org/pricing">View our pricing plans</a></li>
                </ul>
                <hr>
                <p style="font-size: 14px; color: #6b7280;">
                    This is an automated response. Our team will personally follow up with you soon.
                </p>
            """
            text_body = f"""
                Thank you for reaching out, {user_name}!
                
                We've received your business inquiry and a team member will get back to you within 24 hours.
                
                In the meantime, you can:
                - Create your free account: https://tracker.fritt.org/register
                - View our pricing plans: https://tracker.fritt.org/pricing
                
                This is an automated response. Our team will personally follow up with you soon.
            """
        else:
            subject = "We've received your message"
            body = f"""
                <h2>Thanks for reaching out, {user_name}!</h2>
                <p>We've received your message and will get back to you within <strong>24 hours</strong>.</p>
                <p>In the meantime, you can:</p>
                <ul>
                    <li>📝 <a href="https://tracker.fritt.org/register">Create your free account</a></li>
                    <li>📖 <a href="https://tracker.fritt.org/pricing">View our pricing plans</a></li>
                    <li>💬 <a href="https://tracker.fritt.org/feedback">Feedback</a> - Share feature ideas</li>
                </ul>
                <hr>
                <p style="font-size: 14px; color: #6b7280;">
                    This is an automated response. For urgent issues, reply to this email and we'll prioritize it.
                </p>
            """
            text_body = f"""
                Thanks for reaching out, {user_name}!
                
                We've received your message and will get back to you within 24 hours.
                
                In the meantime, you can:
                - Create your free account: https://tracker.fritt.org/register
                - View our pricing plans: https://tracker.fritt.org/pricing
                - Give us feedback and share feature ideas: https://tracker.fritt.org/feedback
                
                This is an automated response. For urgent issues, reply to this email and we'll prioritize it.
            """
        
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": RESEND_FROM_EMAIL,
                "to": [user_email],
                "subject": subject,
                "html": f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <style>
                            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                            .header {{ background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
                            .content {{ padding: 30px; background: #f9fafb; }}
                            .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 14px; }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h1>Fritt Tracker</h1>
                            </div>
                            <div class="content">
                                {body}
                            </div>
                            <div class="footer">
                                <p>Fritt Tracker - Never miss a document renewal</p>
                                <p style="font-size: 12px;">
                                    <a href="https://tracker.fritt.org/terms" style="color: #6b7280;">Terms</a> • 
                                    <a href="https://tracker.fritt.org/privacy" style="color: #6b7280;">Privacy</a>
                                </p>
                            </div>
                        </div>
                    </body>
                    </html>
                """,
                "text": text_body
            },
            timeout=10
        )
        if response.status_code >= 400:
            print(f"⚠️ Failed to send auto-reply: {response.text}")
    except Exception as e:
        print(f"⚠️ Error sending auto-reply: {e}")


def send_business_inquiry_notification(name, email, company, team_size, message, inquiry_id):
    """Send business inquiry notification to you."""
    if not RESEND_API_KEY:
        print(f"📧 New business inquiry from {name} ({email}) at {company}")
        return
    
    try:
        # Get admin email from env variables
        if not ADMIN_EMAIL:
            print(f"⚠️ WARNING: ADMIN_EMAIL not set. Inquiry from {email} was not sent.")
            return
        
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": RESEND_FROM_EMAIL,
                "to": [ADMIN_EMAIL],
                "reply_to": [email],
                "subject": f"[Fritt Tracker] Business Inquiry: {company}",
                "html": f"""
                    <h2>New Business Inquiry</h2>
                    <p><strong>Name:</strong> {name}</p>
                    <p><strong>Email:</strong> {email}</p>
                    <p><strong>Company:</strong> {company}</p>
                    <p><strong>Team Size:</strong> {team_size or 'Not specified'}</p>
                    <p><strong>Message:</strong></p>
                    <p>{message.replace(chr(10), '<br>')}</p>
                    <hr>
                    <p><strong>Inquiry ID:</strong> #{inquiry_id}</p>
                """,
                "text": f"""
                    New Business Inquiry
                    
                    Name: {name}
                    Email: {email}
                    Company: {company}
                    Team Size: {team_size or 'Not specified'}
                    
                    Message:
                    {message}
                    
                    Inquiry ID: #{inquiry_id}
                """
            },
            timeout=10
        )
        if response.status_code >= 400:
            print(f"⚠️ Failed to send business inquiry notification: {response.text}")
    except Exception as e:
        print(f"⚠️ Error sending business inquiry notification: {e}")


def send_business_auto_reply(user_email, user_name):
    """Send auto-reply for business inquiries."""
    return send_auto_reply(user_email, user_name, "business")

# =============================================================================
# ADMIN ROUTES
# =============================================================================

def require_admin():
    """Decorator-like function to require admin access."""
    if not session.get("user_id"):
        flash("Please log in to access the admin area.", "warning")
        return redirect(url_for("login"))
    
    if not is_admin():
        flash("You don't have permission to access the admin area.", "error")
        abort(403)
    
    return None


def log_admin_action(action, target_type=None, target_id=None, details=None):
    """Log admin actions for audit trail."""
    if not session.get("user_id"):
        return
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log 
            (admin_id, action, target_type, target_id, details, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            session["user_id"],
            action,
            target_type,
            target_id,
            json.dumps(details) if details else None,
            request.remote_addr,
            request.headers.get('User-Agent')
        ))
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)


@app.route("/admin")
def admin_dashboard():
    """Admin dashboard - overview of everything."""
    auth = require_admin()
    if auth:
        return auth
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        # Get stats
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE email_verified = TRUE")
        verified_users = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT subscription_tier, COUNT(*) 
            FROM users 
            GROUP BY subscription_tier
        """)
        subscription_stats = cursor.fetchall()
        
        cursor.execute("SELECT COUNT(*) FROM documents")
        total_documents = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE expiry_date::date <= CURRENT_DATE
        """)
        expired_documents = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE expiry_date::date > CURRENT_DATE 
            AND expiry_date::date <= CURRENT_DATE + INTERVAL '14 days'
        """)
        expiring_soon = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM flagged_users WHERE status = 'pending'
        """)
        pending_flags = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM contact_inquiries WHERE status = 'new'
        """)
        pending_inquiries = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT id, email, subscription_tier, email_verified, created_at
            FROM users 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        recent_users = cursor.fetchall()
        
        cursor.close()
        
    finally:
        put_db(conn)
    
    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        verified_users=verified_users,
        subscription_stats=subscription_stats,
        total_documents=total_documents,
        expired_documents=expired_documents,
        expiring_soon=expiring_soon,
        pending_flags=pending_flags,
        pending_inquiries=pending_inquiries,
        recent_users=recent_users
    )


@app.route("/admin/users")
def admin_users():
    """View and manage all users."""
    auth = require_admin()
    if auth:
        return auth
    
    search = request.args.get("search", "")
    status = request.args.get("status", "all")
    page = int(request.args.get("page", 1))
    per_page = 20
    offset = (page - 1) * per_page
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        # Build query
        query = """
            SELECT u.id, u.email, u.email_verified, u.subscription_tier, 
                   u.subscription_status, u.created_at,
                   COUNT(d.id) as doc_count,
                   EXISTS(SELECT 1 FROM admin_users a WHERE a.user_id = u.id) as is_admin,
                   EXISTS(SELECT 1 FROM flagged_users f WHERE f.user_id = u.id AND f.status = 'pending') as is_flagged
            FROM users u
            LEFT JOIN documents d ON d.user_id = u.id
        """
        where_clauses = []
        params = []
        
        if search:
            where_clauses.append("u.email ILIKE %s")
            params.append(f"%{search}%")
        
        if status == "verified":
            where_clauses.append("u.email_verified = TRUE")
        elif status == "unverified":
            where_clauses.append("u.email_verified = FALSE")
        elif status == "flagged":
            where_clauses.append("EXISTS(SELECT 1 FROM flagged_users f WHERE f.user_id = u.id AND f.status = 'pending')")
        elif status == "admin":
            where_clauses.append("EXISTS(SELECT 1 FROM admin_users a WHERE a.user_id = u.id)")
        
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        query += " GROUP BY u.id ORDER BY u.created_at DESC LIMIT %s OFFSET %s"
        params.extend([per_page, offset])
        
        cursor.execute(query, params)
        users = cursor.fetchall()
        
        # Get total count for pagination
        count_query = "SELECT COUNT(DISTINCT u.id) FROM users u"
        if where_clauses:
            count_query += " WHERE " + " AND ".join(where_clauses)
        cursor.execute(count_query, params[:-2])  # Exclude LIMIT/OFFSET
        total_users = cursor.fetchone()[0]
        
        cursor.close()
        
    finally:
        put_db(conn)
    
    return render_template(
        "admin/users.html",
        users=users,
        total_users=total_users,
        page=page,
        per_page=per_page,
        search=search,
        status=status
    )


@app.route("/admin/user/<int:user_id>")
def admin_user_detail(user_id):
    """View detailed user information."""
    auth = require_admin()
    if auth:
        return auth
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        # Get user info
        cursor.execute("""
            SELECT u.id, u.email, u.email_verified, u.subscription_tier,
                u.subscription_status, u.subscription_expiry, u.created_at,
                EXISTS(SELECT 1 FROM admin_users a WHERE a.user_id = u.id) as is_admin,
                EXISTS(SELECT 1 FROM flagged_users f WHERE f.user_id = u.id AND f.status = 'pending') as is_flagged
            FROM users u
            WHERE u.id = %s
        """, (user_id,))
        user = cursor.fetchone()
        
        if not user:
            abort(404)
        
        # Get user documents
        cursor.execute("""
            SELECT id, title, expiry_date,
                   CASE 
                       WHEN expiry_date::date > CURRENT_DATE + INTERVAL '60 days' THEN 'Safe'
                       WHEN expiry_date::date > CURRENT_DATE + INTERVAL '15 days' THEN 'Good'
                       WHEN expiry_date::date >= CURRENT_DATE THEN 'Warning'
                       ELSE 'Expired'
                   END as status
            FROM documents
            WHERE user_id = %s
            ORDER BY expiry_date ASC
        """, (user_id,))
        documents = cursor.fetchall()
        
        # Get user activity logs
        cursor.execute("""
            SELECT action, details, created_at
            FROM user_activity_logs
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 50
        """, (user_id,))
        activity_logs = cursor.fetchall()
        
        # Get audit logs for this user
        cursor.execute("""
            SELECT action, target_type, details, created_at
            FROM audit_log
            WHERE target_type = 'user' AND target_id = %s
            ORDER BY created_at DESC
            LIMIT 20
        """, (user_id,))
        audit_logs = cursor.fetchall()
        
        cursor.close()
        
    finally:
        put_db(conn)
    
    return render_template(
        "admin/user_detail.html",
        user=user,
        documents=documents,
        activity_logs=activity_logs,
        audit_logs=audit_logs
    )


@app.route("/admin/user/<int:user_id>/action", methods=["POST"])
def admin_user_action(user_id):
    """Perform actions on a user (suspend, verify, make admin, etc.)."""
    auth = require_admin()
    if auth:
        return auth
    
    action = request.form.get("action")
    
    if not action:
        flash("No action specified.", "error")
        return redirect(url_for("admin_user_detail", user_id=user_id))
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        if action == "verify_email":
            cursor.execute(
                "UPDATE users SET email_verified = TRUE WHERE id = %s",
                (user_id,)
            )
            conn.commit()
            log_admin_action("verify_email", "user", user_id, {"action": "verified_email"})
            flash("✅ User email verified successfully.", "success")
            
        elif action == "make_admin":
            cursor.execute(
                "INSERT INTO admin_users (user_id) VALUES (%s) ON CONFLICT (user_id) DO NOTHING",
                (user_id,)
            )
            conn.commit()
            log_admin_action("make_admin", "user", user_id, {"action": "made_admin"})
            flash("✅ User is now an admin.", "success")
            
        elif action == "remove_admin":
            cursor.execute(
                "DELETE FROM admin_users WHERE user_id = %s",
                (user_id,)
            )
            conn.commit()
            log_admin_action("remove_admin", "user", user_id, {"action": "removed_admin"})
            flash("✅ Admin privileges removed.", "success")
            
        elif action == "flag_user":
            reason = request.form.get("reason", "No reason provided")
            cursor.execute("""
                INSERT INTO flagged_users (user_id, flagged_by, reason, status)
                VALUES (%s, %s, %s, 'pending')
            """, (user_id, session["user_id"], reason))
            conn.commit()
            log_admin_action("flag_user", "user", user_id, {"reason": reason})
            flash("⚠️ User has been flagged for review.", "warning")
            
        elif action == "resolve_flag":
            cursor.execute("""
                UPDATE flagged_users 
                SET status = 'resolved', resolved_at = %s, notes = %s
                WHERE user_id = %s AND status = 'pending'
            """, (datetime.now(timezone.utc), request.form.get("notes", ""), user_id))
            conn.commit()
            log_admin_action("resolve_flag", "user", user_id, {"action": "resolved_flag"})
            flash("✅ Flag resolved.", "success")
            
        elif action == "suspend_user":
            cursor.execute(
                "UPDATE users SET subscription_tier = 'suspended' WHERE id = %s",
                (user_id,)
            )
            conn.commit()
            log_admin_action("suspend_user", "user", user_id, {"action": "suspended"})
            flash("⚠️ User has been suspended.", "warning")
            
        elif action == "unsuspend_user":
            cursor.execute(
                "UPDATE users SET subscription_tier = 'free', subscription_status = 'active' WHERE id = %s AND subscription_tier = 'suspended'",
                (user_id,)
            )
            conn.commit()
            log_admin_action("unsuspend_user", "user", user_id, {"action": "unsuspended"})
            flash("✅ User unsuspended.", "success")
            
        # NEW: Manual Upgrade/Downgrade Actions
        elif action == "upgrade_user":
            new_tier = request.form.get("new_tier")
            if new_tier not in ['pro', 'vip']:  # Removed 'business'
                flash("Invalid tier selected.", "error")
                return redirect(url_for("admin_user_detail", user_id=user_id))
            
            # Check if user has more than 20 documents when downgrading to free
            if new_tier == 'free':
                cursor.execute("SELECT COUNT(*) FROM documents WHERE user_id = %s", (user_id,))
                doc_count = cursor.fetchone()[0]
                if doc_count > 20:
                    trim_documents_to_free_limit(user_id)
            
            cursor.execute("""
                UPDATE users 
                SET subscription_tier = %s,
                    subscription_status = 'active',
                    subscription_expiry = NULL
                WHERE id = %s
            """, (new_tier, user_id))
            conn.commit()
            log_admin_action("upgrade_user", "user", user_id, {"new_tier": new_tier})
            flash(f"✅ User upgraded to {new_tier.capitalize()} plan.", "success")
            
        elif action == "downgrade_user":
            new_tier = request.form.get("new_tier")
            if new_tier != 'free':
                flash("Only free downgrade is supported.", "error")
                return redirect(url_for("admin_user_detail", user_id=user_id))
            
            # Trim documents to free limit
            deleted_count = trim_documents_to_free_limit(user_id)
            
            cursor.execute("""
                UPDATE users 
                SET subscription_tier = 'free',
                    subscription_status = 'active',
                    subscription_expiry = NULL
                WHERE id = %s
            """, (user_id,))
            conn.commit()
            log_admin_action("downgrade_user", "user", user_id, {"deleted_documents": deleted_count})
            flash(f"✅ User downgraded to Free plan. Removed {deleted_count} documents.", "success")

        elif action == "force_fix":
            # Force a subscription check and cleanup
            sub_status = get_subscription_status(user_id)
            tier = sub_status['tier']
            
            # Check if subscription expired
            if tier != 'free' and tier != 'suspended' and not sub_status['is_active']:
                deleted_count = trim_documents_to_free_limit(user_id)
                cursor.execute("""
                    UPDATE users 
                    SET subscription_tier = 'free', 
                        subscription_status = 'expired',
                        subscription_expiry = NULL
                    WHERE id = %s
                """, (user_id,))
                conn.commit()
                flash(f"✅ User forced to Free plan. Removed {deleted_count} documents.", "success")
            else:
                # Just check and trim if over limit on free
                cursor.execute("SELECT COUNT(*) FROM documents WHERE user_id = %s", (user_id,))
                doc_count = cursor.fetchone()[0]
                if tier == 'free' and doc_count > 20:
                    deleted_count = trim_documents_to_free_limit(user_id)
                    flash(f"⚠️ User had {doc_count} documents on Free plan. Removed {deleted_count} documents.", "warning")
                else:
                    flash(f"✅ User is on {tier} plan with {doc_count} documents. No issues found.", "success")
            
            log_admin_action("force_fix", "user", user_id, {"action": "force_fix_subscription"})
            
        elif action == "delete_user":
            # Delete user and all their data
            cursor.execute("DELETE FROM documents WHERE user_id = %s", (user_id,))
            cursor.execute("DELETE FROM flagged_users WHERE user_id = %s", (user_id,))
            cursor.execute("DELETE FROM admin_users WHERE user_id = %s", (user_id,))
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            log_admin_action("delete_user", "user", user_id, {"action": "deleted_user"})
            flash("🗑️ User and all associated data deleted.", "warning")
            return redirect(url_for("admin_users"))
        
        cursor.close()
        
    except Exception as e:
        conn.rollback()
        flash(f"Error performing action: {str(e)}", "error")
    finally:
        put_db(conn)
    
    return redirect(url_for("admin_user_detail", user_id=user_id))

@app.route("/admin/inquiries")
def admin_inquiries():
    """View all contact inquiries."""
    auth = require_admin()
    if auth:
        return auth
    
    status_filter = request.args.get("status", "all")
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        query = """
            SELECT id, name, email, subject, message, inquiry_type, status, created_at
            FROM contact_inquiries
        """
        params = []
        
        if status_filter != "all":
            query += " WHERE status = %s"
            params.append(status_filter)
        
        query += " ORDER BY created_at DESC"
        
        cursor.execute(query, params)
        inquiries = cursor.fetchall()
        cursor.close()
        
    finally:
        put_db(conn)
    
    return render_template(
        "admin/inquiries.html",
        inquiries=inquiries,
        status_filter=status_filter
    )


@app.route("/admin/inquiry/<int:inquiry_id>/resolve", methods=["POST"])
def resolve_inquiry(inquiry_id):
    """Mark an inquiry as resolved."""
    auth = require_admin()
    if auth:
        return auth
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE contact_inquiries 
            SET status = 'resolved', updated_at = %s
            WHERE id = %s
        """, (datetime.now(timezone.utc), inquiry_id))
        conn.commit()
        cursor.close()
        log_admin_action("resolve_inquiry", "inquiry", inquiry_id, {"action": "resolved"})
        flash("✅ Inquiry marked as resolved.", "success")
    finally:
        put_db(conn)
    
    return redirect(url_for("admin_inquiries"))


@app.route("/admin/business")
def admin_business_inquiries():
    """View all business inquiries."""
    auth = require_admin()
    if auth:
        return auth
    
    status_filter = request.args.get("status", "all")
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        query = """
            SELECT id, name, email, company, team_size, message, status, created_at
            FROM business_inquiries
        """
        params = []
        
        if status_filter != "all":
            query += " WHERE status = %s"
            params.append(status_filter)
        
        query += " ORDER BY created_at DESC"
        
        cursor.execute(query, params)
        inquiries = cursor.fetchall()
        cursor.close()
        
    finally:
        put_db(conn)
    
    return render_template(
        "admin/business_inquiries.html",
        inquiries=inquiries,
        status_filter=status_filter
    )


@app.route("/admin/documents")
def admin_documents():
    """View all documents across all users, grouped by user."""
    auth = require_admin()
    if auth:
        return auth
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT d.id, d.title, d.expiry_date, d.user_id, u.email,
                   CASE 
                       WHEN d.expiry_date::date > CURRENT_DATE + INTERVAL '60 days' THEN 'Safe'
                       WHEN d.expiry_date::date > CURRENT_DATE + INTERVAL '15 days' THEN 'Good'
                       WHEN d.expiry_date::date >= CURRENT_DATE THEN 'Warning'
                       ELSE 'Expired'
                   END as status
            FROM documents d
            JOIN users u ON u.id = d.user_id
            ORDER BY u.email ASC, d.expiry_date ASC
            LIMIT 100
        """)
        documents = cursor.fetchall()
        cursor.close()
    finally:
        put_db(conn)
    
    return render_template("admin/documents.html", documents=documents)

@app.route("/admin/audit")
def admin_audit_log():
    """View audit log of all admin actions."""
    auth = require_admin()
    if auth:
        return auth
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT al.*, u.email as admin_email
            FROM audit_log al
            JOIN users u ON u.id = al.admin_id
            ORDER BY al.created_at DESC
            LIMIT 100
        """)
        logs = cursor.fetchall()
        cursor.close()
    finally:
        put_db(conn)
    
    return render_template("admin/audit.html", logs=logs)

@app.route("/admin/fix-user/<int:user_id>")
def admin_fix_user(user_id):
    """Force a subscription check and cleanup for a user."""
    auth = require_admin()
    if auth:
        return auth
    
    # Check if user exists
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for("admin_users"))
        
        # Force subscription check
        sub_status = get_subscription_status(user_id)
        tier = sub_status['tier']
        
        if tier != 'free' and tier != 'suspended' and not sub_status['is_active']:
            deleted_count = trim_documents_to_free_limit(user_id)
            cursor.execute("""
                UPDATE users 
                SET subscription_tier = 'free', 
                    subscription_status = 'expired',
                    subscription_expiry = NULL
                WHERE id = %s
            """, (user_id,))
            conn.commit()
            flash(f"✅ User {user[0]} downgraded to Free. Removed {deleted_count} documents.", "success")
        else:
            # Just check and trim if over limit
            cursor.execute("SELECT COUNT(*) FROM documents WHERE user_id = %s", (user_id,))
            doc_count = cursor.fetchone()[0]
            if tier == 'free' and doc_count > 20:
                deleted_count = trim_documents_to_free_limit(user_id)
                flash(f"⚠️ User had {doc_count} documents on Free plan. Removed {deleted_count} documents.", "warning")
            else:
                flash(f"✅ User {user[0]} is on {tier} plan with {doc_count} documents. No changes needed.", "success")
        
        cursor.close()
    finally:
        put_db(conn)
    
    return redirect(url_for("admin_user_detail", user_id=user_id))

@app.route("/admin/payment-plans")
def admin_payment_plans():
    """View and manage payment plans."""
    auth = require_admin()
    if auth:
        return auth
    
    # For now, just show current pricing configuration
    regions = ['us', 'uk', 'ng']
    pricing_data = {}
    for region in regions:
        pricing_data[region] = get_pricing(region)
    
    return render_template("admin/payment_plans.html", pricing_data=pricing_data)

@app.route("/admin/user/<int:user_id>/documents")
def admin_user_documents(user_id):
    """View all documents for a specific user."""
    auth = require_admin()
    if auth:
        return auth
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        # Get user info
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for("admin_users"))
        
        # Get user documents
        cursor.execute("""
            SELECT id, title, expiry_date,
                   CASE 
                       WHEN expiry_date::date > CURRENT_DATE + INTERVAL '60 days' THEN 'Safe'
                       WHEN expiry_date::date > CURRENT_DATE + INTERVAL '15 days' THEN 'Good'
                       WHEN expiry_date::date >= CURRENT_DATE THEN 'Warning'
                       ELSE 'Expired'
                   END as status
            FROM documents
            WHERE user_id = %s
            ORDER BY expiry_date ASC
        """, (user_id,))
        documents = cursor.fetchall()
        cursor.close()
        
    finally:
        put_db(conn)
    
    return render_template(
        "admin/user_documents.html",
        user=user,
        user_id=user_id,
        documents=documents
    )


@app.route("/admin/user/<int:user_id>/document/<int:doc_id>/delete", methods=["POST"])
def admin_delete_user_document(user_id, doc_id):
    """Delete a document on behalf of a user."""
    auth = require_admin()
    if auth:
        return auth
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        # Verify document belongs to user
        cursor.execute(
            "SELECT title FROM documents WHERE id = %s AND user_id = %s",
            (doc_id, user_id)
        )
        doc = cursor.fetchone()
        if not doc:
            flash("Document not found or doesn't belong to this user.", "error")
            return redirect(url_for("admin_user_documents", user_id=user_id))
        
        # Delete the document
        cursor.execute(
            "DELETE FROM documents WHERE id = %s AND user_id = %s",
            (doc_id, user_id)
        )
        conn.commit()
        
        log_admin_action("admin_delete_document", "document", doc_id, {"user_id": user_id, "title": doc[0]})
        flash(f"✅ Document '{doc[0]}' deleted successfully.", "success")
        
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting document: {str(e)}", "error")
    finally:
        put_db(conn)
    
    return redirect(url_for("admin_user_documents", user_id=user_id))


@app.route("/admin/user/<int:user_id>/document/<int:doc_id>/renew", methods=["GET", "POST"])
def admin_renew_user_document(user_id, doc_id):
    """Renew a document on behalf of a user."""
    auth = require_admin()
    if auth:
        return auth
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        # Get document info
        cursor.execute(
            "SELECT title, expiry_date FROM documents WHERE id = %s AND user_id = %s",
            (doc_id, user_id)
        )
        doc = cursor.fetchone()
        if not doc:
            flash("Document not found or doesn't belong to this user.", "error")
            return redirect(url_for("admin_user_documents", user_id=user_id))
        
        if request.method == "POST":
            new_expiry = request.form.get("expiry_date")
            
            if not new_expiry:
                flash("Please select a new expiry date.", "error")
                return redirect(url_for("admin_renew_user_document", user_id=user_id, doc_id=doc_id))
            
            try:
                datetime.strptime(new_expiry, "%Y-%m-%d")
            except ValueError:
                flash("Invalid date format.", "error")
                return redirect(url_for("admin_renew_user_document", user_id=user_id, doc_id=doc_id))
            
            cursor.execute("""
                UPDATE documents 
                SET expiry_date = %s, 
                    last_reminder_sent = NULL, 
                    reminder_state = NULL, 
                    snoozed_until = NULL 
                WHERE id = %s AND user_id = %s
            """, (new_expiry, doc_id, user_id))
            conn.commit()
            
            log_admin_action("admin_renew_document", "document", doc_id, {"user_id": user_id, "new_expiry": new_expiry})
            flash(f"✅ Document '{doc[0]}' renewed successfully to {new_expiry}.", "success")
            return redirect(url_for("admin_user_documents", user_id=user_id))
        
        cursor.close()
        
    finally:
        put_db(conn)
    
    return render_template(
        "admin/renew_document.html",
        user_id=user_id,
        doc_id=doc_id,
        doc=doc
    )

@app.route("/pricing")
@limiter.exempt
def pricing():
    """Pricing page showing subscription tiers."""
    region = get_user_region()
    pricing = get_pricing(region)
    
    subscription_tier = 'free'
    subscription_expiry = None
    doc_count = 0
    
    # Get billing period from query parameter (default: monthly)
    billing_period = request.args.get("billing", "monthly")
    if billing_period not in ['monthly', 'annual']:
        billing_period = 'monthly'
    
    if session.get('user_id'):
        user_id = session['user_id']
        sub_status = get_subscription_status(user_id)
        subscription_tier = sub_status['tier']
        subscription_expiry = sub_status['expiry']
        doc_count = get_document_count(user_id)
    
    return render_template(
        "pricing.html",
        pricing=pricing,
        subscription_tier=subscription_tier,
        subscription_expiry=subscription_expiry,
        doc_count=doc_count,
        now=datetime.now(timezone.utc),
        billing_period=billing_period
    )

@app.route("/terms")
@limiter.exempt
def terms():
    """Terms of Service page."""
    return render_template("legal/terms.html")


@app.route("/privacy")
@limiter.exempt
def privacy():
    """Privacy Policy page."""
    return render_template("legal/privacy.html")


@app.route("/feedback")
@limiter.exempt
def feedback():
    """Feedback page."""
    return render_template("feedback.html")

# =============================================================================
# ROUTES - AUTHENTICATION
# =============================================================================

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", error_message="Too many registration attempts. Please try again later.")
def register():
    """User registration."""
    error = None
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        password_errors = validate_password_strength(password)
        if password_errors:
            error = f"Password must contain: {', '.join(password_errors)}"
        else:
            conn = get_db()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cursor.fetchone():
                    error = "An account with that email already exists"
                else:
                    password_hash = generate_password_hash(password)
                    cursor.execute(
                        "INSERT INTO users (email, password_hash, email_verified) VALUES (%s, %s, %s) RETURNING id",
                        (email, password_hash, False)
                    )
                    new_user_id = cursor.fetchone()[0]
                    conn.commit()

                    send_verification_email(email, new_user_id)
                    cursor.close()
                conn.commit()
            finally:
                put_db(conn)

            if not error:
                flash("✅ Account created! Please check your email to verify your address.", "success")
                return redirect(url_for("login"))

    return render_template("register.html", error=error)


@app.route("/verify-email/<token>")
def verify_email(token):
    """Verify a user's email address."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email FROM users WHERE verification_token = %s AND verification_token_expiry > %s AND email_verified = FALSE",
            (token, datetime.now(timezone.utc))
        )
        user = cursor.fetchone()
        
        if user:
            user_id, email = user
            cursor.execute(
                "UPDATE users SET email_verified = TRUE, verification_token = NULL, verification_token_expiry = NULL WHERE id = %s",
                (user_id,)
            )
            conn.commit()
            
            session["user_id"] = user_id
            session["email"] = email
            
            flash("✅ Email verified successfully! Welcome to Fritt Tracker.", "success")
            return redirect("/")
        else:
            cursor.execute(
                "SELECT id, email_verified FROM users WHERE verification_token = %s",
                (token,)
            )
            expired_user = cursor.fetchone()
            
            if expired_user and expired_user[1]:
                flash("ℹ️ This email is already verified. Please log in.", "info")
                return redirect(url_for("login"))
            else:
                flash("❌ This verification link has expired or is invalid. Please request a new one.", "error")
                return render_template("verify_email.html", invalid=True)
        cursor.close()
    finally:
        put_db(conn)


@app.route("/resend-verification", methods=["GET", "POST"])
@limiter.limit("3 per hour", error_message="Too many verification requests. Please wait an hour.")
def resend_verification():
    """Resend email verification."""
    error = None
    success = None
    
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        
        if not email:
            error = "Please enter your email address."
        else:
            user = get_user_by_email(email)
            
            if user and len(user) >= 4:
                user_id = user[0]
                email_verified = user[3]

                if not email_verified:
                    if send_verification_email(email, user_id):
                        success = "A new verification email has been sent. Please check your inbox."
                    else:
                        error = "Could not send verification email. Please try again later."
                else:
                    error = "This email is already verified. Please log in."
            else:
                error = "No unverified account found with that email address."
    
    return render_template("resend_verification.html", error=error, success=success)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", error_message="Too many login attempts. Please wait a moment.")
def login():
    """User login."""
    error = None

    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, password_hash, subscription_tier FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()
        finally:
            put_db(conn)

        if user and check_password_hash(user[2], password):
            # Check if suspended
            if user[3] == 'suspended':
                flash("❌ Your account has been suspended. Please contact support.", "error")
                return render_template("login.html", error="Account suspended. Please contact support.")
            
            session["user_id"] = user[0]
            session["email"] = user[1]
            return redirect("/")
        else:
            error = "Invalid email or password"

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    """User logout."""
    session.clear()
    return redirect("/")


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour", error_message="Too many password reset requests. Please try again later.")
def forgot_password():
    """Request password reset."""
    message = None

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        
        if not email:
            message = "Please enter your email address."
        else:
            user = get_user_by_email(email)

            if user:
                user_id = user[0]
                token = secrets.token_urlsafe(32)
                expiry = datetime.now(timezone.utc) + RESET_TOKEN_LIFETIME

                conn = get_db()
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        "UPDATE users SET reset_token = %s, reset_token_expiry = %s WHERE id = %s",
                        (token, expiry, user_id)
                    )
                    conn.commit()
                    cursor.close()
                finally:
                    put_db(conn)

                reset_link = url_for("reset_password", token=token, _external=True)
                if reset_link.startswith('http://'):
                    reset_link = reset_link.replace('http://', 'https://')
                send_password_reset_email(email, reset_link)

            message = "If an account exists for that email, we've sent a password reset link."

    return render_template("forgot_password.html", message=message)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("15 per hour", error_message="Too many reset attempts. Please try again later.")
def reset_password(token):
    """Reset password with token."""
    user = get_user_by_reset_token(token)

    if not user:
        flash("❌ This password reset link has expired or is invalid. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))

    if len(user) < 3:
        flash("❌ An error occurred. Please try again.", "error")
        return redirect(url_for("forgot_password"))

    user_id = user[0]
    error = None

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            error = "Password must be at least 8 characters"
        elif password != confirm_password:
            error = "Passwords don't match"
        else:
            password_hash = generate_password_hash(password)
            conn = get_db()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET password_hash = %s, reset_token = NULL, reset_token_expiry = NULL WHERE id = %s",
                    (password_hash, user_id)
                )
                conn.commit()
                cursor.close()
            finally:
                put_db(conn)

            flash("✅ Password reset successfully! Please log in with your new password.", "success")
            return redirect(url_for("login"))

    return render_template("reset_password.html", invalid=False, error=error)


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    """Change user password (authenticated)."""
    auth = require_verified()
    if auth:
        return auth

    error = None
    success = None

    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE id = %s", (session["user_id"],))
            current_hash = cursor.fetchone()[0]

            if not check_password_hash(current_hash, current_password):
                error = "Current password is incorrect"
            elif len(new_password) < 8:
                error = "New password must be at least 8 characters"
            elif new_password != confirm_password:
                error = "New passwords don't match"
            else:
                new_hash = generate_password_hash(new_password)
                cursor.execute(
                    "UPDATE users SET password_hash = %s WHERE id = %s",
                    (new_hash, session["user_id"])
                )
                conn.commit()
                success = "Password updated."

            cursor.close()
        finally:
            put_db(conn)

    return render_template("change_password.html", error=error, success=success)


@app.route("/delete-account", methods=["GET", "POST"])
def delete_account():
    """Delete user account."""
    auth = require_verified()
    if auth:
        return auth

    error = None

    if request.method == "POST":
        password = request.form["password"]

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE id = %s", (session["user_id"],))
            current_hash = cursor.fetchone()[0]

            if not check_password_hash(current_hash, password):
                error = "Incorrect password"
            else:
                cursor.execute("DELETE FROM documents WHERE user_id = %s", (session["user_id"],))
                cursor.execute("DELETE FROM users WHERE id = %s", (session["user_id"],))
                conn.commit()

            cursor.close()
        finally:
            put_db(conn)

        if not error:
            session.clear()
            return redirect(url_for("login"))

    return render_template("delete_account.html", error=error)

# =============================================================================
# ROUTES - DOCUMENT MANAGEMENT
# =============================================================================

@app.route("/add", methods=["GET", "POST"])
# @limiter.limit("30 per hour", error_message="You're adding documents too quickly. Please slow down.")
def add_document():
    """Add a new document."""
    auth = require_verified()
    if auth:
        return auth

    if not can_add_document(session["user_id"]):
        flash("⚠️ You've reached the document limit on your current plan. Upgrade to Pro for more documents.", "warning")
        return redirect(url_for("pricing"))

    error = None

    if request.method == "POST":
        title = request.form["title"].strip()
        expiry_date = request.form["expiry_date"]

        if not title or not expiry_date:
            error = "Please fill in all fields"
        else:
            try:
                datetime.strptime(expiry_date, "%Y-%m-%d")
            except ValueError:
                error = "Invalid date format"

        if not error:
            conn = get_db()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id FROM documents WHERE user_id = %s AND title = %s AND expiry_date = %s",
                    (session["user_id"], title, expiry_date)
                )
                existing = cursor.fetchone()
                
                if existing:
                    error = "You already have a document with this title and expiry date."
                else:
                    cursor.execute(
                        "INSERT INTO documents (title, expiry_date, user_id) VALUES (%s, %s, %s)",
                        (title, expiry_date, session["user_id"])
                    )
                    conn.commit()
                    flash("✅ Document added successfully!", "success")
                cursor.close()
            finally:
                put_db(conn)
            return redirect("/")

    return render_template("add.html", error=error)


@app.route("/edit/<int:doc_id>", methods=["GET", "POST"])
@limiter.limit("60 per hour", error_message="Too many edits. Please slow down.")
def edit_document(doc_id):
    """Edit an existing document."""
    auth = require_verified()
    if auth:
        return auth

    user_id = session["user_id"]
    error = None
    doc = get_owned_document(doc_id, user_id)

    if not doc:
        abort(404)

    if request.method == "POST":
        title = request.form["title"].strip()
        expiry_date = request.form["expiry_date"]

        if not title or not expiry_date:
            error = "Please fill in all fields"
        else:
            try:
                datetime.strptime(expiry_date, "%Y-%m-%d")
            except ValueError:
                error = "Invalid date format"
            else:
                conn = get_db()
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        "UPDATE documents SET title = %s, expiry_date = %s WHERE id = %s AND user_id = %s",
                        (title, expiry_date, doc_id, user_id)
                    )
                    conn.commit()
                    cursor.close()
                finally:
                    put_db(conn)
                flash("✅ Document updated successfully!", "success")
                return redirect("/")

    return render_template("edit.html", doc=doc, error=error)


@app.route("/delete/<int:doc_id>", methods=["POST"])
@limiter.limit("60 per hour", error_message="Too many deletions. Please slow down.")
def delete_document(doc_id):
    """Delete a document."""
    auth = require_verified()
    if auth:
        return auth

    user_id = session["user_id"]
    doc = get_owned_document(doc_id, user_id)
    if not doc:
        abort(404)

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM documents WHERE id = %s AND user_id = %s", (doc_id, user_id))
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)

    flash("✅ Document deleted successfully!", "success")
    return redirect("/")


@app.route("/renewed/<int:doc_id>", methods=["GET", "POST"])
@limiter.limit("60 per hour", error_message="Too many renewals. Please slow down.")
def mark_renewed(doc_id):
    """Mark a document as renewed and set a new expiry date."""
    auth = require_verified()
    if auth:
        return auth

    user_id = session["user_id"]
    doc = get_owned_document(doc_id, user_id)
    
    if not doc:
        abort(404)

    error = None

    if request.method == "POST":
        new_expiry = request.form.get("expiry_date")
        
        if not new_expiry:
            error = "Please select a new expiry date."
        else:
            try:
                datetime.strptime(new_expiry, "%Y-%m-%d")
            except ValueError:
                error = "Invalid date format."
            else:
                conn = get_db()
                try:
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE documents 
                        SET expiry_date = %s, 
                            last_reminder_sent = NULL, 
                            reminder_state = NULL, 
                            snoozed_until = NULL 
                        WHERE id = %s AND user_id = %s
                    """, (new_expiry, doc_id, user_id))
                    conn.commit()
                    cursor.close()
                finally:
                    put_db(conn)
                
                flash("✅ Document renewed successfully! New expiry date set.", "success")
                return redirect("/")

    return render_template("renewed.html", doc=doc, error=error)

# =============================================================================
# ROUTES - BULK IMPORT
# =============================================================================

@app.route("/import-csv", methods=["GET", "POST"])
@limiter.limit(lambda: "20 per day" if session.get('user_id') and get_user_tier(session['user_id']) == 'vip' else "5 per day")
def import_csv():
    """Import documents from CSV file."""
    auth = require_verified()
    if auth:
        return auth
    
    user_id = session["user_id"]
    
    # Check if user is on a paid plan
    sub_status = get_subscription_status(user_id)
    tier = sub_status['tier']
    
    # Only Pro, VIP, and Business can import CSV
    if tier not in ['pro', 'vip', 'business']:
        flash("📥 CSV import is a Pro feature. Upgrade to import multiple documents at once!", "warning")
        return redirect(url_for("pricing"))

    error = None

    if request.method == "POST":
        if 'csv_file' not in request.files:
            error = "Please upload a CSV file."
        else:
            file = request.files['csv_file']
            
            if file.filename == '':
                error = "No file selected."
            elif not file.filename.lower().endswith('.csv'):
                error = "Please upload a CSV file (.csv)."
            else:
                try:
                    stream = io.StringIO(file.stream.read().decode("UTF-8"), newline=None)
                    csv_input = csv.reader(stream)
                    
                    headers = [h.strip().lower().replace(' ', '_') for h in next(csv_input)]
                    
                    title_match = None
                    expiry_match = None
                    
                    for i, h in enumerate(headers):
                        if h in ['title', 'document', 'document_title', 'doc_title', 'name']:
                            title_match = i
                        if h in ['expiry_date', 'expiry', 'expiration', 'expiration_date']:
                            expiry_match = i
                    
                    if title_match is None:
                        error = f"CSV must have a 'title' column. Found: {', '.join(headers)}"
                    elif expiry_match is None:
                        error = f"CSV must have an 'expiry_date' column. Found: {', '.join(headers)}"
                    else:
                        conn = get_db()
                        cursor = conn.cursor()
                        added = 0
                        failed = 0
                        
                        for row in csv_input:
                            if not row or all(cell.strip() == '' for cell in row):
                                continue
                            
                            title = row[title_match].strip() if len(row) > title_match else ""
                            expiry_date = row[expiry_match].strip() if len(row) > expiry_match else ""
                            
                            if not title or not expiry_date:
                                failed += 1
                                continue
                            
                            try:
                                datetime.strptime(expiry_date, "%Y-%m-%d")
                            except ValueError:
                                try:
                                    parsed = datetime.strptime(expiry_date, "%d/%m/%Y")
                                    expiry_date = parsed.strftime("%Y-%m-%d")
                                except ValueError:
                                    try:
                                        parsed = datetime.strptime(expiry_date, "%m/%d/%Y")
                                        expiry_date = parsed.strftime("%Y-%m-%d")
                                    except ValueError:
                                        failed += 1
                                        continue
                            
                            try:
                                cursor.execute(
                                    "INSERT INTO documents (title, expiry_date, user_id) VALUES (%s, %s, %s)",
                                    (title, expiry_date, session["user_id"])
                                )
                                added += 1
                            except Exception:
                                failed += 1
                        
                        conn.commit()
                        cursor.close()
                        put_db(conn)
                        
                        if added > 0:
                            flash(f"✅ Successfully imported {added} documents! {failed} failed.", "success")
                        else:
                            flash(f"⚠️ No documents imported. {failed} rows had errors.", "error")
                            
                        return redirect("/")
                        
                except csv.Error as e:
                    error = f"CSV error: {str(e)}"
                except Exception as e:
                    error = f"Error reading file: {str(e)}"

    return render_template("import_csv.html", error=error)

# =============================================================================
# ROUTES - SUBSCRIPTIONS & PAYMENTS
# =============================================================================

@app.route("/subscribe/<plan_type>")
@limiter.limit("10 per hour", error_message="Too many subscription page views. Please slow down.")
def subscribe(plan_type):
    """Show payment page for subscription."""    
    auth = require_verified()
    if auth:
        return auth
    
    user_id = session['user_id']
    user_email = session['email']
    
    region = get_user_region()
    currency = get_currency_for_region(region)
    
    plan_id = get_plan_id(plan_type, currency)
    
    if not plan_id:
        flash(f"Payment plan not available for your region ({region}). Please contact support.", "error")
        return redirect(url_for("pricing"))
    
    pricing = get_pricing(region)
    
    plan_details = {
        'pro_monthly': {'name': 'Pro Monthly', 'price': pricing['monthly'], 'tier': 'Pro'},
        'pro_yearly': {'name': 'Pro Yearly', 'price': pricing['yearly'], 'tier': 'Pro'},
        'vip_monthly': {'name': 'VIP Monthly', 'price': pricing['vip_monthly'], 'tier': 'VIP'},
        'vip_yearly': {'name': 'VIP Yearly', 'price': pricing['vip_yearly'], 'tier': 'VIP'},
    }
    
    if plan_type not in plan_details:
        flash("Invalid plan selected.", "error")
        return redirect(url_for("pricing"))
    
    return render_template(
        "subscribe.html",
        plan_type=plan_type,
        plan_id=plan_id,
        plan_details=plan_details[plan_type],
        pricing=pricing,
        currency=currency,
        user_email=user_email
    )

@app.route("/cancel-subscription", methods=["POST"])
@limiter.limit("5 per hour", error_message="Too many cancellation attempts. Please wait.")
def cancel_subscription():
    """Cancel user's subscription."""
    auth = require_verified()
    if auth:
        return auth
    
    user_id = session["user_id"]
    sub_status = get_subscription_status(user_id)
    
    if sub_status['tier'] == 'free':
        flash("You're already on the Free plan.", "info")
        return redirect(url_for("home"))
    
    # Update user to free
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET subscription_tier = 'free',
                subscription_status = 'cancelled',
                subscription_expiry = NULL
            WHERE id = %s
        """, (user_id,))
        conn.commit()
        cursor.close()
        print(f"✅ User {user_id} cancelled subscription")
    finally:
        put_db(conn)
    
    # Optional: Call Flutterwave API to cancel subscription if you have a subscription ID
    # This would be more complex and require storing the Flutterwave subscription ID
    
    flash("✅ Your subscription has been cancelled. You'll be downgraded to the Free plan at the end of your billing period.", "success")
    return redirect(url_for("home"))

@app.route("/payment/initiate", methods=["POST"])
@limiter.limit("5 per hour", error_message="Too many payment initiations. Please wait before trying again.")
def initiate_payment():
    """Initialize Flutterwave payment."""
    auth = require_verified()
    if auth:
        return auth
    
    plan_id = request.form.get("plan_id")
    plan_type = request.form.get("plan_type")
    
    if not plan_id or not plan_type:
        flash("Invalid payment request.", "error")
        return redirect(url_for("pricing"))
    
    region = get_user_region()
    currency = get_currency_for_region(region)
    pricing = get_pricing(region)
    
    amount_map = {
        'pro_monthly': pricing['monthly_raw'],
        'pro_yearly': pricing['yearly_raw'],
        'vip_monthly': pricing['vip_monthly_raw'],
        'vip_yearly': pricing['vip_yearly_raw'],
    }
    
    amount = amount_map.get(plan_type, 0)
    if amount <= 0:
        flash("Invalid payment amount.", "error")
        return redirect(url_for("pricing"))
    
    try:
        base_url = os.environ.get("APP_URL", "tracker.fritt.org")
        redirect_url = f"https://{base_url}{url_for('payment_callback')}"
        
        tx_ref = f"fritt_{session['user_id']}_{int(time.time())}"
        
        payload = {
            'amount': str(amount),
            'currency': currency,
            'tx_ref': tx_ref,
            'payment_plan': int(plan_id),
            'redirect_url': redirect_url,
            'customer': {
                'email': session['email'],
                'name': session.get('email', 'Customer').split('@')[0],
            },
            'meta': {
                'user_id': session['user_id'],
                'plan_type': plan_type,
                'region': region
            }
        }
        
        print(f"🔍 Sending payment request: {payload}")
        
        response = requests.post(
            'https://api.flutterwave.com/v3/payments',
            headers={
                'Authorization': f'Bearer {os.getenv("FLW_SECRET_KEY")}',
                'Content-Type': 'application/json'
            },
            json=payload,
            timeout=30
        )
        
        print(f"📨 Flutterwave response status: {response.status_code}")
        print(f"📨 Flutterwave response: {response.text[:500]}...")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                session['tx_ref'] = tx_ref
                
                link = data['data'].get('link')
                if link:
                    return redirect(link)
                else:
                    flash("Payment link not found.", "error")
                    return redirect(url_for("pricing"))
            else:
                error_message = data.get('message', 'Unknown error')
                print(f"❌ Flutterwave error: {error_message}")
                flash(f"Payment initialization failed: {error_message}", "error")
                return redirect(url_for("pricing"))
        else:
            print(f"❌ HTTP Error: {response.status_code}")
            print(f"❌ Response: {response.text}")
            flash("Payment initialization failed. Please try again.", "error")
            return redirect(url_for("pricing"))
        
    except Exception as e:
        print(f"❌ Payment error: {e}")
        import traceback
        traceback.print_exc()
        flash("Payment initialization failed. Please try again.", "error")
        return redirect(url_for("pricing"))


@app.route("/payment/callback")
@limiter.exempt  # Payment callbacks should never be rate limited
def payment_callback():
    """Handle payment callback from Flutterwave."""
    auth = require_verified()
    if auth:
        return auth
    
    tx_ref = request.args.get('tx_ref')
    transaction_id = request.args.get('transaction_id')
    
    if not tx_ref or not transaction_id:
        flash("Invalid payment callback.", "error")
        return redirect(url_for("pricing"))
    
    try:
        # Check if we're in test mode vs live mode
        # This prevents test mode payments from upgrading users in production
        is_test_mode = os.environ.get("FLW_TEST_MODE", "false").lower() == "true"
        
        response = requests.get(
            f'https://api.flutterwave.com/v3/transactions/{transaction_id}/verify',
            headers={
                'Authorization': f'Bearer {os.getenv("FLW_SECRET_KEY")}',
                'Content-Type': 'application/json'
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status') == 'success' and data['data']['status'] == 'successful':
                # Skip test mode transactions in production
                if data['data'].get('test_mode', False) and not is_test_mode:
                    flash("Test payments are not allowed in production.", "error")
                    return redirect(url_for("pricing"))
                
                user_id = session['user_id']
                
                meta = data['data'].get('meta', {})
                plan_type = meta.get('plan_type', '')
                
                if not plan_type:
                    payment_plan = data['data'].get('payment_plan', {})
                    plan_name = payment_plan.get('name', '')
                    if 'Pro' in plan_name:
                        plan_type = 'pro_monthly' if 'Monthly' in plan_name else 'pro_yearly'
                    elif 'VIP' in plan_name:
                        plan_type = 'vip_monthly' if 'Monthly' in plan_name else 'vip_yearly'
                
                tier = plan_type.split('_')[0] if plan_type else 'pro'
                
                conn = get_db()
                try:
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE users 
                        SET subscription_tier = %s,
                            subscription_status = 'active',
                            subscription_expiry = NULL
                        WHERE id = %s
                    """, (tier, user_id))
                    conn.commit()
                    cursor.close()
                    print(f"✅ User {user_id} upgraded to {tier}")
                finally:
                    put_db(conn)
                
                flash("✅ Payment successful! Your subscription is now active.", "success")
                return redirect(url_for("home"))
            else:
                flash("Payment failed. Please try again.", "error")
                return redirect(url_for("pricing"))
        else:
            flash("Error verifying payment. Please contact support.", "error")
            return redirect(url_for("pricing"))
            
    except Exception as e:
        print(f"❌ Callback error: {e}")
        import traceback
        traceback.print_exc()
        flash("Error verifying payment. Please contact support.", "error")
        return redirect(url_for("pricing"))
    
@app.route("/payment/cancel")
def payment_cancel():
    """Handle payment cancellation."""
    auth = require_verified()
    if auth:
        return auth

    flash("Payment cancelled. You can try again anytime.", "info")
    return redirect(url_for("pricing"))

# =============================================================================
# ROUTES - WEBHOOKS & CRON
# =============================================================================

@app.route("/webhook/flutterwave", methods=["POST"])
@csrf.exempt
@limiter.exempt  # Webhooks should NEVER be rate limited
def flutterwave_webhook():
    """Handle Flutterwave webhook for subscription events."""
    try:
        data = request.json
        if not data:
            print("❌ No JSON data received")
            return "No data", 400
        
        print(f"📨 Webhook received at {datetime.now(timezone.utc)}")
        print(f"📨 Event: {data.get('event', 'unknown')}")
        print(f"📨 Full data: {data}")
        
        signature = request.headers.get('verif-hash')

        # --- CRITICAL: Enable Signature Verification ---
        if not verify_flutterwave_webhook(data, signature):
            print("❌ Webhook signature verification failed.")
            return "Invalid Signature", 401
        # -------------------------------------------------

        if signature:
            print(f"📨 Signature: {signature[:20]}...")
        
        try:
            event = data.get('event')
            
            if event == 'charge.completed':
                print("✅ Payment completed webhook received")
                
                webhook_data = data.get('data', {})
                
                user_id = None
                meta = webhook_data.get('meta', {})
                if meta:
                    user_id = meta.get('user_id')
                    plan_type = meta.get('plan_type', 'pro_monthly')
                
                if not user_id:
                    customer = webhook_data.get('customer', {})
                    email = customer.get('email')
                    if email:
                        print(f"📨 Looking up user by email: {email}")
                        user = get_user_by_email(email)
                        if user:
                            user_id = user[0]
                
                if user_id:
                    tier = plan_type.split('_')[0] if plan_type else 'pro'
                    
                    conn = get_db()
                    try:
                        cursor = conn.cursor()
                        cursor.execute("""
                            UPDATE users 
                            SET subscription_tier = %s,
                                subscription_status = 'active',
                                subscription_expiry = NULL
                            WHERE id = %s
                        """, (tier, user_id))
                        conn.commit()
                        cursor.close()
                        print(f"✅ User {user_id} upgraded to {tier}")
                    except Exception as db_error:
                        print(f"❌ Database error: {db_error}")
                    finally:
                        put_db(conn)
                else:
                    print(f"⚠️ Could not find user for webhook: {data}")
            
            elif event == 'subscription.cancelled':
                print("❌ Subscription cancelled")
                meta = data.get('data', {}).get('meta', {})
                user_id = meta.get('user_id')
                if user_id:
                    update_user_to_free(user_id)
            
            elif event == 'subscription.expired':
                print("⏰ Subscription expired")
                meta = data.get('data', {}).get('meta', {})
                user_id = meta.get('user_id')
                if user_id:
                    update_user_to_free(user_id)
            
            else:
                print(f"ℹ️ Unhandled webhook event: {event}")
                
        except Exception as process_error:
            print(f"❌ Error processing webhook: {process_error}")
            import traceback
            traceback.print_exc()
        
        return "OK", 200
        
    except Exception as e:
        print(f"❌ Webhook error: {e}")
        import traceback
        traceback.print_exc()
        return "OK", 200

@app.route("/cron/reminders")
@limiter.exempt  # Cron jobs should NEVER be rate limited
def run_reminders():
    """Endpoint triggered by cron-job.org to send daily reminders."""
    provided_token = request.args.get("token") or request.headers.get("X-Trigger-Token")
    
    if provided_token != TRIGGER_SECRET:
        abort(401, "Unauthorized: Invalid token")
    
    try:
        import reminders
        reminders.check_and_send_reminders()
        return "✅ Reminders sent successfully.", 200
    except Exception as e:
        return f"❌ Reminders failed: {str(e)}", 500

# =============================================================================
# ROUTES - NEWSLETTER
# =============================================================================

@app.route("/newsletter/subscribe", methods=["POST"])
@limiter.limit("5 per hour", error_message="Too many subscription attempts. Please wait an hour.")
def subscribe_newsletter():
    """Subscribe to newsletter."""
    email = request.form.get("email", "").strip().lower()
    
    if not email:
        flash("Please enter your email address.", "error")
        return redirect(url_for("home"))
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO newsletter_subscribers (email, subscribed_at) VALUES (%s, %s) ON CONFLICT (email) DO NOTHING",
            (email, datetime.now(timezone.utc))
        )
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    flash("✅ Thanks for subscribing! You'll hear from us soon.", "success")
    return redirect(url_for("home"))


@app.route("/admin/newsletter")
def newsletter_admin():
    """Admin page to view newsletter subscribers."""
    auth = require_admin()
    if auth:
        return auth
    
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT email, subscribed_at FROM newsletter_subscribers ORDER BY subscribed_at DESC")
        subscribers = cursor.fetchall()
        cursor.close()
    finally:
        put_db(conn)
    
    return render_template("admin/newsletter.html", subscribers=subscribers)

# # Call with your email
# reset_user_to_free('sedejordan88@gmail.com')

# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.run(debug=False)