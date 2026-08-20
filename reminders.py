"""
reminders.py

Handles email reminders for:
1. Document expirations (existing functionality)
2. Subscription/trial expirations (new)
"""

import json
import os
import psycopg2
from datetime import datetime, timedelta, timezone
import requests

APP_URL = os.environ.get("APP_URL", "tracker.fritt.org")
# Ensure APP_URL has https:// prefix for links
if not APP_URL.startswith('http://') and not APP_URL.startswith('https://'):
    APP_URL = f"https://{APP_URL}"

DATABASE_URL = os.environ.get("DATABASE_URL")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "auth@fritt.org")
RESEND_NOTIFY_EMAIL = os.environ.get("RESEND_NOTIFY_EMAIL", "notify@fritt.org")

def get_db():
    return psycopg2.connect(DATABASE_URL)

def send_reminder_email(email, documents, urgency):
    """Send a batch email with all expiring documents. Returns True if
    Resend actually accepted it, False otherwise - callers should check
    this rather than assume success."""
    subject = f"⚠️ {urgency}: Your Fritt Tracker documents need attention"

    html = f"""
    <h2>Your Fritt Tracker Documents</h2>
    <p>The following documents need your attention:</p>
    <ul>
    """
    for doc in documents:
        html += f"<li><strong>{doc['title']}</strong> — expires {doc['expiry_date']} ({doc['days_left']} days left)</li>"

    html += f"""
    </ul>
    <p><a href="{APP_URL}">View your dashboard →</a></p>
    <p style="font-size: 12px; color: #666;">Update reminders in your account settings.</p>
    """

    if not RESEND_API_KEY:
        print(f"❌ RESEND_API_KEY not set, cannot send reminder email to {email}")
        return False

    from_email = f"Fritt Tracker <{RESEND_NOTIFY_EMAIL}>"
    
    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": from_email,
                "to": [email],
                "subject": subject,
                "html": html
            },
            timeout=10
        )

        if response.status_code >= 400:
            print(f"Resend rejected reminder email to {email}: {response.status_code} {response.text}")
            return False

        return True
    except Exception as e:
        print(f"Error sending reminder email to {email}: {e}")
        return False

def send_subscription_reminder_email(user_email, user_name, tier, expiry_date, is_trial=False):
    """Send email reminder about subscription/trial expiration."""
    if not RESEND_API_KEY:
        print(f"ℹ️ Subscription reminder not sent: RESEND_API_KEY not configured")
        return False
    
    # Make expiry_date timezone-aware if it's naive
    if expiry_date.tzinfo is None:
        expiry_date = expiry_date.replace(tzinfo=timezone.utc)
    
    now = datetime.now(timezone.utc)
    days_left = (expiry_date - now).days
    
    if days_left < 0:
        days_left = 0
    
    if is_trial:
        subject = f"⚠️ Your Fritt Tracker {tier.upper()} trial ends in {days_left} days"
        html_content = f"""
            <h2>Your Free Trial is Ending Soon</h2>
            <p>Your free trial of <strong>{tier.upper()}</strong> ends in <strong>{days_left} days</strong>.</p>
            <p>After the trial ends, you'll be downgraded to the Free plan with a 20-document limit.</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{APP_URL}/pricing" style="background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Subscribe Now →</a>
            </p>
            <p style="font-size: 14px; color: #6b7280;">
                You'll keep your {tier.upper()} features until {expiry_date.strftime('%B %d, %Y')}.
            </p>
        """
        text_content = f"""
            Your Free Trial is Ending Soon
            
            Your free trial of {tier.upper()} ends in {days_left} days.
            
            After the trial ends, you'll be downgraded to the Free plan with a 20-document limit.
            
            Subscribe now: {APP_URL}/pricing
            
            You'll keep your {tier.upper()} features until {expiry_date.strftime('%B %d, %Y')}.
        """
    else:
        subject = f"⚠️ Your Fritt Tracker {tier.upper()} subscription expires in {days_left} days"
        html_content = f"""
            <h2>Your Subscription is Ending Soon</h2>
            <p>Your <strong>{tier.upper()}</strong> subscription expires in <strong>{days_left} days</strong>.</p>
            <p>After expiration, you'll be downgraded to the Free plan with a 20-document limit.</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{APP_URL}/pricing" style="background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Renew Now →</a>
            </p>
            <p style="font-size: 14px; color: #6b7280;">
                Your {tier.upper()} features will remain active until {expiry_date.strftime('%B %d, %Y')}.
            </p>
        """
        text_content = f"""
            Your Subscription is Ending Soon
            
            Your {tier.upper()} subscription expires in {days_left} days.
            
            After expiration, you'll be downgraded to the Free plan with a 20-document limit.
            
            Renew now: {APP_URL}/pricing
            
            Your {tier.upper()} features will remain active until {expiry_date.strftime('%B %d, %Y')}.
        """
    
    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": f"Fritt Tracker <{RESEND_FROM_EMAIL}>",
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
                                {html_content}
                            </div>
                            <div class="footer">
                                <p>Fritt Tracker - Never miss a document renewal</p>
                                <p style="font-size: 12px;">
                                    <a href="{APP_URL}/terms" style="color: #6b7280;">Terms</a> • 
                                    <a href="{APP_URL}/privacy" style="color: #6b7280;">Privacy</a>
                                </p>
                            </div>
                        </div>
                    </body>
                    </html>
                """,
                "text": text_content
            },
            timeout=10
        )
        if response.status_code >= 400:
            print(f"⚠️ Failed to send subscription reminder to {user_email}: {response.text}")
            return False
        return True
    except Exception as e:
        print(f"⚠️ Error sending subscription reminder to {user_email}: {e}")
        return False

def check_and_send_reminders():
    """
    Check for documents and subscriptions expiring soon and send reminders.
    Called by cron-job.org daily.
    """
    print(f"🔄 Running daily reminder check at {datetime.now(timezone.utc)}")
    
    # 1. Check document reminders (existing functionality)
    check_document_reminders()
    
    # 2. Check subscription reminders (new)
    check_subscription_reminders()
    
    print("✅ Reminder check complete")

def check_document_reminders():
    """Find documents that need reminders and send emails."""
    conn = get_db()
    try:
        cursor = conn.cursor()

        today = datetime.today().date()

        # Find all users with expiring documents
        cursor.execute("""
            SELECT DISTINCT u.id, u.email
            FROM users u
            JOIN documents d ON u.id = d.user_id
            WHERE d.expiry_date::date <= %s + INTERVAL '6 months'
        """, (today,))

        users = cursor.fetchall()

        for user_id, email in users:
            # Get all documents expiring within 120 days
            cursor.execute("""
                SELECT id, title, expiry_date::date,
                       (expiry_date::date - %s) as days_left
                FROM documents
                WHERE user_id = %s
                AND expiry_date::date <= %s + INTERVAL '120 days'
                ORDER BY expiry_date ASC
            """, (today, user_id, today))

            docs = cursor.fetchall()

            if not docs:
                continue

            # Categorize based on thresholds
            critical = []      # 0-7 days
            urgent = []        # 8-60 days
            warning = []       # 61-120 days
            expired = []       # <0 days

            for doc_id, title, expiry_date, days_left in docs:
                doc = {
                    'id': doc_id,
                    'title': title,
                    'expiry_date': expiry_date,
                    'days_left': days_left
                }

                if days_left < 0:
                    expired.append(doc)
                elif days_left <= 7:
                    critical.append(doc)
                elif days_left <= 60:
                    urgent.append(doc)
                else:
                    warning.append(doc)

            # Send expired emails daily (same as critical)
            if expired:
                send_reminder_email(email, expired, "EXPIRED")
            elif critical:
                send_reminder_email(email, critical, "CRITICAL")
            elif urgent:
                # Check if it's been at least 7 days since last reminder
                cursor.execute("""
                    SELECT MAX(last_reminder_sent) FROM documents
                    WHERE user_id = %s AND expiry_date::date <= %s + INTERVAL '90 days'
                """, (user_id, today))
                last_reminder = cursor.fetchone()[0]

                if not last_reminder or (today - last_reminder).days >= 7:
                    sent = send_reminder_email(email, urgent, "URGENT")
                    if sent:
                        for doc in urgent:
                            cursor.execute(
                                "UPDATE documents SET last_reminder_sent = %s WHERE id = %s",
                                (today, doc['id'])
                            )
            elif warning:
                # Monthly reminder
                cursor.execute("""
                    SELECT MAX(last_reminder_sent) FROM documents
                    WHERE user_id = %s AND expiry_date::date <= %s + INTERVAL '180 days'
                """, (user_id, today))
                last_reminder = cursor.fetchone()[0]

                if not last_reminder or (today - last_reminder).days >= 30:
                    sent = send_reminder_email(email, warning, "WARNING")
                    if sent:
                        for doc in warning:
                            cursor.execute(
                                "UPDATE documents SET last_reminder_sent = %s WHERE id = %s",
                                (today, doc['id'])
                            )

            conn.commit()

        cursor.close()
    except Exception as e:
        print(f"❌ Error checking document reminders: {e}")
    finally:
        conn.close()

def check_subscription_reminders():
    """Check for subscriptions/trials expiring soon and send email reminders."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, email, subscription_tier, subscription_expiry, trial_ends_at, trial_used
            FROM users 
            WHERE subscription_tier IN ('pro', 'vip')
            AND subscription_status = 'active'
        """)
        users = cursor.fetchall()
        
        now = datetime.now(timezone.utc)
        today = now.date()
        
        for user in users:
            user_id, email, tier, expiry, trial_ends_at, trial_used = user
            
            # Make all datetimes timezone-aware
            if expiry and expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if trial_ends_at and trial_ends_at.tzinfo is None:
                trial_ends_at = trial_ends_at.replace(tzinfo=timezone.utc)
            
            is_trial = trial_used and trial_ends_at and trial_ends_at > now
            
            if is_trial:
                # Trial reminder - send at 2 days and 1 day before
                days_left = (trial_ends_at - now).days
                
                # Check if we already sent a reminder today
                cursor.execute("""
                    SELECT 1 FROM user_activity_logs 
                    WHERE user_id = %s 
                    AND action = 'trial_reminder_sent' 
                    AND created_at::date = %s
                """, (user_id, today))
                already_sent = cursor.fetchone()
                
                if days_left in [2, 1] and not already_sent:
                    success = send_subscription_reminder_email(
                        email, 
                        email.split('@')[0], 
                        tier, 
                        trial_ends_at, 
                        is_trial=True
                    )
                    if success:
                        # Log that we sent the reminder
                        cursor.execute("""
                            INSERT INTO user_activity_logs (user_id, action, details, created_at)
                            VALUES (%s, 'trial_reminder_sent', %s, %s)
                        """, (user_id, json.dumps({'days_left': days_left, 'tier': tier}), now))
                        conn.commit()
                        print(f"📧 Sent trial reminder to {email} ({days_left} days left)")
            
            elif expiry and expiry > now:
                # Regular subscription reminder - send at 7, 2, and 1 days before
                days_left = (expiry - now).days
                
                # Check if we already sent a reminder today
                cursor.execute("""
                    SELECT 1 FROM user_activity_logs 
                    WHERE user_id = %s 
                    AND action = 'subscription_reminder_sent' 
                    AND created_at::date = %s
                """, (user_id, today))
                already_sent = cursor.fetchone()
                
                if days_left in [7, 2, 1] and not already_sent:
                    success = send_subscription_reminder_email(
                        email, 
                        email.split('@')[0], 
                        tier, 
                        expiry, 
                        is_trial=False
                    )
                    if success:
                        # Log that we sent the reminder
                        cursor.execute("""
                            INSERT INTO user_activity_logs (user_id, action, details, created_at)
                            VALUES (%s, 'subscription_reminder_sent', %s, %s)
                        """, (user_id, json.dumps({'days_left': days_left, 'tier': tier}), now))
                        conn.commit()
                        print(f"📧 Sent subscription reminder to {email} ({days_left} days left)")
        
        cursor.close()
        
    except Exception as e:
        print(f"❌ Error checking subscription reminders: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

if __name__ == "__main__":
    check_and_send_reminders()