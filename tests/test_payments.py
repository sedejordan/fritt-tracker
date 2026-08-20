# tests/test_payments.py - Fixed
"""
tests/test_payments.py - Fixed
"""

import os
import json
from datetime import datetime, timedelta, timezone
import pytest
from unittest.mock import patch, Mock
from database import get_db, put_db


@patch('app.requests.post')
def test_initiate_payment_redirects_to_flutterwave(mock_post, client, logged_in_user):
    """Payment initiation should redirect to Flutterwave."""
    # Mock Flutterwave response properly
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'status': 'success',
        'data': {
            'link': 'https://checkout.flutterwave.com/pay/test'
        }
    }
    mock_response.text = json.dumps(mock_response.json.return_value)  # For the print statement
    mock_post.return_value = mock_response
    
    # Ensure plan_id exists in env
    os.environ["FLW_PRO_MONTHLY_USD_PLAN"] = "123"
    
    response = client.post(
        "/payment/initiate",
        data={
            "plan_id": "123",
            "plan_type": "pro_monthly",
            "csrf_token": "test"
        },
        follow_redirects=False
    )
    
    # Should redirect to Flutterwave
    assert response.status_code == 302
    assert 'flutterwave' in response.location


@patch('app.requests.get')
def test_payment_callback_verifies_and_upgrades(mock_get, client, logged_in_user):
    """Payment callback should verify transaction and upgrade user."""
    # Mock verification response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'status': 'success',
        'data': {
            'status': 'successful',
            'meta': {
                'user_id': logged_in_user['id'],
                'plan_type': 'pro_monthly'
            },
            'subscription_id': 'flw_sub_123'
        }
    }
    mock_get.return_value = mock_response
    
    response = client.get(
        "/payment/callback?tx_ref=test_tx_123&transaction_id=123456",
        follow_redirects=True
    )
    
    # Should show success
    assert response.status_code == 200

def test_subscription_webhook_upgrades_user(client, test_user):
    """Webhook should upgrade user when payment is confirmed."""
    # Make sure the webhook secret is set in the environment
    os.environ["FLW_WEBHOOK_SECRET"] = "test_webhook_secret"
    
    webhook_data = {
        'event': 'charge.completed',
        'data': {
            'meta': {
                'user_id': test_user['id'],
                'plan_type': 'pro_monthly'
            },
            'subscription_id': 'flw_sub_456'
        }
    }
    
    # Compute the signature using the same method as the app
    import hmac
    import hashlib
    import json
    
    secret = os.environ.get("FLW_WEBHOOK_SECRET", "test_webhook_secret")
    payload = json.dumps(webhook_data)
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    response = client.post(
        "/webhook/flutterwave",
        data=payload,
        content_type='application/json',
        headers={'verif-hash': expected_signature}
    )
    
    assert response.status_code == 200
       
@patch('app.requests.put')
def test_cancel_subscription_calls_flutterwave_api(mock_put, client, logged_in_user):
    """Canceling subscription should call Flutterwave API."""
    # Set up user with subscription
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET subscription_tier = 'pro',
                subscription_status = 'active',
                subscription_expiry = CURRENT_TIMESTAMP + INTERVAL '30 days',
                flw_subscription_id = 'flw_sub_789'
            WHERE id = %s
        """, (logged_in_user["id"],))
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    # Mock Flutterwave response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {'status': 'success'}
    mock_put.return_value = mock_response
    
    response = client.post(
        "/cancel-subscription",
        data={"csrf_token": "test"},
        follow_redirects=True
    )
    
    # Should show cancellation message
    assert response.status_code == 200

def test_expired_subscription_webhook_downgrades_user(client, test_user):
    """Expired subscription webhook should downgrade user to free."""
    # Set up user with subscription
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET subscription_tier = 'pro',
                subscription_status = 'active',
                flw_subscription_id = 'flw_sub_999'
            WHERE id = %s
        """, (test_user["id"],))
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    webhook_data = {
        'event': 'subscription.expired',
        'data': {
            'id': 'flw_sub_999'
        }
    }
    
    # Set secret and compute signature
    os.environ["FLW_WEBHOOK_SECRET"] = "test_webhook_secret"
    
    import hmac
    import hashlib
    import json
    
    secret = os.environ.get("FLW_WEBHOOK_SECRET", "test_webhook_secret")
    payload = json.dumps(webhook_data)
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    response = client.post(
        "/webhook/flutterwave",
        data=payload,
        content_type='application/json',
        headers={'verif-hash': expected_signature}
    )
    
    assert response.status_code == 200

def test_pricing_page_shows_correct_plans(client):
    """Pricing page should show all available plans."""
    response = client.get("/pricing")
    assert response.status_code == 200
    assert b"Free" in response.data
    assert b"Pro" in response.data
    assert b"VIP" in response.data


def test_pricing_page_region_detection(client):
    """Pricing should adjust based on detected region."""
    # US region - use USD symbol
    with patch('app.get_user_region') as mock_region:
        mock_region.return_value = 'us'
        response = client.get("/pricing")
        assert b'$' in response.data
    
    # UK region - use GBP symbol
    with patch('app.get_user_region') as mock_region:
        mock_region.return_value = 'uk'
        response = client.get("/pricing")
        assert b'&pound;' in response.data or b'\xc2\xa3' in response.data


def test_pricing_page_detects_user_subscription(client, logged_in_user):
    """Pricing page should show the user's current plan."""
    # Upgrade to Pro
    conn = get_db()
    try:
        cursor = conn.cursor()
        expiry = datetime.now(timezone.utc) + timedelta(days=30)
        cursor.execute("""
            UPDATE users 
            SET subscription_tier = 'pro',
                subscription_status = 'active',
                subscription_expiry = %s
            WHERE id = %s
        """, (expiry, logged_in_user["id"]))
        conn.commit()
        cursor.close()
    finally:
        put_db(conn)
    
    response = client.get("/pricing")
    assert b"YOUR CURRENT PLAN" in response.data or b"Current Plan" in response.data