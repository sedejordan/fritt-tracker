# set_test_env.ps1
Write-Host "Setting test environment variables..." -ForegroundColor Cyan

$env:TEST_DATABASE_URL = "postgresql://postgres:newpassword123@localhost:5432/fritt_tracker_test"
$env:DISABLE_RATE_LIMITING = "true"
$env:FLW_TEST_MODE = "true"
$env:SECRET_KEY = "test-secret-key-not-for-production"
$env:RESEND_API_KEY = "test_resend_key"
$env:FLW_WEBHOOK_SECRET = "test_webhook_secret"
$env:TRIGGER_SECRET = "test_trigger_secret"
$env:ADMIN_EMAIL = "admin@test.com"

Write-Host "Environment variables set!" -ForegroundColor Green
Write-Host ""
Write-Host "TEST_DATABASE_URL = $env:TEST_DATABASE_URL" -ForegroundColor Yellow

# Test the connection
Write-Host ""
Write-Host "Testing database connection..." -ForegroundColor Cyan
try {
    python -c "import os, psycopg2; conn = psycopg2.connect(os.environ['TEST_DATABASE_URL']); print('✅ Connected!'); conn.close()"
} catch {
    Write-Host "❌ Failed to connect. Make sure PostgreSQL is running." -ForegroundColor Red
}