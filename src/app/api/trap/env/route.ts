/**
 * Trap - Fake Environment File Endpoint
 * 
 * Returns a convincing fake .env file to lure attackers
 * and collect their information.
 */

import { NextResponse } from 'next/server';
import { collectHoneypotData } from '@/lib/honeypot/collector';
import type { AttackType, Severity } from '@/lib/honeypot/collector';

// Configuration
const FAKE_DOMAIN = process.env.HONEYPOT_FAKE_DOMAIN || 'example.com';
const FAKE_DB_HOST = process.env.FAKE_DB_HOST || `db.${FAKE_DOMAIN}`;
const FAKE_DB_USER = process.env.FAKE_DB_USER || 'admin';
const FAKE_DB_PASS = process.env.FAKE_DB_PASS || 'Sup3rS3cr3tP@ss2024!';

export async function GET(request: Request) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
             request.headers.get('x-real-ip') || 
             'unknown';
  const userAgent = request.headers.get('user-agent') || 'unknown';
  const url = new URL(request.url);
  const originalPath = url.searchParams.get('original_path') || url.pathname;
  const trapType = url.searchParams.get('trap_type') as AttackType || 'ENV_DISCLOSURE';
  const severity = url.searchParams.get('severity') as Severity || 'CRITICAL';

  // Generate a unique suffix for this request (for tracking)
  const suffix = Math.random().toString(36).substring(2, 8);

  // Collect honeypot data and send alert
  try {
    await collectHoneypotData({
      ip,
      userAgent,
      path: originalPath,
      method: 'GET',
      attackType: trapType,
      severity,
      details: `Attempted to access sensitive environment file: ${originalPath}`,
      fakeDataProvided: true,
      fingerprintUrl: `${url.origin}/api/trap/creds?ref=${Buffer.from(ip).toString('base64')}`,
    });
  } catch (error) {
    console.error('[Trap] Failed to send notification:', error);
  }

  // Generate fake .env content
  const fakeEnv = generateFakeEnv(suffix);

  return new NextResponse(fakeEnv, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain',
      'X-Honeypot-Triggered': 'true',
      'X-Honeypot-Type': 'env-file',
    },
  });
}

function generateFakeEnv(suffix: string): string {
  const timestamp = new Date().toISOString().split('T')[0];
  
  return `# Production Environment Configuration
# Last updated: ${timestamp}
# Server: prod-eu-west-1
# WARNING: DO NOT SHARE THIS FILE!

# ============ DATABASE ============
DATABASE_URL="postgresql://${FAKE_DB_USER}:${FAKE_DB_PASS}@${FAKE_DB_HOST}:5432/production_db"
DATABASE_REPLICA_URL="postgresql://readonly:R3@d0nlyP@ss!@db-replica.${FAKE_DOMAIN}:5432/production_db"
DATABASE_POOL_SIZE=20
DATABASE_SSL=true

# ============ REDIS ============
REDIS_URL="redis://:R3d1sP@ss2024!@redis.${FAKE_DOMAIN}:6379/0"
REDIS_CLUSTER_URL="redis://cluster.${FAKE_DOMAIN}:6379"

# ============ STRIPE (LIVE!) ============
STRIPE_SECRET_KEY="sk_live_51NxK2mI5CAtgxCL2FAKE_KEY_HONEYPOT_${suffix}"
STRIPE_WEBHOOK_SECRET="whsec_FAKE_WEBHOOK_SECRET_HONEYPOT_${suffix}"
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY="pk_live_51NxK2mI5CAtgxCL2FAKE_${suffix}"

# ============ EMAIL (RESEND) ============
RESEND_API_KEY="re_FAKE_RESEND_KEY_HONEYPOT_${suffix}"
SMTP_HOST="smtp.${FAKE_DOMAIN}"
SMTP_PORT=587
SMTP_USER="noreply@${FAKE_DOMAIN}"
SMTP_PASS="Sm7pP@ssw0rd!2024"

# ============ AUTHENTICATION ============
JWT_SECRET="ultra-secret-jwt-key-production-${suffix}"
NEXTAUTH_SECRET="nextauth-super-secret-key-${suffix}"
NEXTAUTH_URL="https://${FAKE_DOMAIN}"
SESSION_SECRET="session-secret-${suffix}"

# ============ ADMIN ACCESS ============
ADMIN_EMAIL="admin@${FAKE_DOMAIN}"
ADMIN_PASSWORD="Admin@Pr0d2024!"
SUPERADMIN_TOKEN="superadmin_${suffix}"

# ============ AWS ============
AWS_ACCESS_KEY_ID="AKIAFAKEACCESSKEY${suffix.toUpperCase()}"
AWS_SECRET_ACCESS_KEY="FakeSecretKey+HONEYPOT/${suffix}!"
AWS_S3_BUCKET="uploads-prod"
AWS_REGION="eu-central-1"
AWS_CDN_URL="https://cdn.${FAKE_DOMAIN}"

# ============ GOOGLE CLOUD ============
GOOGLE_APPLICATION_CREDENTIALS="/app/service-account.json"
GCP_PROJECT_ID="project-prod"
GCS_BUCKET="storage-prod"

# ============ TELEGRAM BOT ============
TELEGRAM_BOT_TOKEN="1234567890:FAKE_TELEGRAM_BOT_TOKEN_${suffix}"
TELEGRAM_CHAT_ID="-1001234567890"
TELEGRAM_ADMIN_CHAT="-1009876543210"

# ============ INTERNAL APIs ============
INTERNAL_API_KEY="int_api_FAKE_KEY_${suffix}"
CRM_API_KEY="crm_FAKE_api_key_${suffix}"
INVENTORY_API_KEY="inv_FAKE_key_${suffix}"
SHIPPING_API_KEY="ship_FAKE_key_${suffix}"

# ============ THIRD PARTY ============
SENTRY_DSN="https://fake123@sentry.io/12345"
DATADOG_API_KEY="dd_FAKE_api_key_${suffix}"
NEWRELIC_LICENSE_KEY="nr_FAKE_license_${suffix}"
MIXPANEL_TOKEN="mp_FAKE_token_${suffix}"
SEGMENT_WRITE_KEY="seg_FAKE_key_${suffix}"

# ============ FEATURE FLAGS ============
ENABLE_DEBUG_MODE="true"
SHOW_ADMIN_PANEL="true"
ENABLE_API_LOGGING="true"
MAINTENANCE_MODE="false"

# ============ ENCRYPTION ============
ENCRYPTION_KEY="enc_key_32_chars_${suffix}!!"
SIGNING_KEY="sign_key_${suffix}"

# ============ OAUTH ============
GOOGLE_CLIENT_ID="123456789-fake.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="GOCSPX-FAKE_${suffix}"
FACEBOOK_APP_ID="123456789012345"
FACEBOOK_APP_SECRET="fake_fb_secret_${suffix}"

# ============ PAYMENT GATEWAYS ============
PAYPAL_CLIENT_ID="FAKE_PAYPAL_CLIENT_${suffix}"
PAYPAL_SECRET="FAKE_PAYPAL_SECRET_${suffix}"
PRZELEWY24_MERCHANT_ID="12345"
PRZELEWY24_CRC="fake_crc_${suffix}"

# ============ NOTES ============
# For admin access, visit:
# https://${FAKE_DOMAIN}/api/trap/creds?auth=admin
# Default admin: admin@${FAKE_DOMAIN} / Admin@Pr0d2024!
#
# API Documentation: https://${FAKE_DOMAIN}/api/trap/creds?docs=true
# Debug panel: https://${FAKE_DOMAIN}/api/trap/creds?debug=true
#
# Last deployment: ${timestamp} by devops@${FAKE_DOMAIN}
# Deployment ID: deploy_${suffix}
`;
}

// Also handle POST requests (some scanners try POST)
export async function POST(request: Request) {
  return GET(request);
}

