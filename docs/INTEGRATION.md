# Integration Guide

This guide explains how to integrate Trap into your existing Next.js project.

## Quick Start

### 1. Copy Files

Copy the following directories to your project:

```
your-project/
├── lib/
│   └── honeypot/
│       ├── index.ts
│       ├── collector.ts
│       ├── traps.ts
│       ├── geolocation.ts
│       ├── whois.ts
│       └── blocker.ts
└── app/
    └── api/
        └── trap/
            ├── env/route.ts
            ├── creds/route.ts
            ├── fingerprint/route.ts
            └── actions/route.ts
```

### 2. Configure Environment Variables

Add to your `.env`:

```env
# Required
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=-100xxxxxxxxxx

# Optional
TELEGRAM_MESSAGE_THREAD_ID=3
HONEYPOT_FAKE_DOMAIN=yourdomain.com
```

### 3. Update Middleware

Add honeypot checks to your `middleware.ts`:

```typescript
import { honeypotTraps } from '@/lib/honeypot/traps';
import { isIPBlocked } from '@/lib/honeypot/blocker';

export async function middleware(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown';

  // Check blocked IPs
  if (await isIPBlocked(ip)) {
    return NextResponse.json({ error: 'Access denied' }, { status: 403 });
  }

  // Check honeypot traps
  const trapResponse = honeypotTraps(request, ip);
  if (trapResponse) {
    return trapResponse;
  }

  return NextResponse.next();
}
```

### 4. Set Up Telegram Webhook

```bash
curl -X POST "https://api.telegram.org/bot<TOKEN>/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://yourdomain.com/api/trap/actions"}'
```

## Configuration Options

### Trap Customization

Edit `lib/honeypot/traps.ts` to add or modify traps:

```typescript
export const HONEYPOT_TRAPS: HoneypotTrap[] = [
  // Add your custom traps
  {
    path: '/your-custom-path',
    redirectPath: '/api/trap/env',
    attackType: 'CUSTOM_ATTACK',
    severity: 'HIGH',
    description: 'Custom trap description'
  },
  // ... existing traps
];
```

### Fake Credentials

Customize fake credentials in environment:

```env
FAKE_DB_HOST=db.yoursite.com
FAKE_DB_USER=admin
FAKE_DB_PASS=YourFakePassword123!
FAKE_STRIPE_KEY=sk_live_FAKE_KEY_HONEYPOT
```

### Media Capture

Control media capture attempts:

```env
ENABLE_MEDIA_CAPTURE=true   # Camera/mic/screen
ENABLE_WEBRTC_LEAK=true     # Real IP detection
ENABLE_GPS_LOCATION=true    # GPS coordinates
```

## Telegram Bot Setup

### 1. Create Bot

1. Message [@BotFather](https://t.me/BotFather)
2. Send `/newbot`
3. Follow instructions to create bot
4. Save the token

### 2. Create Group/Channel

1. Create a new group or channel
2. Add your bot as admin
3. Get the chat ID:
   - Add [@userinfobot](https://t.me/userinfobot) to the group
   - It will show the chat ID
   - For groups, prefix with `-100`

### 3. Enable Topics (Optional)

If using topics in a supergroup:
1. Enable topics in group settings
2. Create a topic for security alerts
3. Get the topic ID from the URL
4. Set `TELEGRAM_MESSAGE_THREAD_ID`

## Testing

### Test Traps Locally

```bash
# Test .env trap
curl http://localhost:3000/.env

# Test git trap
curl http://localhost:3000/.git/config

# Test admin trap
curl http://localhost:3000/wp-admin
```

### Test Telegram Notifications

```bash
# Check webhook status
curl "https://api.telegram.org/bot<TOKEN>/getWebhookInfo"

# Send test message
curl -X POST "https://api.telegram.org/bot<TOKEN>/sendMessage" \
  -H "Content-Type: application/json" \
  -d '{"chat_id": "<CHAT_ID>", "text": "Test message"}'
```

## Production Deployment

### Cloudflare

If using Cloudflare:
1. Ensure Cloudflare passes real IP via `CF-Connecting-IP`
2. Update middleware to use this header
3. Configure Cloudflare Firewall Rules for additional protection

### Docker

```dockerfile
ENV TELEGRAM_BOT_TOKEN=your_token
ENV TELEGRAM_CHAT_ID=your_chat_id
```

### Vercel

Add environment variables in Vercel dashboard:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- Other optional variables

## Troubleshooting

### Notifications Not Sending

1. Check bot token is correct
2. Verify chat ID format (groups need `-100` prefix)
3. Ensure bot is admin in the group
4. Check webhook is set correctly

### Traps Not Triggering

1. Verify middleware is running
2. Check path matches exactly
3. Look for console logs `[Trap]`
4. Test with curl directly

### IP Not Detected

1. Check if behind proxy/load balancer
2. Verify `x-forwarded-for` header is passed
3. For Cloudflare, use `cf-connecting-ip`

## Security Best Practices

1. **Never use real credentials** in honeypot responses
2. **Include "FAKE" or "HONEYPOT"** in fake keys
3. **Log all honeypot triggers** for analysis
4. **Review alerts regularly** for false positives
5. **Keep trap patterns updated** with new attack vectors

