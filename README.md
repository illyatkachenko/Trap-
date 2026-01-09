# 🪤 Trap - Advanced Honeypot Security System

<p align="center">
  <img src="docs/images/trap-logo.png" alt="Trap Logo" width="200">
</p>

<p align="center">
  <strong>Intelligent honeypot system for detecting, tracking, and analyzing attackers</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#integration">Integration</a> •
  <a href="#api">API</a>
</p>

---

## 🎯 What is Trap?

**Trap** is a comprehensive honeypot security system designed for Next.js/Node.js applications. It creates decoy endpoints that attract attackers, collect their information, and alert you in real-time via Telegram, Slack, Discord, and more.

### Key Capabilities:

- 🎭 **Fake Sensitive Files** - Serve convincing fake `.env`, `.git/config`, database dumps
- 🔍 **Advanced Fingerprinting** - Collect browser fingerprints, WebRTC real IP, canvas hash
- 📸 **Media Capture** - Attempt to capture camera photos, screenshots, microphone audio
- 📍 **Precise Geolocation** - GPS coordinates (with consent) + IP-based location
- 🤖 **Multi-Channel Alerts** - Telegram, Slack, Discord, Email, Webhooks
- 🚫 **Auto-Blocking** - Configurable rules for automatic IP blocking
- 🌍 **Country Blocking** - Block or allow traffic by country
- 🔑 **API Key Monitoring** - Track and alert on stolen API key usage
- 🧠 **Bot Detection** - Mouse/typing analysis to detect automated attacks
- 📊 **Dashboard** - Real-time attack statistics and analytics
- 🛡️ **Threat Intelligence** - AbuseIPDB, VirusTotal, GreyNoise integration

---

## ✨ Features

### 🪤 Honeypot Traps (195+ Patterns)

| Category | Examples | What it does |
|----------|----------|--------------|
| Environment Files | `/.env*`, `/config.env` | Returns fake credentials, tracks access |
| VCS Files | `/.git/*`, `/.svn/*` | Fake git/svn config with tracking |
| Admin Panels | `/wp-admin`, `/phpmyadmin`, `/adminer` | Fake login page with fingerprinting |
| Config Files | `/config.*`, `/secrets.json`, `/settings.yml` | Fake configuration files |
| Database Files | `/*.sql`, `/backup*`, `/dump*` | Fake database exports |
| Debug Endpoints | `/debug`, `/phpinfo.php`, `/info.php` | Fake debug information |
| API Keys | `/api/keys`, `/credentials` | Fake API key endpoints |
| Cloud Configs | `/.aws/*`, `/.gcp/*`, `/firebase.json` | Fake cloud configurations |

### 🔍 Data Collection

When an attacker triggers a trap, Trap collects:

**Network Information:**
- IP Address (including X-Forwarded-For, CF-Connecting-IP)
- Real IP via WebRTC leak detection
- ISP, ASN, Organization
- Proxy/VPN/Tor detection

**Geolocation:**
- Country, City, Region
- GPS Coordinates (if browser permission granted)
- Timezone

**Browser Fingerprint:**
- Screen resolution & pixel ratio
- GPU (WebGL renderer)
- Canvas hash
- Audio context fingerprint
- Installed plugins & fonts
- Hardware concurrency
- Battery status
- Network connection type

**Media Capture (with consent):**
- 📸 Camera photos from all available cameras
- 🖥️ Screenshot of attacker's screen
- 🎤 Microphone audio recording

**Behavior Analysis:**
- 🖱️ Mouse movements and patterns
- ⌨️ Typing speed and rhythm
- 🤖 Bot vs Human detection

### 🚫 Auto-Block Rules

Configure automatic blocking based on:

```typescript
// Block after 3 HIGH severity attacks in 5 minutes
{
  id: 'high-3-in-5min',
  conditions: [
    { type: 'severity', operator: 'eq', value: 'HIGH' },
    { type: 'attack_count', operator: 'gte', value: 3, timeWindow: 300 }
  ],
  action: { type: 'block', duration: '1h' }
}

// Instant block for CRITICAL attacks
{
  id: 'critical-instant',
  conditions: [
    { type: 'severity', operator: 'eq', value: 'CRITICAL' }
  ],
  action: { type: 'block', duration: '24h' }
}

// Block scanners by User-Agent
{
  id: 'scanner-detection',
  conditions: [
    { type: 'user_agent', operator: 'matches', value: 'sqlmap|nikto|nmap|masscan' }
  ],
  action: { type: 'block', duration: 'permanent' }
}
```

### 🔑 API Key Monitoring

Protect your API keys from being stolen:

```typescript
import { createResendMonitor, createStripeMonitor } from '@/lib/honeypot';

// Monitor Resend API usage
const resendMonitor = createResendMonitor(process.env.RESEND_API_KEY!);
await resendMonitor.trackEmail(to, subject, ip, userAgent, success);

// Monitor Stripe API usage
const stripeMonitor = createStripeMonitor(process.env.STRIPE_SECRET_KEY!);
await stripeMonitor.trackRequest('create_payment_intent', ip, userAgent, success);
```

**Features:**
- Detect when fake honeypot keys are used
- Alert on unusual API activity (high rate, multiple IPs)
- Track all API key usage with anomaly detection

### 🌍 Country Blocking

Block or allow traffic by country:

```typescript
import { blockHighRiskCountries, allowOnlyEU, checkCountry } from '@/lib/honeypot';

// Block high-risk countries (CN, RU, KP, IR, SY)
blockHighRiskCountries();

// Or allow only EU countries
allowOnlyEU();

// Check specific IP
const result = await checkCountry('1.2.3.4');
if (!result.allowed) {
  return new Response('Access denied', { status: 403 });
}
```

**Generate firewall rules:**
```typescript
import { generateCloudflareRules, generateNginxRules } from '@/lib/honeypot';

// Get Cloudflare firewall expression
const cfRules = generateCloudflareRules();

// Get Nginx GeoIP config
const nginxRules = generateNginxRules();
```

### 🛡️ Threat Intelligence

Check IP reputation across multiple sources:

```typescript
import { checkAllSources, autoReportAttack } from '@/lib/honeypot';

// Check IP against AbuseIPDB, VirusTotal, GreyNoise
const intel = await checkAllSources('1.2.3.4');
console.log(intel.isMalicious); // true
console.log(intel.confidenceScore); // 85
console.log(intel.sources); // [{name: 'AbuseIPDB', score: 90, ...}]

// Auto-report attack to AbuseIPDB
await autoReportAttack('1.2.3.4', 'SQL_INJECTION', '/api/users', 'Detected SQL injection');
```

### 📊 Dashboard

Real-time attack statistics:

```typescript
import { getStats, generateDashboardHTML } from '@/lib/honeypot';

// Get statistics
const stats = getStats({ start: Date.now() - 86400000, end: Date.now() });
console.log(stats.totalAttacks);
console.log(stats.attacksByType);
console.log(stats.topAttackers);

// Generate dashboard HTML
const html = generateDashboardHTML('https://yoursite.com');
```

**Dashboard includes:**
- Total attacks / blocked / unique IPs
- Attacks by type (pie chart)
- Timeline (24h line chart)
- Top attackers table
- Top targeted paths
- Recent attacks log

### 📱 Multi-Channel Notifications

Send alerts to multiple channels:

```env
# Telegram
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=-100xxxxxxxxxx
TELEGRAM_MESSAGE_THREAD_ID=3

# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx

# Discord
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx

# Email (for CRITICAL/HIGH only)
ALERT_EMAIL_FROM=security@yoursite.com
ALERT_EMAIL_TO=admin@yoursite.com
RESEND_API_KEY=re_xxx

# Custom Webhook
ALERT_WEBHOOK_URL=https://yoursite.com/api/security-alerts
```

### 📧 Email Tracker Pixel

Track when attackers open emails with stolen credentials:

```typescript
import { generateTrackerPixelHtml } from '@/lib/honeypot';

// In your fake .env response, include a link that loads the pixel
const fakeEnv = `
# API Documentation: https://yoursite.com/docs?track=${trackingId}
`;

// Or embed in HTML emails
const pixelHtml = generateTrackerPixelHtml('https://yoursite.com', trackingId);
```

---

## 📦 Installation

### Prerequisites

- Node.js 18+
- Next.js 14+ (App Router)
- Telegram Bot Token (optional but recommended)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/illyatkachenko/Trap-.git
cd Trap-

# Install dependencies
npm install

# Copy environment variables
cp .env.example .env

# Configure your settings
# Edit .env with your TELEGRAM_BOT_TOKEN, etc.
```

---

## ⚙️ Configuration

### Environment Variables

```env
# ============ TELEGRAM (Required for alerts) ============
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=-100xxxxxxxxxx
TELEGRAM_MESSAGE_THREAD_ID=3  # Optional: for topics/threads

# ============ SLACK (Optional) ============
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx
SLACK_CHANNEL=#security-alerts
SLACK_USERNAME=Trap Security

# ============ DISCORD (Optional) ============
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx
DISCORD_USERNAME=Trap Security

# ============ EMAIL ALERTS (Optional) ============
ALERT_EMAIL_FROM=security@yoursite.com
ALERT_EMAIL_TO=admin@yoursite.com,security@yoursite.com
EMAIL_PROVIDER=resend
RESEND_API_KEY=re_xxx

# ============ THREAT INTELLIGENCE (Optional) ============
ABUSEIPDB_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
GREYNOISE_API_KEY=your_key

# ============ CUSTOM WEBHOOK (Optional) ============
ALERT_WEBHOOK_URL=https://yoursite.com/api/security-alerts

# ============ HONEYPOT CONFIG ============
HONEYPOT_ENABLED=true
HONEYPOT_FAKE_DOMAIN=yoursite.com
```

---

## 🔌 Integration

### Next.js App Router

#### 1. Copy the required files

```
your-project/
├── middleware.ts              # Add honeypot checks
├── lib/
│   └── honeypot/             # Copy entire directory
│       ├── index.ts
│       ├── collector.ts
│       ├── traps.ts
│       ├── detector.ts
│       ├── autoblock.ts
│       ├── notifications.ts
│       ├── behavior.ts
│       ├── key-monitor.ts
│       ├── threat-intel.ts
│       ├── country-block.ts
│       ├── statistics.ts
│       ├── geolocation.ts
│       ├── whois.ts
│       └── blocker.ts
└── app/
    └── api/
        └── trap/
            ├── env/route.ts
            ├── creds/route.ts
            ├── fingerprint/route.ts
            ├── actions/route.ts
            ├── behavior/route.ts
            ├── stats/route.ts
            ├── pixel/route.ts
            ├── intel/route.ts
            ├── country/route.ts
            ├── keys/route.ts
            └── rules/route.ts
```

#### 2. Update your middleware.ts

```typescript
import { honeypotTraps } from './lib/honeypot/traps';
import { processAttack } from './lib/honeypot/autoblock';
import { checkCountry } from './lib/honeypot/country-block';

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown';

  // 1. Check country blocking
  const countryCheck = await checkCountry(ip, pathname);
  if (!countryCheck.allowed) {
    return new NextResponse('Access denied', { status: 403 });
  }

  // 2. Check honeypot traps
  const trapResponse = honeypotTraps(request, ip);
  if (trapResponse) {
    return trapResponse;
  }

  // Your existing middleware logic...
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

---

## 📚 API Reference

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/trap/env` | GET | Returns fake .env file |
| `/api/trap/creds` | GET/POST | Fake login page & credential capture |
| `/api/trap/fingerprint` | POST | Receives browser fingerprint |
| `/api/trap/actions` | GET/POST | Telegram webhook & IP management |
| `/api/trap/behavior` | POST | Behavior analysis (bot detection) |
| `/api/trap/stats` | GET | Attack statistics (JSON/CSV/HTML) |
| `/api/trap/pixel` | GET | Email tracker pixel |
| `/api/trap/intel` | GET/POST | Threat intelligence lookup/report |
| `/api/trap/country` | GET/POST | Country blocking management |
| `/api/trap/keys` | GET/POST | API key monitoring |
| `/api/trap/rules` | GET/POST | Auto-block rules management |

### Dashboard

Access the dashboard at:
```
https://yoursite.com/api/trap/stats?format=html
```

Export data:
```
https://yoursite.com/api/trap/stats?format=csv
https://yoursite.com/api/trap/stats?hours=48
```

---

## 🛡️ Security Considerations

### Legal Notice

⚠️ **Important**: This tool collects sensitive information from attackers. Ensure you:

1. Only deploy on systems you own or have authorization to protect
2. Comply with local privacy laws (GDPR, etc.)
3. Do not use collected data for illegal purposes
4. Consider adding a security.txt file disclosing your honeypot

### Best Practices

- ✅ Keep fake credentials realistic but obviously fake upon inspection
- ✅ Include "HONEYPOT" or "FAKE" in fake API keys
- ✅ Log all honeypot triggers for analysis
- ✅ Regularly review and update trap patterns
- ✅ Use threat intelligence to enrich data
- ✅ Set up auto-blocking rules for repeated attackers
- ❌ Never use real credentials in honeypot responses
- ❌ Don't expose actual system information

---

## 📊 Attack Types & Severity

| Attack Type | Severity | Description |
|-------------|----------|-------------|
| `ENV_DISCLOSURE` | 🔴 CRITICAL | Attempt to access environment files |
| `GIT_DISCLOSURE` | 🔴 CRITICAL | Attempt to access git repository |
| `CREDENTIAL_HARVESTING` | 🔴 CRITICAL | Submitted credentials to fake login |
| `CRYPTOMINER` | 🔴 CRITICAL | Cryptocurrency mining attempt |
| `RANSOMWARE` | 🔴 CRITICAL | Ransomware indicators detected |
| `SQL_INJECTION` | 🟠 HIGH | SQL injection attempt |
| `COMMAND_INJECTION` | 🟠 HIGH | OS command injection |
| `PATH_TRAVERSAL` | 🟠 HIGH | Directory traversal attempt |
| `WEBSHELL_UPLOAD` | 🟠 HIGH | Web shell upload attempt |
| `XSS` | 🟡 MEDIUM | Cross-site scripting attempt |
| `BRUTE_FORCE` | 🟡 MEDIUM | Login brute force attempt |
| `SCANNER` | 🟡 MEDIUM | Automated scanner detected |
| `FINGERPRINTING` | 🟢 LOW | Browser fingerprint collected |

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

### Development

```bash
# Clone the repo
git clone https://github.com/illyatkachenko/Trap-.git

# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build
```

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- Inspired by various honeypot projects
- WebRTC leak detection techniques
- Browser fingerprinting research
- AbuseIPDB, VirusTotal, GreyNoise APIs

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/illyatkachenko">Illia Tkachenko</a>
</p>

<p align="center">
  <a href="https://github.com/illyatkachenko/Trap-/issues">Report Bug</a> •
  <a href="https://github.com/illyatkachenko/Trap-/issues">Request Feature</a>
</p>
