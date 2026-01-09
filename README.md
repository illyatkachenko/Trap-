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

**Trap** is a comprehensive honeypot security system designed for Next.js/Node.js applications. It creates decoy endpoints that attract attackers, collect their information, and alert you in real-time via Telegram.

### Key Capabilities:

- 🎭 **Fake Sensitive Files** - Serve convincing fake `.env`, `.git/config`, database dumps
- 🔍 **Advanced Fingerprinting** - Collect browser fingerprints, WebRTC real IP, canvas hash
- 📸 **Media Capture** - Attempt to capture camera photos, screenshots, microphone audio
- 📍 **Precise Geolocation** - GPS coordinates (with consent) + IP-based location
- 🤖 **Telegram Integration** - Real-time alerts with interactive threat management
- 🚫 **IP Blocking** - One-click blocking from Telegram with duration options
- 📊 **Attack Analytics** - Comprehensive logging and reporting

---

## ✨ Features

### 🪤 Honeypot Traps

| Trap | Path | What it does |
|------|------|--------------|
| Environment Files | `/.env*` | Returns fake credentials, tracks access |
| Git Repository | `/.git/*` | Fake git config with tracking |
| Admin Panels | `/wp-admin`, `/phpmyadmin` | Fake login page with fingerprinting |
| Config Files | `/config.*`, `/secrets.json` | Fake configuration files |
| Database Dumps | `/*.sql`, `/backup*` | Fake database exports |
| PHP Files | `/*.php` | Catches PHP-based attacks |

### 🔍 Data Collection

When an attacker triggers a trap, Trap collects:

**Network Information:**
- IP Address (including X-Forwarded-For, CF-Connecting-IP)
- Real IP via WebRTC leak detection
- ISP, ASN, Organization
- Proxy/VPN detection

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

### 📱 Telegram Integration

Real-time alerts with:
- Attack type and severity
- Full attacker information
- Interactive buttons for threat management

**Available Actions:**
- 🚫 Block IP (1h / 24h / Permanent)
- 📋 WHOIS lookup
- 📧 Abuse report
- 🌍 Geo-blocking instructions
- 🔍 Mark for investigation
- ✅ Mark as false positive

---

## 📦 Installation

### Prerequisites

- Node.js 18+
- Next.js 14+ (App Router)
- Telegram Bot Token

### Quick Start

```bash
# Clone the repository
git clone https://github.com/illyatkachenko/Trap-.git
cd Trap-

# Install dependencies
npm install

# Copy environment variables
cp .env.example .env

# Configure your Telegram bot
# Edit .env with your TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
```

### NPM Package (Coming Soon)

```bash
npm install @illyatkachenko/trap
```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file with the following variables:

```env
# Telegram Configuration (Required)
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=-100xxxxxxxxxx
TELEGRAM_MESSAGE_THREAD_ID=3  # Optional: for topics/threads

# Honeypot Configuration (Optional)
HONEYPOT_ENABLED=true
HONEYPOT_LOG_LEVEL=info
HONEYPOT_FAKE_DOMAIN=yoursite.com

# IP Blocking (Optional)
BLOCK_DURATION_DEFAULT=3600  # 1 hour in seconds
BLOCK_STORAGE=memory  # memory | redis | database
REDIS_URL=redis://localhost:6379  # If using redis
```

### Telegram Bot Setup

1. Create a bot via [@BotFather](https://t.me/BotFather)
2. Get your bot token
3. Create a group/channel for alerts
4. Add the bot to the group as admin
5. Get the chat ID (use [@userinfobot](https://t.me/userinfobot))
6. Set up webhook:

```bash
curl -X POST "https://api.telegram.org/bot<YOUR_TOKEN>/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://yoursite.com/api/trap/actions"}'
```

---

## 🔌 Integration

### Next.js App Router

#### 1. Copy the required files

```
your-project/
├── middleware.ts              # Add honeypot checks
├── lib/
│   └── honeypot/
│       ├── collector.ts       # Data collection & Telegram
│       ├── traps.ts          # Trap definitions
│       ├── geolocation.ts    # IP geolocation
│       └── whois.ts          # WHOIS lookups
└── app/
    └── api/
        └── trap/
            ├── env/route.ts       # Fake .env endpoint
            ├── creds/route.ts     # Fake login page
            ├── fingerprint/route.ts # Fingerprint collector
            └── actions/route.ts   # Telegram callback handler
```

#### 2. Update your middleware.ts

```typescript
import { honeypotTraps } from './lib/honeypot/traps';

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown';

  // Check honeypot traps FIRST
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

#### 3. Configure traps

Edit `lib/honeypot/traps.ts` to customize which paths trigger traps:

```typescript
export const HONEYPOT_TRAPS: HoneypotTrap[] = [
  { 
    path: '/.env', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL' 
  },
  // Add more traps...
];
```

### Express.js

```javascript
const { trapMiddleware } = require('@illyatkachenko/trap/express');

app.use(trapMiddleware({
  telegramToken: process.env.TELEGRAM_BOT_TOKEN,
  telegramChatId: process.env.TELEGRAM_CHAT_ID,
}));
```

### Standalone (Any Node.js)

```javascript
const { TrapCollector } = require('@illyatkachenko/trap');

const trap = new TrapCollector({
  telegramToken: process.env.TELEGRAM_BOT_TOKEN,
  telegramChatId: process.env.TELEGRAM_CHAT_ID,
});

// When you detect suspicious activity:
await trap.collect({
  ip: '1.2.3.4',
  userAgent: req.headers['user-agent'],
  path: req.path,
  attackType: 'SQL_INJECTION',
  severity: 'HIGH',
});
```

---

## 📚 API Reference

### TrapCollector

```typescript
interface HoneypotData {
  ip: string;
  userAgent: string;
  path: string;
  method: string;
  attackType: AttackType;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  details?: string;
  fingerprint?: BrowserFingerprint;
  credentials?: CapturedCredentials;
  cameraImage?: string;      // Base64
  screenshot?: string;       // Base64
  microphoneAudio?: string;  // Base64
  preciseGeolocation?: GPSLocation;
}

type AttackType = 
  | 'ENV_DISCLOSURE'
  | 'GIT_DISCLOSURE'
  | 'BRUTE_FORCE'
  | 'SQL_INJECTION'
  | 'XSS'
  | 'COMMAND_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'FILE_UPLOAD'
  | 'CREDENTIAL_HARVESTING'
  | 'CRYPTOMINER'
  | 'MALWARE_INJECTION'
  | 'WEBSHELL_UPLOAD'
  | 'RANSOMWARE'
  | 'BOTNET_C2'
  | 'DATA_EXFILTRATION';
```

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/trap/env` | GET | Returns fake .env file |
| `/api/trap/creds` | GET/POST | Fake login page & credential capture |
| `/api/trap/fingerprint` | POST | Receives browser fingerprint |
| `/api/trap/actions` | POST | Telegram webhook for button callbacks |
| `/api/trap/actions?action=check&ip=x.x.x.x` | GET | Check if IP is blocked |
| `/api/trap/actions?action=blocked` | GET | List all blocked IPs |

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
- ❌ Never use real credentials in honeypot responses
- ❌ Don't expose actual system information

---

## 📊 Attack Types & Severity

| Attack Type | Severity | Description |
|-------------|----------|-------------|
| `ENV_DISCLOSURE` | 🔴 CRITICAL | Attempt to access environment files |
| `GIT_DISCLOSURE` | 🔴 CRITICAL | Attempt to access git repository |
| `CREDENTIAL_HARVESTING` | 🔴 CRITICAL | Submitted credentials to fake login |
| `SQL_INJECTION` | 🟠 HIGH | SQL injection attempt |
| `COMMAND_INJECTION` | 🟠 HIGH | OS command injection |
| `PATH_TRAVERSAL` | 🟠 HIGH | Directory traversal attempt |
| `XSS` | 🟡 MEDIUM | Cross-site scripting attempt |
| `BRUTE_FORCE` | 🟡 MEDIUM | Login brute force attempt |
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

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/illyatkachenko">Illia Tkachenko</a>
</p>

<p align="center">
  <a href="https://github.com/illyatkachenko/Trap-/issues">Report Bug</a> •
  <a href="https://github.com/illyatkachenko/Trap-/issues">Request Feature</a>
</p>

